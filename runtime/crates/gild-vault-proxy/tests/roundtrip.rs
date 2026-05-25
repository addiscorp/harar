use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use age::secrecy::ExposeSecret;
use axum::Router;
use gild_vault_client::VaultClient;
use gild_vault_proxy::{AppState, app};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

const TOKEN: &str = "proxy-test-token";

#[tokio::test]
async fn real_vault_round_trip_and_cross_shop_keys_stay_scoped() {
    let vault = RealVault::start();
    let (base_url, _server) = start_proxy(app(AppState::new(
        TOKEN,
        VaultClient::from_socket_path(&vault.socket_path),
    )))
    .await;
    let client = reqwest::Client::new();

    let put_a = post(
        &client,
        &base_url,
        "put",
        json!({"shopId": "shop_alpha", "key": "SECRET", "value": "alpha-secret"}),
    )
    .await;
    assert_eq!(put_a, json!({"ok": true}));

    let put_b = post(
        &client,
        &base_url,
        "put",
        json!({"shopId": "shop_beta", "key": "SECRET", "value": "beta-secret"}),
    )
    .await;
    assert_eq!(put_b, json!({"ok": true}));

    let get_a = post(
        &client,
        &base_url,
        "get",
        json!({"shopId": "shop_alpha", "key": "SECRET"}),
    )
    .await;
    assert_eq!(get_a, json!({"ok": true, "value": "alpha-secret"}));

    let list_a = post(&client, &base_url, "list", json!({"shopId": "shop_alpha"})).await;
    assert_eq!(list_a, json!({"ok": true, "keys": ["SECRET"]}));

    let injected = client
        .post(format!("{base_url}/api/vault/get"))
        .bearer_auth(TOKEN)
        .json(&json!({"shopId": "shop_alpha", "key": "shops/shop_beta/SECRET"}))
        .send()
        .await
        .unwrap();
    assert_eq!(injected.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        injected.json::<Value>().await.unwrap(),
        json!({"ok": false, "error": "invalid_key"})
    );

    let delete_a = post(
        &client,
        &base_url,
        "delete",
        json!({"shopId": "shop_alpha", "key": "SECRET"}),
    )
    .await;
    assert_eq!(delete_a, json!({"ok": true}));

    let get_deleted = post(
        &client,
        &base_url,
        "get",
        json!({"shopId": "shop_alpha", "key": "SECRET"}),
    )
    .await;
    assert_eq!(get_deleted, json!({"ok": false, "error": "not_found"}));
}

#[tokio::test]
async fn proxy_binary_uses_vault_socket_env_and_checks_health_before_binding() {
    let vault = RealVault::start();
    let port = unused_local_port();
    let mut proxy = Command::new(gild_vault_proxy_binary())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .env("VAULT_PROXY_TOKEN", TOKEN)
        .env("VAULT_SOCKET", &vault.socket_path)
        .env_remove("GILD_VAULT_SOCKET")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let base_url = format!("http://127.0.0.1:{port}");
    wait_for_proxy(&base_url).await;
    let response = reqwest::get(format!("{base_url}/health")).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let _ = proxy.kill();
    let _ = proxy.wait();
}

#[tokio::test]
async fn proxy_binary_tls_requires_client_cert_and_bearer_and_audits_cn() {
    let vault = RealVault::start();
    let certs = TlsFixture::new();
    let tls_port = unused_local_port();
    let audit_log = certs.temp.path().join("audit.log");
    let mut proxy = Command::new(gild_vault_proxy_binary())
        .arg("--tls-bind")
        .arg(format!("127.0.0.1:{tls_port}"))
        .arg("--tls-ca")
        .arg(&certs.ca_cert_path)
        .arg("--tls-cert")
        .arg(&certs.server_cert_path)
        .arg("--tls-key")
        .arg(&certs.server_key_path)
        .arg("--socket")
        .arg(&vault.socket_path)
        .arg("--audit-log")
        .arg(&audit_log)
        .env("VAULT_PROXY_TOKEN", TOKEN)
        .env_remove("VAULT_SOCKET")
        .env_remove("GILD_VAULT_SOCKET")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let base_url = format!("https://localhost:{tls_port}");
    let valid_client = tls_client(&certs.ca_cert_pem, Some(&certs.client_identity_pem));
    wait_for_tls_proxy(&valid_client, &base_url).await;

    let missing_cert = tls_client(&certs.ca_cert_pem, None);
    assert!(
        missing_cert
            .get(format!("{base_url}/health"))
            .send()
            .await
            .is_err()
    );

    let wrong_ca = TlsFixture::new();
    let wrong_client = tls_client(&certs.ca_cert_pem, Some(&wrong_ca.client_identity_pem));
    assert!(
        wrong_client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .is_err()
    );

    let wrong_bearer = valid_client
        .post(format!("{base_url}/api/vault/list"))
        .bearer_auth("wrong-token")
        .json(&json!({"shopId": "shop_alpha"}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_bearer.status(), StatusCode::UNAUTHORIZED);

    let ok = valid_client
        .post(format!("{base_url}/api/vault/put"))
        .bearer_auth(TOKEN)
        .json(&json!({"shopId": "shop_alpha", "key": "TLS_SECRET", "value": "ok"}))
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), StatusCode::OK);
    assert_eq!(ok.json::<Value>().await.unwrap(), json!({"ok": true}));

    let audit = std::fs::read_to_string(&audit_log).unwrap();
    assert!(audit.contains(r#""tls_client_cn":"storefront-droplet-do-01""#));
    assert!(audit.contains(r#""status":401"#));
    assert!(audit.contains(r#""status":200"#));

    let _ = proxy.kill();
    let _ = proxy.wait();
}

#[test]
fn proxy_binary_refuses_to_bind_when_configured_socket_is_unreachable() {
    let missing_socket = std::env::temp_dir().join(format!(
        "missing-gild-vault-{}-{}.sock",
        std::process::id(),
        unused_local_port()
    ));
    let output = Command::new(gild_vault_proxy_binary())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(unused_local_port().to_string())
        .arg("--socket")
        .arg(&missing_socket)
        .env("VAULT_PROXY_TOKEN", TOKEN)
        .env_remove("VAULT_SOCKET")
        .env_remove("GILD_VAULT_SOCKET")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "gild-vault health check failed on socket {}",
            missing_socket.display()
        )),
        "stderr did not include configured socket path: {stderr}"
    );
    assert!(
        stderr.contains("refusing to bind"),
        "stderr did not explain bind refusal: {stderr}"
    );
}

async fn start_proxy(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), server)
}

async fn post(client: &reqwest::Client, base_url: &str, op: &str, body: Value) -> Value {
    let response = client
        .post(format!("{base_url}/api/vault/{op}"))
        .bearer_auth(TOKEN)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.json().await.unwrap()
}

struct RealVault {
    socket_path: PathBuf,
    _temp: TempDir,
    child: Child,
}

impl RealVault {
    fn start() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let socket_path = temp.path().join("run/gild-vault/sock");
        std::fs::create_dir_all(socket_path.parent().unwrap()).unwrap();
        let state_path = temp.path().join("keys.age");
        let master_key_path = temp.path().join("vault-master.key");
        let identity = age::x25519::Identity::generate();
        std::fs::write(
            &master_key_path,
            format!("{}\n", identity.to_string().expose_secret()),
        )
        .unwrap();
        set_mode(&master_key_path, 0o400);
        let audit_log = temp.path().join("audit.log");
        let binary = gild_vault_binary();

        let child = Command::new(binary)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--state-path")
            .arg(&state_path)
            .arg("--audit-log")
            .arg(&audit_log)
            .env("GILD_VAULT_MASTER_KEY_PATH", &master_key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        wait_for_socket(&socket_path);
        Self {
            socket_path,
            _temp: temp,
            child,
        }
    }
}

impl Drop for RealVault {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn gild_vault_binary() -> PathBuf {
    workspace_binary("gild-vault")
}

fn gild_vault_proxy_binary() -> PathBuf {
    workspace_binary("gild-vault-proxy")
}

fn workspace_binary(name: &str) -> PathBuf {
    let target_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let binary = target_dir.join(name);
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    command.args(["build", "--quiet", "-p", name]);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    let status = command.status().unwrap();
    assert!(status.success(), "failed to build {name} test binary");
    assert!(binary.exists(), "{} was not built", binary.display());
    binary
}

fn unused_local_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn wait_for_proxy(base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = reqwest::get(format!("{base_url}/health")).await
            && response.status() == StatusCode::OK
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for proxy at {base_url}");
}

fn wait_for_socket(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("timed out waiting for {}", path.display());
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

async fn wait_for_tls_proxy(client: &reqwest::Client, base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(response) = client.get(format!("{base_url}/health")).send().await
            && response.status() == StatusCode::OK
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for proxy at {base_url}");
}

fn tls_client(ca_cert_pem: &str, identity_pem: Option<&str>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca_cert_pem.as_bytes()).unwrap());
    if let Some(identity_pem) = identity_pem {
        builder = builder.identity(reqwest::Identity::from_pem(identity_pem.as_bytes()).unwrap());
    }
    builder.build().unwrap()
}

struct TlsFixture {
    temp: TempDir,
    ca_cert_pem: String,
    ca_cert_path: PathBuf,
    server_cert_path: PathBuf,
    server_key_path: PathBuf,
    client_identity_pem: String,
}

impl TlsFixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let ca = certificate_authority();
        let ca_cert_pem = ca.serialize_pem().unwrap();
        let server = signed_cert(
            &ca,
            "gild-vault-proxy-test",
            vec!["localhost".to_string()],
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        let client = signed_cert(
            &ca,
            "storefront-droplet-do-01",
            vec!["storefront-droplet-do-01".to_string()],
            ExtendedKeyUsagePurpose::ClientAuth,
        );

        let ca_cert_path = temp.path().join("ca.pem");
        let server_cert_path = temp.path().join("server.pem");
        let server_key_path = temp.path().join("server.key");
        std::fs::write(&ca_cert_path, &ca_cert_pem).unwrap();
        std::fs::write(
            &server_cert_path,
            server.serialize_pem_with_signer(&ca).unwrap(),
        )
        .unwrap();
        std::fs::write(&server_key_path, server.serialize_private_key_pem()).unwrap();
        let client_identity_pem = format!(
            "{}{}",
            client.serialize_pem_with_signer(&ca).unwrap(),
            client.serialize_private_key_pem()
        );

        Self {
            temp,
            ca_cert_pem,
            ca_cert_path,
            server_cert_path,
            server_key_path,
            client_identity_pem,
        }
    }
}

fn certificate_authority() -> Certificate {
    let mut params = CertificateParams::new(vec!["vault-proxy-test-ca".to_string()]);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "vault-proxy-test-ca");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    Certificate::from_params(params).unwrap()
}

fn signed_cert(
    ca: &Certificate,
    cn: &str,
    subject_alt_names: Vec<String>,
    extended_key_usage: ExtendedKeyUsagePurpose,
) -> Certificate {
    let mut params = CertificateParams::new(subject_alt_names);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![extended_key_usage];
    let cert = Certificate::from_params(params).unwrap();
    let _ = cert.serialize_pem_with_signer(ca).unwrap();
    cert
}
