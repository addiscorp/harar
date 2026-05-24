use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use axum::Router;
use gild_vault_client::VaultClient;
use gild_vault_proxy::{AppState, app};
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

#[test]
fn proxy_binary_falls_back_to_production_socket_path_and_refuses_to_bind() {
    let output = Command::new(gild_vault_proxy_binary())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(unused_local_port().to_string())
        .env("VAULT_PROXY_TOKEN", TOKEN)
        .env_remove("VAULT_SOCKET")
        .env_remove("GILD_VAULT_SOCKET")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("gild-vault health check failed on socket /run/gild-vault/sock"),
        "stderr did not include production socket path: {stderr}"
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
        let state_path = temp.path().join("keys.json");
        let audit_log = temp.path().join("audit.log");
        let binary = gild_vault_binary();

        let child = Command::new(binary)
            .arg("--socket")
            .arg(&socket_path)
            .arg("--state-path")
            .arg(&state_path)
            .arg("--audit-log")
            .arg(&audit_log)
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
    if binary.exists() {
        return binary;
    }

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
