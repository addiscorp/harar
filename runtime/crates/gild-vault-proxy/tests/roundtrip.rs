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
        let socket_path = temp.path().join("gild-vault.sock");
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
    let target_dir = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let binary = target_dir.join("gild-vault");
    if binary.exists() {
        return binary;
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    command.args(["build", "--quiet", "-p", "gild-vault"]);
    if !cfg!(debug_assertions) {
        command.arg("--release");
    }
    let status = command.status().unwrap();
    assert!(status.success(), "failed to build gild-vault test binary");
    assert!(binary.exists(), "{} was not built", binary.display());
    binary
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
