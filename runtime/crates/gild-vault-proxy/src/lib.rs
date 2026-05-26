use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use gild_vault_client::{VaultClient, VaultClientError};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[cfg(test)]
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct AppState {
    token: String,
    upstream: Arc<RwLock<VaultUpstream>>,
    peers: Arc<Vec<PeerUpstream>>,
    audit_log_path: Option<PathBuf>,
}

impl AppState {
    pub fn new(token: impl Into<String>, vault: VaultClient) -> Self {
        Self {
            token: token.into(),
            upstream: Arc::new(RwLock::new(VaultUpstream::Local(vault))),
            peers: Arc::new(Vec::new()),
            audit_log_path: None,
        }
    }

    pub fn with_peers(mut self, peers: Vec<PeerUpstream>) -> Self {
        self.peers = Arc::new(peers);
        self
    }

    pub fn with_audit_log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit_log_path = Some(path.into());
        self
    }

    pub async fn check_and_failover(&self) {
        if self.current_status().await.is_ok() {
            return;
        }

        match self.best_healthy_peer().await {
            Some((base_url, status)) => {
                let old = self.upstream.read().await.label();
                eprintln!(
                    "gild-vault-proxy switching to replica: was={old}, now={}, epoch={}",
                    base_url, status.epoch
                );
                *self.upstream.write().await = VaultUpstream::PeerHttp {
                    base_url,
                    token: self.token.clone(),
                    client: reqwest::Client::new(),
                };
            }
            None => {
                eprintln!("gild-vault-proxy no healthy vault peer found; serving retryable 503");
            }
        }
    }

    async fn current_status(&self) -> Result<ProxyStatus, ProxyRequestError> {
        self.upstream.read().await.status().await
    }

    async fn best_healthy_peer(&self) -> Option<(String, ProxyStatus)> {
        let mut best = None;
        for peer in self.peers.iter() {
            match peer.status(&self.token).await {
                Ok(status) if status.ok => {
                    if best
                        .as_ref()
                        .is_none_or(|(_, current): &(String, ProxyStatus)| {
                            status.epoch > current.epoch
                        })
                    {
                        best = Some((peer.base_url.clone(), status));
                    }
                }
                Ok(_) => {}
                Err(err) => eprintln!(
                    "gild-vault-proxy peer health check failed for {}: {err}",
                    peer.base_url
                ),
            }
        }
        best
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/vault/status", get(status))
        .route("/api/vault/list", post(list))
        .route("/api/vault/get", post(get_secret))
        .route("/api/vault/put", post(put_secret))
        .route("/api/vault/delete", post(delete_secret))
        .layer(middleware::from_fn_with_state(state.clone(), audit_request))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn status(State(state): State<AppState>, headers: HeaderMap) -> Response {
    match authorize(&headers, &state.token) {
        Ok(()) => match state.current_status().await {
            Ok(status) => Json(status).into_response(),
            Err(err) => retryable_unavailable(&err.to_string()),
        },
        Err(err) => err.into_response(),
    }
}

async fn audit_request(
    State(state): State<AppState>,
    peer: Option<Extension<RequestPeer>>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let peer = peer.map(|Extension(peer)| peer);
    let response = next.run(request).await;
    if let Some(path_buf) = state.audit_log_path.as_ref() {
        let peer_addr = peer.as_ref().and_then(|peer| peer.remote_addr);
        let event = AuditEvent {
            ts_unix_ms: now_unix_ms(),
            method: &method,
            path: &path,
            status: response.status().as_u16(),
            peer_addr: peer_addr.as_ref(),
            tls_client_cn: peer.as_ref().and_then(|peer| peer.tls_client_cn.as_deref()),
        };
        if let Err(err) = append_audit(path_buf, &event) {
            eprintln!("gild-vault-proxy audit write failed: {err}");
        }
    }
    response
}

fn append_audit(path: &PathBuf, event: &AuditEvent<'_>) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, event)?;
    file.write_all(b"\n")
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[derive(Debug, Clone)]
pub struct RequestPeer {
    pub remote_addr: Option<SocketAddr>,
    pub tls_client_cn: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    ts_unix_ms: u128,
    method: &'a str,
    path: &'a str,
    status: u16,
    peer_addr: Option<&'a SocketAddr>,
    tls_client_cn: Option<&'a str>,
}

#[derive(Clone, Debug)]
enum VaultUpstream {
    Local(VaultClient),
    PeerHttp {
        base_url: String,
        token: String,
        client: reqwest::Client,
    },
    #[cfg(test)]
    Mock(MockVault),
}

#[derive(Clone, Debug)]
pub struct PeerUpstream {
    base_url: String,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct MockVault {
    data: Arc<RwLock<HashMap<String, String>>>,
    healthy: Arc<RwLock<bool>>,
    epoch: u64,
}

#[cfg(test)]
impl MockVault {
    fn new(epoch: u64, data: Arc<RwLock<HashMap<String, String>>>) -> Self {
        Self {
            data,
            healthy: Arc::new(RwLock::new(true)),
            epoch,
        }
    }

    async fn set_healthy(&self, healthy: bool) {
        *self.healthy.write().await = healthy;
    }

    async fn status(&self) -> Result<ProxyStatus, ProxyRequestError> {
        if !*self.healthy.read().await {
            return Err(ProxyRequestError::Upstream("mock vault down".to_string()));
        }
        Ok(ProxyStatus {
            ok: true,
            upstream: "mock".to_string(),
            epoch: self.epoch,
            fenced: false,
            mode: "authoritative".to_string(),
        })
    }

    async fn list_for_shop(&self, shop_id: &str) -> Result<Vec<String>, ProxyRequestError> {
        self.status().await?;
        let prefix = shop_prefix(shop_id);
        let mut keys = self
            .data
            .read()
            .await
            .keys()
            .filter_map(|key| key.strip_prefix(&prefix).map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    async fn get_for_shop(&self, key: &str, shop_id: &str) -> Result<String, ProxyRequestError> {
        self.status().await?;
        self.data
            .read()
            .await
            .get(&shop_key(shop_id, key))
            .cloned()
            .ok_or_else(|| ProxyRequestError::Vault("not_found".to_string()))
    }

    async fn put_for_shop(
        &self,
        key: &str,
        value: &str,
        shop_id: &str,
    ) -> Result<(), ProxyRequestError> {
        self.status().await?;
        self.data
            .write()
            .await
            .insert(shop_key(shop_id, key), value.to_string());
        Ok(())
    }

    async fn delete_for_shop(&self, key: &str, shop_id: &str) -> Result<(), ProxyRequestError> {
        self.status().await?;
        self.data.write().await.remove(&shop_key(shop_id, key));
        Ok(())
    }
}

impl PeerUpstream {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: normalize_base_url(base_url.into()),
        }
    }

    async fn status(&self, token: &str) -> Result<ProxyStatus, ProxyRequestError> {
        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/api/vault/status", self.base_url))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|err| ProxyRequestError::Upstream(err.to_string()))?;
        if !response.status().is_success() {
            return Err(ProxyRequestError::Upstream(format!(
                "peer returned HTTP {}",
                response.status()
            )));
        }
        response
            .json::<ProxyStatus>()
            .await
            .map_err(|err| ProxyRequestError::Upstream(err.to_string()))
    }
}

impl VaultUpstream {
    fn label(&self) -> String {
        match self {
            Self::Local(vault) => vault.socket_path.display().to_string(),
            Self::PeerHttp { base_url, .. } => base_url.clone(),
            #[cfg(test)]
            Self::Mock(_) => "mock".to_string(),
        }
    }

    async fn status(&self) -> Result<ProxyStatus, ProxyRequestError> {
        match self {
            Self::Local(vault) => {
                let health = vault
                    .health()
                    .await
                    .map_err(|err| ProxyRequestError::Upstream(err.to_string()))?;
                Ok(ProxyStatus {
                    ok: true,
                    upstream: self.label(),
                    epoch: health.epoch.unwrap_or_default(),
                    fenced: health.fenced.unwrap_or(false),
                    mode: health.mode.unwrap_or_else(|| "unknown".to_string()),
                })
            }
            Self::PeerHttp {
                base_url,
                token,
                client,
            } => {
                let response = client
                    .get(format!("{base_url}/api/vault/status"))
                    .bearer_auth(token)
                    .send()
                    .await
                    .map_err(|err| ProxyRequestError::Upstream(err.to_string()))?;
                if !response.status().is_success() {
                    return Err(ProxyRequestError::Upstream(format!(
                        "peer returned HTTP {}",
                        response.status()
                    )));
                }
                response
                    .json::<ProxyStatus>()
                    .await
                    .map_err(|err| ProxyRequestError::Upstream(err.to_string()))
            }
            #[cfg(test)]
            Self::Mock(vault) => vault.status().await,
        }
    }

    async fn list_for_shop(&self, shop_id: &str) -> Result<Vec<String>, ProxyRequestError> {
        match self {
            Self::Local(vault) => vault
                .list_for_shop(shop_id)
                .await
                .map(|keys| strip_shop_prefixes(shop_id, keys))
                .map_err(ProxyRequestError::from),
            Self::PeerHttp { .. } => self
                .proxy_request("list", &serde_json::json!({ "shopId": shop_id }))
                .await
                .and_then(|body| {
                    serde_json::from_value::<Vec<String>>(
                        body.get("keys").cloned().unwrap_or_default(),
                    )
                    .map_err(|err| ProxyRequestError::Upstream(err.to_string()))
                }),
            #[cfg(test)]
            Self::Mock(vault) => vault.list_for_shop(shop_id).await,
        }
    }

    async fn get_for_shop(&self, key: &str, shop_id: &str) -> Result<String, ProxyRequestError> {
        match self {
            Self::Local(vault) => vault
                .get_for_shop(&shop_key(shop_id, key), shop_id)
                .await
                .map_err(ProxyRequestError::from),
            Self::PeerHttp { .. } => self
                .proxy_request("get", &serde_json::json!({ "shopId": shop_id, "key": key }))
                .await
                .and_then(|body| {
                    body.get("value")
                        .and_then(|value| value.as_str())
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| ProxyRequestError::Upstream("missing value".to_string()))
                }),
            #[cfg(test)]
            Self::Mock(vault) => vault.get_for_shop(key, shop_id).await,
        }
    }

    async fn put_for_shop(
        &self,
        key: &str,
        value: &str,
        shop_id: &str,
    ) -> Result<(), ProxyRequestError> {
        match self {
            Self::Local(vault) => vault
                .put_for_shop(&shop_key(shop_id, key), value, shop_id)
                .await
                .map_err(ProxyRequestError::from),
            Self::PeerHttp { .. } => self
                .proxy_request(
                    "put",
                    &serde_json::json!({ "shopId": shop_id, "key": key, "value": value }),
                )
                .await
                .map(|_| ()),
            #[cfg(test)]
            Self::Mock(vault) => vault.put_for_shop(key, value, shop_id).await,
        }
    }

    async fn delete_for_shop(&self, key: &str, shop_id: &str) -> Result<(), ProxyRequestError> {
        match self {
            Self::Local(vault) => vault
                .delete_for_shop(&shop_key(shop_id, key), shop_id)
                .await
                .map_err(ProxyRequestError::from),
            Self::PeerHttp { .. } => self
                .proxy_request(
                    "delete",
                    &serde_json::json!({ "shopId": shop_id, "key": key }),
                )
                .await
                .map(|_| ()),
            #[cfg(test)]
            Self::Mock(vault) => vault.delete_for_shop(key, shop_id).await,
        }
    }

    async fn proxy_request(
        &self,
        op: &str,
        body: &serde_json::Value,
    ) -> Result<serde_json::Value, ProxyRequestError> {
        let Self::PeerHttp {
            base_url,
            token,
            client,
        } = self
        else {
            return Err(ProxyRequestError::Upstream(
                "not an HTTP peer upstream".to_string(),
            ));
        };
        let response = client
            .post(format!("{base_url}/api/vault/{op}"))
            .bearer_auth(token)
            .json(body)
            .send()
            .await
            .map_err(|err| ProxyRequestError::Upstream(err.to_string()))?;
        let status = response.status();
        let body = response
            .json::<serde_json::Value>()
            .await
            .map_err(|err| ProxyRequestError::Upstream(err.to_string()))?;
        if !status.is_success() {
            return Err(ProxyRequestError::Upstream(format!(
                "peer returned HTTP {status}: {body}"
            )));
        }
        if body.get("ok").and_then(|ok| ok.as_bool()) == Some(false) {
            let message = body
                .get("error")
                .and_then(|error| error.as_str())
                .unwrap_or("vault_error")
                .to_string();
            return Err(ProxyRequestError::Vault(message));
        }
        Ok(body)
    }
}

#[derive(Debug)]
enum ProxyRequestError {
    Vault(String),
    Upstream(String),
}

impl From<VaultClientError> for ProxyRequestError {
    fn from(value: VaultClientError) -> Self {
        match value {
            VaultClientError::Vault(message) => Self::Vault(message),
            err => Self::Upstream(err.to_string()),
        }
    }
}

impl std::fmt::Display for ProxyRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vault(message) | Self::Upstream(message) => write!(f, "{message}"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct ProxyStatus {
    ok: bool,
    upstream: String,
    epoch: u64,
    fenced: bool,
    mode: String,
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultRequestBody>,
) -> Response {
    match authorize(&headers, &state.token).and_then(|_| validate_shop_id(&request.shop_id)) {
        Ok(()) => json_result(
            state
                .upstream
                .read()
                .await
                .list_for_shop(&request.shop_id)
                .await,
            |keys| serde_json::json!({ "ok": true, "keys": keys }),
        ),
        Err(err) => err.into_response(),
    }
}

async fn get_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultRequestBody>,
) -> Response {
    let key = match authorize(&headers, &state.token)
        .and_then(|_| validate_shop_id(&request.shop_id))
        .and_then(|_| required_key(&request))
    {
        Ok(key) => key,
        Err(err) => return err.into_response(),
    };

    json_result(
        state
            .upstream
            .read()
            .await
            .get_for_shop(key, &request.shop_id)
            .await,
        |value| serde_json::json!({ "ok": true, "value": value }),
    )
}

async fn put_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultRequestBody>,
) -> Response {
    let (key, value) = match authorize(&headers, &state.token)
        .and_then(|_| validate_shop_id(&request.shop_id))
        .and_then(|_| required_key(&request))
        .and_then(|key| required_value(&request).map(|value| (key, value)))
    {
        Ok(parts) => parts,
        Err(err) => return err.into_response(),
    };

    json_result(
        state
            .upstream
            .read()
            .await
            .put_for_shop(key, value, &request.shop_id)
            .await,
        |_| serde_json::json!({ "ok": true }),
    )
}

async fn delete_secret(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultRequestBody>,
) -> Response {
    let key = match authorize(&headers, &state.token)
        .and_then(|_| validate_shop_id(&request.shop_id))
        .and_then(|_| required_key(&request))
    {
        Ok(key) => key,
        Err(err) => return err.into_response(),
    };

    json_result(
        state
            .upstream
            .read()
            .await
            .delete_for_shop(key, &request.shop_id)
            .await,
        |_| serde_json::json!({ "ok": true }),
    )
}

fn authorize(headers: &HeaderMap, expected: &str) -> Result<(), ProxyError> {
    let Some(header) = headers.get(axum::http::header::AUTHORIZATION) else {
        return Err(ProxyError::unauthorized());
    };
    let Ok(value) = header.to_str() else {
        return Err(ProxyError::unauthorized());
    };
    let Some(token) = value.strip_prefix("Bearer ") else {
        return Err(ProxyError::unauthorized());
    };
    if constant_time_eq(token.as_bytes(), expected.as_bytes()) {
        Ok(())
    } else {
        Err(ProxyError::unauthorized())
    }
}

fn required_key(request: &VaultRequestBody) -> Result<&str, ProxyError> {
    let Some(key) = request.key.as_deref() else {
        return Err(ProxyError::bad_request("key_required"));
    };
    validate_key(key)?;
    Ok(key)
}

fn required_value(request: &VaultRequestBody) -> Result<&str, ProxyError> {
    request
        .value
        .as_deref()
        .ok_or_else(|| ProxyError::bad_request("value_required"))
}

fn validate_shop_id(shop_id: &str) -> Result<(), ProxyError> {
    if shop_id.is_empty()
        || shop_id.len() > 128
        || !shop_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Err(ProxyError::bad_request("invalid_shop_id"))
    } else {
        Ok(())
    }
}

fn validate_key(key: &str) -> Result<(), ProxyError> {
    if key.is_empty()
        || key.len() > 256
        || key == "."
        || key == ".."
        || key.contains('/')
        || key.contains('\\')
        || key.bytes().any(|b| b.is_ascii_control())
    {
        Err(ProxyError::bad_request("invalid_key"))
    } else {
        Ok(())
    }
}

fn shop_key(shop_id: &str, key: &str) -> String {
    format!("{}{key}", shop_prefix(shop_id))
}

fn shop_prefix(shop_id: &str) -> String {
    format!("shops/{shop_id}/")
}

fn strip_shop_prefixes(shop_id: &str, keys: Vec<String>) -> Vec<String> {
    let prefix = shop_prefix(shop_id);
    keys.into_iter()
        .filter_map(|key| key.strip_prefix(&prefix).map(ToOwned::to_owned))
        .collect()
}

fn json_result<T>(
    result: Result<T, ProxyRequestError>,
    ok: impl FnOnce(T) -> serde_json::Value,
) -> Response {
    match result {
        Ok(value) => Json(ok(value)).into_response(),
        Err(ProxyRequestError::Vault(message)) => vault_error_response(message),
        Err(err) => retryable_unavailable(&err.to_string()),
    }
}

fn vault_error_response(message: String) -> Response {
    let status = match message.as_str() {
        "demoted_fenced" | "replica_read_only" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::OK,
    };
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
}

fn retryable_unavailable(message: &str) -> Response {
    let mut response = error(StatusCode::SERVICE_UNAVAILABLE, message);
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn normalize_base_url(url: String) -> String {
    url.trim_end_matches('/').to_string()
}

pub fn parse_peer_upstreams(raw: Option<&str>) -> Vec<PeerUpstream> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PeerUpstream::new)
        .collect()
}

#[derive(Debug, Clone, Copy)]
struct ProxyError {
    status: StatusCode,
    message: &'static str,
}

impl ProxyError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: "unauthorized",
        }
    }

    fn bad_request(message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message,
        }
    }
}

impl IntoResponse for ProxyError {
    fn into_response(self) -> Response {
        error(self.status, self.message)
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for i in 0..max_len {
        let a = left.get(i).copied().unwrap_or(0);
        let b = right.get(i).copied().unwrap_or(0);
        diff |= usize::from(a ^ b);
    }
    diff == 0
}

#[derive(Debug, Deserialize)]
struct VaultRequestBody {
    #[serde(rename = "shopId")]
    shop_id: String,
    key: Option<String>,
    value: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    ok: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{self, Body};
    use axum::http::{Request, header};
    use tokio::net::TcpListener;
    use tower::ServiceExt;

    fn test_app(token: &str) -> Router {
        app(AppState::new(
            token,
            VaultClient::from_socket_path("/tmp/missing-gild-vault.sock"),
        ))
    }

    #[tokio::test]
    async fn middleware_rejects_no_token() {
        let response = test_app("secret")
            .oneshot(vault_request(None))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_rejects_wrong_token() {
        let response = test_app("secret")
            .oneshot(vault_request(Some("wrong")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn middleware_accepts_valid_token() {
        let response = test_app("secret")
            .oneshot(vault_request(Some("secret")))
            .await
            .unwrap();
        assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn vault_write_gate_errors_return_503() {
        for message in ["demoted_fenced", "replica_read_only"] {
            let response = json_result::<()>(
                Err(ProxyRequestError::Vault(message.to_string())),
                |_| serde_json::json!({ "ok": true }),
            );

            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body, serde_json::json!({ "ok": false, "error": message }));
        }
    }

    #[tokio::test]
    async fn upstream_errors_return_retryable_503() {
        let response = test_app("secret")
            .oneshot(vault_request(Some("secret")))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(header::RETRY_AFTER).unwrap(),
            HeaderValue::from_static("1")
        );
    }

    #[tokio::test]
    async fn failover_switches_to_highest_epoch_healthy_peer() {
        let low = fake_peer(10, &["LOW_SECRET"]).await;
        let high = fake_peer(1000, &["HIGH_SECRET"]).await;
        let state = AppState::new(
            "secret",
            VaultClient::from_socket_path("/tmp/missing-gild-vault-proxy-test.sock"),
        )
        .with_peers(vec![PeerUpstream::new(low), PeerUpstream::new(high)]);

        state.check_and_failover().await;

        let response = app(state)
            .oneshot(vault_request(Some("secret")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            body,
            serde_json::json!({ "ok": true, "keys": ["HIGH_SECRET"] })
        );
    }

    #[tokio::test]
    async fn peer_failover_forwards_raw_keys_and_preserves_peer_list_keys() {
        let data = Arc::new(RwLock::new(HashMap::new()));
        let vault_a = MockVault::new(10, data.clone());
        let vault_b = MockVault::new(20, data);

        let state_b = AppState {
            token: "secret".to_string(),
            upstream: Arc::new(RwLock::new(VaultUpstream::Mock(vault_b))),
            peers: Arc::new(Vec::new()),
            audit_log_path: None,
        };
        let peer_b = start_test_proxy(app(state_b)).await;

        let state_a = AppState {
            token: "secret".to_string(),
            upstream: Arc::new(RwLock::new(VaultUpstream::Mock(vault_a.clone()))),
            peers: Arc::new(vec![PeerUpstream::new(&peer_b)]),
            audit_log_path: None,
        };
        let proxy_a = start_test_proxy(app(state_a.clone())).await;
        let client = reqwest::Client::new();

        let put = proxy_post(
            &client,
            &proxy_a,
            "put",
            serde_json::json!({
                "shopId": "shop_alpha",
                "key": "SECRET",
                "value": "replicated-secret"
            }),
        )
        .await;
        assert_eq!(put, serde_json::json!({"ok": true}));

        vault_a.set_healthy(false).await;
        state_a.check_and_failover().await;

        let get = proxy_post(
            &client,
            &proxy_a,
            "get",
            serde_json::json!({"shopId": "shop_alpha", "key": "SECRET"}),
        )
        .await;
        assert_eq!(
            get,
            serde_json::json!({"ok": true, "value": "replicated-secret"})
        );

        let list = proxy_post(
            &client,
            &proxy_a,
            "list",
            serde_json::json!({"shopId": "shop_alpha"}),
        )
        .await;
        assert_eq!(list, serde_json::json!({"ok": true, "keys": ["SECRET"]}));
    }

    async fn fake_peer(epoch: u64, keys: &'static [&'static str]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let keys = keys
            .iter()
            .map(|key| (*key).to_string())
            .collect::<Vec<_>>();
        let router = Router::new()
            .route(
                "/api/vault/status",
                get(move || async move {
                    Json(serde_json::json!({
                        "ok": true,
                        "upstream": "fake",
                        "epoch": epoch,
                        "fenced": false,
                        "mode": "authoritative"
                    }))
                }),
            )
            .route(
                "/api/vault/list",
                post(move || {
                    let keys = keys.clone();
                    async move {
                        Json(serde_json::json!({
                            "ok": true,
                            "keys": keys
                        }))
                    }
                }),
            );
        tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn start_test_proxy(app: Router) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    async fn proxy_post(
        client: &reqwest::Client,
        base_url: &str,
        op: &str,
        body: serde_json::Value,
    ) -> serde_json::Value {
        let response = client
            .post(format!("{base_url}/api/vault/{op}"))
            .bearer_auth("secret")
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), StatusCode::OK.as_u16());
        response.json().await.unwrap()
    }

    fn vault_request(token: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/vault/list")
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(token) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        builder
            .body(Body::from(r#"{"shopId":"shop_alpha"}"#))
            .unwrap()
    }
}
