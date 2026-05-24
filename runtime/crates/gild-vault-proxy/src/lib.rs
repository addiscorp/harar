use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use gild_vault_client::{VaultClient, VaultClientError};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct AppState {
    token: String,
    vault: VaultClient,
}

impl AppState {
    pub fn new(token: impl Into<String>, vault: VaultClient) -> Self {
        Self {
            token: token.into(),
            vault,
        }
    }
}

pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/vault/list", post(list))
        .route("/api/vault/get", post(get_secret))
        .route("/api/vault/put", post(put_secret))
        .route("/api/vault/delete", post(delete_secret))
        .with_state(state)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { ok: true })
}

async fn list(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<VaultRequestBody>,
) -> Response {
    match authorize(&headers, &state.token).and_then(|_| validate_shop_id(&request.shop_id)) {
        Ok(()) => json_result(state.vault.list_for_shop(&request.shop_id).await, |keys| {
            let prefix = shop_prefix(&request.shop_id);
            let keys = keys
                .into_iter()
                .filter_map(|key| key.strip_prefix(&prefix).map(ToOwned::to_owned))
                .collect::<Vec<_>>();
            serde_json::json!({ "ok": true, "keys": keys })
        }),
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
            .vault
            .get_for_shop(&shop_key(&request.shop_id, key), &request.shop_id)
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
            .vault
            .put_for_shop(&shop_key(&request.shop_id, key), value, &request.shop_id)
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
            .vault
            .delete_for_shop(&shop_key(&request.shop_id, key), &request.shop_id)
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

fn json_result<T>(
    result: Result<T, VaultClientError>,
    ok: impl FnOnce(T) -> serde_json::Value,
) -> Response {
    match result {
        Ok(value) => Json(ok(value)).into_response(),
        Err(VaultClientError::Vault(message)) => {
            Json(serde_json::json!({ "ok": false, "error": message })).into_response()
        }
        Err(err) => error(StatusCode::BAD_GATEWAY, &err.to_string()),
    }
}

fn error(status: StatusCode, message: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "ok": false, "error": message })),
    )
        .into_response()
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
    use axum::body::Body;
    use axum::http::{Request, header};
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
