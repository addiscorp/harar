//! The egress broker: agents in VMs call `http://<broker>/<service>/<path>`
//! holding only a placeholder. For every request the broker asks the vault
//! what the placeholder stands for, swaps in the real credential and forwards
//! to that service's upstream, and nowhere else.

use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use harar_client::VaultClient;
use harar_client::broker::PLACEHOLDER_PREFIX;

/// Large enough for model requests with images.
const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Never forwarded either way (RFC 9110 hop-by-hop, plus framing the client
/// library sets itself).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
];

#[derive(Clone)]
pub struct Broker {
    vault: VaultClient,
    client: reqwest::Client,
    audit_log_path: Option<Arc<PathBuf>>,
}

impl Broker {
    pub fn new(vault: VaultClient) -> Self {
        Self {
            vault,
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("build HTTP client"),
            audit_log_path: None,
        }
    }

    pub fn with_audit_log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.audit_log_path = Some(Arc::new(path.into()));
        self
    }
}

/// Serves the broker on `listener` until the process ends.
pub async fn serve(listener: tokio::net::TcpListener, broker: Broker) -> std::io::Result<()> {
    axum::serve(listener, app(broker)).await
}

pub fn app(broker: Broker) -> Router {
    Router::new()
        .route("/:service", any(forward_root))
        .route("/:service/*path", any(forward))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
        .with_state(broker)
}

async fn forward_root(
    State(broker): State<Broker>,
    Path(service): Path<String>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay(broker, service, String::new(), method, uri, headers, body).await
}

async fn forward(
    State(broker): State<Broker>,
    Path((service, path)): Path<(String, String)>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    relay(broker, service, path, method, uri, headers, body).await
}

/// The placeholder the agent sent, in whichever header its tool uses.
fn find_placeholder(headers: &HeaderMap) -> Option<String> {
    headers.values().find_map(|value| {
        let value = value.to_str().ok()?.trim();
        let value = value.strip_prefix("Bearer ").unwrap_or(value).trim();
        value.starts_with(PLACEHOLDER_PREFIX).then(|| value.to_string())
    })
}

async fn relay(
    broker: Broker,
    service: String,
    path: String,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(placeholder) = find_placeholder(&headers) else {
        audit(&broker, None, &service, &method, &path, 401, "no_placeholder");
        return refuse(StatusCode::UNAUTHORIZED, "no_placeholder");
    };
    let resolved = match broker.vault.broker_resolve(&placeholder, &service).await {
        Ok(resolved) => resolved,
        Err(err) => {
            let reason = match err {
                harar_client::VaultClientError::Vault(reason) => reason,
                other => {
                    eprintln!("harar broker: vault unreachable: {other}");
                    "vault_unavailable".to_string()
                }
            };
            audit(&broker, None, &service, &method, &path, 403, &reason);
            return refuse(StatusCode::FORBIDDEN, &reason);
        }
    };

    let mut url = format!("{}/{}", resolved.upstream.trim_end_matches('/'), path);
    if let Some(query) = uri.query() {
        url.push('?');
        url.push_str(query);
    }
    let mut outgoing = reqwest::header::HeaderMap::new();
    for (name, value) in &headers {
        let carries_placeholder = value.to_str().is_ok_and(|v| v.contains(PLACEHOLDER_PREFIX));
        if HOP_BY_HOP.contains(&name.as_str()) || carries_placeholder {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            outgoing.append(name, value);
        }
    }
    let credential = if resolved.bearer { format!("Bearer {}", resolved.value) } else { resolved.value.clone() };
    let (Ok(name), Ok(mut value)) = (
        reqwest::header::HeaderName::from_bytes(resolved.header.as_bytes()),
        reqwest::header::HeaderValue::from_str(&credential),
    ) else {
        return refuse(StatusCode::INTERNAL_SERVER_ERROR, "bad_service_config");
    };
    value.set_sensitive(true);
    outgoing.insert(name, value);

    let Ok(method_out) = reqwest::Method::from_bytes(method.as_str().as_bytes()) else {
        return refuse(StatusCode::METHOD_NOT_ALLOWED, "bad_method");
    };
    let upstream = match broker.client.request(method_out, &url).headers(outgoing).body(body).send().await {
        Ok(upstream) => upstream,
        Err(err) => {
            eprintln!("harar broker: {service} upstream failed: {err}");
            audit(&broker, Some(&resolved.sid), &service, &method, &path, 502, "upstream_failed");
            return refuse(StatusCode::BAD_GATEWAY, "upstream_failed");
        }
    };
    let status = upstream.status().as_u16();
    audit(&broker, Some(&resolved.sid), &service, &method, &path, status, "forwarded");

    let mut response = Response::builder().status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in upstream.headers() {
        if HOP_BY_HOP.contains(&name.as_str()) {
            continue;
        }
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_str().as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            response = response.header(name, value);
        }
    }
    response
        .body(Body::from_stream(upstream.bytes_stream()))
        .unwrap_or_else(|_| refuse(StatusCode::BAD_GATEWAY, "bad_upstream_response"))
}

fn refuse(status: StatusCode, reason: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": reason }))).into_response()
}

/// One line per request: which session called which service, never values.
fn audit(broker: &Broker, sid: Option<&str>, service: &str, method: &Method, path: &str, status: u16, result: &str) {
    let Some(log) = &broker.audit_log_path else { return };
    let line = serde_json::json!({
        "ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
        "sid": sid,
        "service": service,
        "method": method.as_str(),
        "path": format!("/{path}"),
        "status": status,
        "result": result,
    });
    use std::io::Write;
    let written = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log.as_path())
        .and_then(|mut file| writeln!(file, "{line}"));
    if let Err(err) = written {
        eprintln!("harar broker: audit log {}: {err}", log.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_found_in_any_header_with_or_without_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", HeaderValue::from_static("harar-ph-abc"));
        assert_eq!(find_placeholder(&headers).as_deref(), Some("harar-ph-abc"));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer harar-ph-xyz"));
        assert_eq!(find_placeholder(&headers).as_deref(), Some("harar-ph-xyz"));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer sk-real-looking"));
        assert_eq!(find_placeholder(&headers), None);
    }
}
