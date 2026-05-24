use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

const DEFAULT_SOCKET_PATH: &str = "/run/tana-vault.sock";
const DEFAULT_GILD_VAULT_SOCKET_PATH: &str = "/run/gild-vault/sock";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Secrets {
    pub socket_path: PathBuf,
    cache: Arc<Mutex<HashMap<String, String>>>,
}

#[derive(Debug)]
pub enum SecretsError {
    EmptyKey,
    Io(std::io::Error),
    InvalidResponse(String),
    AgentStatus { status: u16, body: String },
    Json(serde_json::Error),
}

#[derive(Clone, Debug)]
pub struct VaultClient {
    pub socket_path: PathBuf,
}

#[derive(Debug)]
pub enum VaultClientError {
    EmptyKey,
    Io(std::io::Error),
    InvalidResponse(String),
    Vault(String),
    Json(serde_json::Error),
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum VaultRequest<'a> {
    Get { key: &'a str },
    Put { key: &'a str, value: &'a str },
    List,
    Delete { key: &'a str },
    Health,
}

#[derive(Debug, serde::Deserialize)]
struct VaultResponse {
    ok: bool,
    value: Option<String>,
    keys: Option<Vec<String>>,
    error: Option<String>,
    version: Option<String>,
    uptime_seconds: Option<u64>,
    key_count: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHealth {
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub key_count: Option<usize>,
}

impl Secrets {
    pub fn from_socket() -> Result<Self, SecretsError> {
        Ok(Self::from_socket_path(DEFAULT_SOCKET_PATH))
    }

    pub fn from_socket_path(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
            cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get(&self, key: &str) -> Result<String, SecretsError> {
        if key.is_empty() {
            return Err(SecretsError::EmptyKey);
        }

        if let Some(value) = self.cache.lock().await.get(key).cloned() {
            return Ok(value);
        }

        let value = self.fetch(key).await?;
        self.cache
            .lock()
            .await
            .insert(key.to_string(), value.clone());
        Ok(value)
    }

    pub async fn boot(&self, keys: &[&str]) -> Result<HashMap<String, String>, SecretsError> {
        let mut values = HashMap::with_capacity(keys.len());
        for key in keys {
            values.insert((*key).to_string(), self.get(key).await?);
        }
        Ok(values)
    }

    async fn fetch(&self, key: &str) -> Result<String, SecretsError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(SecretsError::Io)?;
        let request = format!(
            "GET /v1/secret/{key} HTTP/1.1\r\n\
             Host: gild-vault\r\n\
             Accept: application/json\r\n\
             Connection: close\r\n\
             \r\n"
        );

        stream
            .write_all(request.as_bytes())
            .await
            .map_err(SecretsError::Io)?;
        stream.shutdown().await.map_err(SecretsError::Io)?;

        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES as u64)
            .read_to_end(&mut response)
            .await
            .map_err(SecretsError::Io)?;

        parse_response(&response)
    }
}

impl VaultClient {
    pub fn from_socket() -> Self {
        Self::from_socket_path(
            std::env::var("VAULT_SOCKET")
                .or_else(|_| std::env::var("GILD_VAULT_SOCKET"))
                .unwrap_or_else(|_| DEFAULT_GILD_VAULT_SOCKET_PATH.to_string()),
        )
    }

    pub fn from_socket_path(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, key: &str) -> Result<String, VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self.request(&VaultRequest::Get { key }).await?;
        if response.ok {
            response.value.ok_or_else(|| {
                VaultClientError::InvalidResponse("missing response value".to_string())
            })
        } else {
            Err(VaultClientError::Vault(
                response.error.unwrap_or_else(|| "get_failed".to_string()),
            ))
        }
    }

    pub async fn put(&self, key: &str, value: &str) -> Result<(), VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self.request(&VaultRequest::Put { key, value }).await?;
        if response.ok {
            Ok(())
        } else {
            Err(VaultClientError::Vault(
                response.error.unwrap_or_else(|| "put_failed".to_string()),
            ))
        }
    }

    pub async fn list(&self) -> Result<Vec<String>, VaultClientError> {
        let response = self.request(&VaultRequest::List).await?;
        if response.ok {
            let mut keys = response.keys.unwrap_or_default();
            keys.sort();
            Ok(keys)
        } else {
            Err(VaultClientError::Vault(
                response.error.unwrap_or_else(|| "list_failed".to_string()),
            ))
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self.request(&VaultRequest::Delete { key }).await?;
        if response.ok {
            Ok(())
        } else {
            Err(VaultClientError::Vault(
                response
                    .error
                    .unwrap_or_else(|| "delete_failed".to_string()),
            ))
        }
    }

    pub async fn health(&self) -> Result<VaultHealth, VaultClientError> {
        let response = self.request(&VaultRequest::Health).await?;
        if response.ok {
            Ok(VaultHealth {
                version: response.version,
                uptime_seconds: response.uptime_seconds,
                key_count: response.key_count,
            })
        } else {
            Err(VaultClientError::Vault(
                response
                    .error
                    .unwrap_or_else(|| "health_failed".to_string()),
            ))
        }
    }

    pub async fn get_for_shop(&self, shop_id: &str, key: &str) -> Result<String, VaultClientError> {
        self.get(&shop_key(shop_id, key)?).await
    }

    pub async fn put_for_shop(
        &self,
        shop_id: &str,
        key: &str,
        value: &str,
    ) -> Result<(), VaultClientError> {
        self.put(&shop_key(shop_id, key)?, value).await
    }

    pub async fn delete_for_shop(&self, shop_id: &str, key: &str) -> Result<(), VaultClientError> {
        self.delete(&shop_key(shop_id, key)?).await
    }

    pub async fn list_for_shop(&self, shop_id: &str) -> Result<Vec<String>, VaultClientError> {
        validate_shop_id(shop_id)?;
        let prefix = format!("shops/{shop_id}/");
        let mut keys = self
            .list()
            .await?
            .into_iter()
            .filter_map(|key| key.strip_prefix(&prefix).map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        keys.sort();
        Ok(keys)
    }

    async fn request(&self, request: &VaultRequest<'_>) -> Result<VaultResponse, VaultClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(VaultClientError::Io)?;
        let bytes = serde_json::to_vec(request).map_err(VaultClientError::Json)?;
        stream
            .write_all(&bytes)
            .await
            .map_err(VaultClientError::Io)?;
        stream.shutdown().await.map_err(VaultClientError::Io)?;

        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES as u64)
            .read_to_end(&mut response)
            .await
            .map_err(VaultClientError::Io)?;
        if response.is_empty() {
            return Err(VaultClientError::InvalidResponse("empty response".into()));
        }

        serde_json::from_slice(&response).map_err(VaultClientError::Json)
    }
}

fn shop_key(shop_id: &str, key: &str) -> Result<String, VaultClientError> {
    validate_shop_id(shop_id)?;
    validate_shop_key(key)?;
    Ok(format!("shops/{shop_id}/{key}"))
}

fn validate_shop_id(shop_id: &str) -> Result<(), VaultClientError> {
    if shop_id.is_empty()
        || shop_id.len() > 128
        || !shop_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        Err(VaultClientError::Vault("invalid_shop_id".to_string()))
    } else {
        Ok(())
    }
}

fn validate_shop_key(key: &str) -> Result<(), VaultClientError> {
    if key.is_empty()
        || key.len() > 256
        || key == "."
        || key == ".."
        || key.contains('/')
        || key.contains('\\')
        || key.bytes().any(|b| b.is_ascii_control())
    {
        Err(VaultClientError::Vault("invalid_key".to_string()))
    } else {
        Ok(())
    }
}

impl fmt::Display for SecretsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecretsError::EmptyKey => write!(f, "secret key cannot be empty"),
            SecretsError::Io(err) => write!(f, "vault agent I/O error: {err}"),
            SecretsError::InvalidResponse(message) => {
                write!(f, "vault agent returned an invalid response: {message}")
            }
            SecretsError::AgentStatus { status, body } => {
                write!(f, "vault agent returned HTTP {status}: {body}")
            }
            SecretsError::Json(err) => write!(f, "vault agent JSON error: {err}"),
        }
    }
}

impl fmt::Display for VaultClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultClientError::EmptyKey => write!(f, "vault key cannot be empty"),
            VaultClientError::Io(err) => write!(f, "gild-vault I/O error: {err}"),
            VaultClientError::InvalidResponse(message) => {
                write!(f, "gild-vault returned an invalid response: {message}")
            }
            VaultClientError::Vault(err) => write!(f, "gild-vault rejected request: {err}"),
            VaultClientError::Json(err) => write!(f, "gild-vault JSON error: {err}"),
        }
    }
}

impl std::error::Error for VaultClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VaultClientError::Io(err) => Some(err),
            VaultClientError::Json(err) => Some(err),
            _ => None,
        }
    }
}

impl std::error::Error for SecretsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SecretsError::Io(err) => Some(err),
            SecretsError::Json(err) => Some(err),
            _ => None,
        }
    }
}

fn parse_response(response: &[u8]) -> Result<String, SecretsError> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| SecretsError::InvalidResponse("missing HTTP header terminator".into()))?;
    let (head, body_with_separator) = response.split_at(header_end);
    let body = &body_with_separator[4..];
    let head = std::str::from_utf8(head)
        .map_err(|_| SecretsError::InvalidResponse("headers are not UTF-8".into()))?;
    let status = parse_status(head)?;

    if !(200..300).contains(&status) {
        return Err(SecretsError::AgentStatus {
            status,
            body: String::from_utf8_lossy(body).trim().to_string(),
        });
    }

    let json: serde_json::Value = serde_json::from_slice(body).map_err(SecretsError::Json)?;
    json.get("value")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| SecretsError::InvalidResponse("missing string field `value`".into()))
}

fn parse_status(head: &str) -> Result<u16, SecretsError> {
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| SecretsError::InvalidResponse("missing status line".into()))?;
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| SecretsError::InvalidResponse("missing HTTP version".into()))?;
    if !version.starts_with("HTTP/") {
        return Err(SecretsError::InvalidResponse(
            "status line does not start with HTTP/".into(),
        ));
    }

    parts
        .next()
        .ok_or_else(|| SecretsError::InvalidResponse("missing status code".into()))?
        .parse::<u16>()
        .map_err(|_| SecretsError::InvalidResponse("status code is not numeric".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::net::UnixListener;

    #[tokio::test]
    async fn get_and_boot_read_from_agent_and_cache_values() {
        let server = MockAgent::start(&[
            ("API_KEY", "api-secret"),
            ("prod/deka.gg/STRIPE_SECRET_KEY", "stripe-secret"),
            ("DATABASE_URL", "postgres://local"),
            ("REDIS_URL", "redis://local"),
        ])
        .await;
        let secrets = Secrets::from_socket_path(&server.socket_path);

        assert_eq!(secrets.get("API_KEY").await.unwrap(), "api-secret");
        assert_eq!(secrets.get("API_KEY").await.unwrap(), "api-secret");
        assert_eq!(
            secrets.get("prod/deka.gg/STRIPE_SECRET_KEY").await.unwrap(),
            "stripe-secret"
        );

        let boot = secrets.boot(&["DATABASE_URL", "REDIS_URL"]).await.unwrap();
        assert_eq!(boot.get("DATABASE_URL").unwrap(), "postgres://local");
        assert_eq!(boot.get("REDIS_URL").unwrap(), "redis://local");
        assert_eq!(server.requests.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn get_returns_error_when_agent_is_unreachable() {
        let temp = TempDir::new().unwrap();
        let secrets = Secrets::from_socket_path(temp.path().join("missing.sock"));

        let err = secrets.get("API_KEY").await.unwrap_err();
        assert!(matches!(err, SecretsError::Io(_)));
    }

    struct MockAgent {
        socket_path: PathBuf,
        _temp: TempDir,
        requests: Arc<AtomicUsize>,
    }

    impl MockAgent {
        async fn start(secrets: &[(&str, &str)]) -> Self {
            let temp = TempDir::new().unwrap();
            let socket_path = temp.path().join("vault.sock");
            let listener = UnixListener::bind(&socket_path).unwrap();
            let secrets = Arc::new(
                secrets
                    .iter()
                    .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                    .collect::<HashMap<_, _>>(),
            );
            let requests = Arc::new(AtomicUsize::new(0));

            tokio::spawn({
                let secrets = Arc::clone(&secrets);
                let requests = Arc::clone(&requests);
                async move {
                    loop {
                        let Ok((mut stream, _)) = listener.accept().await else {
                            return;
                        };
                        let secrets = Arc::clone(&secrets);
                        let requests = Arc::clone(&requests);
                        tokio::spawn(async move {
                            requests.fetch_add(1, Ordering::SeqCst);
                            let mut request = Vec::new();
                            let _ = stream.read_to_end(&mut request).await;
                            let key = request_key(&request).unwrap_or_default();
                            let (status, body) = match secrets.get(&key) {
                                Some(value) => ("200 OK", serde_json::json!({ "value": value })),
                                None => {
                                    ("404 Not Found", serde_json::json!({ "error": "missing" }))
                                }
                            };
                            let body = body.to_string();
                            let response = format!(
                                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = stream.write_all(response.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        });
                    }
                }
            });

            Self {
                socket_path,
                _temp: temp,
                requests,
            }
        }
    }

    fn request_key(request: &[u8]) -> Option<String> {
        let request = std::str::from_utf8(request).ok()?;
        let path = request.split_whitespace().nth(1)?;
        path.strip_prefix("/v1/secret/").map(ToOwned::to_owned)
    }
}
