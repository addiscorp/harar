use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

const DEFAULT_SOCKET_PATH: &str = "/run/tana-vault.sock";
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
