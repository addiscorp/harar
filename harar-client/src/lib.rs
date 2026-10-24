//! The harar client: identity tokens and how to check them (`oidc`), the
//! identity model (`model`), approvals and recovery, and a client for a
//! harar primary or the per-user agent over its local socket.

use std::fmt;
use std::path::{Path, PathBuf};

use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

pub mod approvals;
pub mod model;
pub mod oidc;
pub mod primary;
pub mod recovery;

use primary::{PolicyChange, PolicyView, PrimaryRequest, PrimaryResponse};

/// Where a primary listens on its machine.
pub const DEFAULT_PRIMARY_SOCKET: &str = "/run/harar.sock";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

fn b64_url(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_url_decode(value: &str) -> Result<Vec<u8>, TokenError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::InvalidToken("invalid base64url".to_string()))
}

fn random_jti() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("jti_{}", b64_url(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub crv: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub key_use: String,
    pub x: String,
    /// Only on EC keys.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    TtlOutOfBounds { cap_seconds: u64 },
    InvalidToken(String),
    KeyNotFound,
    Expired,
    WrongAudience,
    BadSignature,
    Json(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::TtlOutOfBounds { cap_seconds } => write!(f, "ttl_seconds must be between 1 and {cap_seconds}"),
            TokenError::InvalidToken(message) => write!(f, "invalid token: {message}"),
            TokenError::KeyNotFound => write!(f, "token kid is not in JWKS"),
            TokenError::Expired => write!(f, "token expired"),
            TokenError::WrongAudience => write!(f, "token audience mismatch"),
            TokenError::BadSignature => write!(f, "token signature check failed"),
            TokenError::Json(message) => write!(f, "token JSON error: {message}"),
        }
    }
}

impl std::error::Error for TokenError {}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn key_id(verifying_key: &VerifyingKey) -> String {
    format!("harar-{}", &b64_url(verifying_key.as_bytes())[..16])
}

/// The JWKS for an Ed25519 key.
pub fn jwks_for_key(verifying_key: &VerifyingKey) -> Jwks {
    Jwks {
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            kid: key_id(verifying_key),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            key_use: "sig".to_string(),
            x: b64_url(verifying_key.as_bytes()),
            y: None,
        }],
    }
}

/// Talks to a harar primary, or the per-user agent, over its local socket.
/// Who you are is the OS user you run as: the kernel tells the other end.
#[derive(Clone, Debug)]
pub struct VaultClient {
    pub socket_path: PathBuf,
}

#[derive(Debug)]
pub enum VaultClientError {
    Io(std::io::Error),
    InvalidResponse(String),
    /// The primary or agent refused, with its reason.
    Vault(String),
    Json(serde_json::Error),
}

impl fmt::Display for VaultClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultClientError::Io(err) => write!(f, "harar I/O error: {err}"),
            VaultClientError::InvalidResponse(message) => write!(f, "harar sent an invalid response: {message}"),
            VaultClientError::Vault(reason) => write!(f, "harar refused: {reason}"),
            VaultClientError::Json(err) => write!(f, "harar JSON error: {err}"),
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

impl VaultClient {
    pub fn from_socket_path(path: impl AsRef<Path>) -> Self {
        Self { socket_path: path.as_ref().to_path_buf() }
    }

    pub async fn get(&self, key: &str) -> Result<String, VaultClientError> {
        let response = self.ask(&PrimaryRequest::Get { key: key.into() }).await?;
        response.value.ok_or_else(|| VaultClientError::InvalidResponse("no value".into()))
    }

    pub async fn put(&self, key: &str, value: &str) -> Result<(), VaultClientError> {
        self.ask(&PrimaryRequest::Put { key: key.into(), value: value.into() }).await.map(drop)
    }

    pub async fn delete(&self, key: &str) -> Result<(), VaultClientError> {
        self.ask(&PrimaryRequest::Delete { key: key.into() }).await.map(drop)
    }

    /// The secret paths you may read.
    pub async fn list(&self) -> Result<Vec<String>, VaultClientError> {
        Ok(self.ask(&PrimaryRequest::List).await?.keys.unwrap_or_default())
    }

    /// The primary's version.
    pub async fn health(&self) -> Result<Option<String>, VaultClientError> {
        Ok(self.ask(&PrimaryRequest::Health).await?.version)
    }

    /// An identity token for the actor you run as.
    pub async fn token(&self, ask: &oidc::TokenAsk) -> Result<(String, oidc::IdentityClaims), VaultClientError> {
        let response = self.ask(&PrimaryRequest::Token(ask.clone())).await?;
        match (response.token, response.claims) {
            (Some(token), Some(claims)) => Ok((token, claims)),
            _ => Err(VaultClientError::InvalidResponse("no token".into())),
        }
    }

    pub async fn policy_show(&self) -> Result<PolicyView, VaultClientError> {
        self.ask(&PrimaryRequest::PolicyShow).await?.policy.ok_or_else(|| VaultClientError::InvalidResponse("no policy".into()))
    }

    pub async fn policy_change(&self, change: &PolicyChange) -> Result<(), VaultClientError> {
        self.ask(&PrimaryRequest::PolicyChange { change: change.clone() }).await.map(drop)
    }

    /// What `actor` (default: you) would be allowed, without doing it.
    pub async fn decide(&self, actor: Option<model::Name>, action: model::Action) -> Result<String, VaultClientError> {
        self.ask(&PrimaryRequest::Decide { actor, action }).await?.decision.ok_or_else(|| VaultClientError::InvalidResponse("no decision".into()))
    }

    async fn ask(&self, request: &PrimaryRequest) -> Result<PrimaryResponse, VaultClientError> {
        let mut stream = UnixStream::connect(&self.socket_path).await.map_err(VaultClientError::Io)?;
        let bytes = serde_json::to_vec(request).map_err(VaultClientError::Json)?;
        stream.write_all(&bytes).await.map_err(VaultClientError::Io)?;
        stream.shutdown().await.map_err(VaultClientError::Io)?;
        let mut response = Vec::new();
        stream.take(MAX_RESPONSE_BYTES as u64).read_to_end(&mut response).await.map_err(VaultClientError::Io)?;
        if response.is_empty() {
            return Err(VaultClientError::InvalidResponse("empty response".into()));
        }
        let response: PrimaryResponse = serde_json::from_slice(&response).map_err(VaultClientError::Json)?;
        if response.ok {
            Ok(response)
        } else {
            Err(VaultClientError::Vault(response.error.unwrap_or_else(|| "refused".into())))
        }
    }
}
