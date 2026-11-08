//! The harar client: identity tokens and how to check them (`oidc`), the
//! identity model (`model`), approvals and recovery, and a client for a
//! harar primary or the per-user agent over its local socket.
//!
#![doc = include_str!("../README.md")]

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

/// What a reference to a vault key starts with: `harar://prod/shop/STRIPE_KEY`
/// names the key `prod/shop/STRIPE_KEY`, as `op://` names a 1Password field.
pub const REFERENCE_PREFIX: &str = "harar://";

/// The vault key a value refers to, if the whole value is a reference.
pub fn reference(value: &str) -> Option<&str> {
    value
        .strip_prefix(REFERENCE_PREFIX)
        .filter(|key| !key.is_empty() && !key.chars().any(char::is_whitespace))
}

/// The per-user agent's folder (`harar agent`): its socket and vault. In the
/// user's Application Support on macOS, in `$XDG_RUNTIME_DIR/harar` on Linux,
/// else `~/.harar`.
pub fn agent_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/harar");
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("harar");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    home.join(".harar")
}

/// Where the per-user agent listens.
pub fn default_agent_socket() -> PathBuf {
    agent_dir().join("agent.sock")
}

/// The harar agent on this machine, at its own socket: no account, no token.
/// The agent answers only the user it runs as.
pub fn vault() -> VaultClient {
    VaultClient::from_socket_path(default_agent_socket())
}
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
    /// Not a `harar://` reference.
    Reference(String),
    Json(serde_json::Error),
}

impl fmt::Display for VaultClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultClientError::Io(err) => write!(f, "harar I/O error: {err}"),
            VaultClientError::InvalidResponse(message) => write!(f, "harar sent an invalid response: {message}"),
            VaultClientError::Vault(reason) => write!(f, "harar refused: {reason}"),
            VaultClientError::Reference(value) => write!(f, "not a harar:// reference: {value:?}"),
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

    /// `harar://` references resolved to their values.
    pub fn secrets(&self) -> Secrets<'_> {
        Secrets { client: self }
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

    /// Applies the change, or, once approver devices exist and it widens,
    /// returns the request now waiting for a person.
    pub async fn policy_change(&self, change: &PolicyChange) -> Result<Option<primary::Pending>, VaultClientError> {
        self.ask(&PrimaryRequest::PolicyChange { change: change.clone() }).await.map(|response| response.pending)
    }

    /// The requests waiting for a person, and the approver devices.
    pub async fn approvals(&self) -> Result<Approvals, VaultClientError> {
        let response = self.ask(&PrimaryRequest::Approvals).await?;
        Ok(Approvals {
            pending: response.approvals.unwrap_or_default(),
            devices: response.devices.unwrap_or_default(),
            notices: response.notices.unwrap_or_default(),
            recovery_codes_left: response.recovery_codes_left.unwrap_or_default(),
        })
    }

    /// A signed decision; returns `approved`, `denied` or `pending <have>/<need>`.
    /// The decision, and the new recovery codes when it approved a set of yours.
    pub async fn submit(&self, approval: approvals::Approval) -> Result<(String, Option<Vec<String>>), VaultClientError> {
        let response = self.ask(&PrimaryRequest::Submit { approval }).await?;
        let decision = response.decision.ok_or_else(|| VaultClientError::InvalidResponse("no decision".into()))?;
        Ok((decision, response.recovery_codes))
    }

    /// Enrolls a device: its id when enrolled at once, or the request that
    /// waits for one of the person's other devices; and, for a person's first
    /// device, their recovery codes (shown once).
    pub async fn add_device(&self, device: approvals::ApproverDevice) -> Result<AddedDevice, VaultClientError> {
        let response = self.ask(&PrimaryRequest::AddDevice { device }).await?;
        Ok(AddedDevice { id: response.value, pending: response.pending, recovery_codes: response.recovery_codes })
    }

    /// Enrolls `device` with one of your recovery codes; its id, and your
    /// other devices (who should be told).
    pub async fn recover(&self, code: &str, device: approvals::ApproverDevice) -> Result<(String, Vec<approvals::ApproverDevice>), VaultClientError> {
        let response = self.ask(&PrimaryRequest::Recover { code: code.into(), device }).await?;
        let id = response.value.ok_or_else(|| VaultClientError::InvalidResponse("no device id".into()))?;
        Ok((id, response.devices.unwrap_or_default()))
    }

    /// Asks for a new set of your recovery codes: the request your own device approves.
    pub async fn new_recovery_codes(&self) -> Result<primary::Pending, VaultClientError> {
        self.ask(&PrimaryRequest::NewRecoveryCodes).await?.pending.ok_or_else(|| VaultClientError::InvalidResponse("no request".into()))
    }

    /// The hosts you may send `key` to.
    pub async fn hosts(&self, key: &str) -> Result<Vec<String>, VaultClientError> {
        Ok(self.ask(&PrimaryRequest::Hosts { key: key.into() }).await?.hosts.unwrap_or_default())
    }

    /// Lets `key` go to `host` (a per-user agent's vault; a primary says to
    /// use a role's `send` permission).
    pub async fn allow_host(&self, key: &str, host: &str) -> Result<(), VaultClientError> {
        self.ask(&PrimaryRequest::AllowHost { key: key.into(), host: host.into() }).await.map(drop)
    }

    pub async fn revoke_host(&self, key: &str, host: &str) -> Result<(), VaultClientError> {
        self.ask(&PrimaryRequest::RevokeHost { key: key.into(), host: host.into() }).await.map(drop)
    }

    /// The value of `key`, for a request to `host` only.
    pub async fn send(&self, key: &str, host: &str) -> Result<String, VaultClientError> {
        self.ask(&PrimaryRequest::Send { key: key.into(), host: host.into() }).await?.value.ok_or_else(|| VaultClientError::InvalidResponse("no value".into()))
    }

    /// The request one of your other devices approves to revoke `id`.
    pub async fn remove_device(&self, id: &str) -> Result<primary::Pending, VaultClientError> {
        self.ask(&PrimaryRequest::RemoveDevice { id: id.into() }).await?.pending.ok_or_else(|| VaultClientError::InvalidResponse("no request".into()))
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

/// `harar://` references resolved to their values, the shape of 1Password's
/// `client.secrets.resolve("op://…")`. The value is read when asked for and
/// held only by the caller.
#[derive(Debug)]
pub struct Secrets<'a> {
    client: &'a VaultClient,
}

impl Secrets<'_> {
    /// The value `reference` (`harar://prod/shop/STRIPE_KEY`) names.
    pub async fn resolve(&self, reference: &str) -> Result<String, VaultClientError> {
        let key = crate::reference(reference).ok_or_else(|| VaultClientError::Reference(reference.into()))?;
        self.client.get(key).await
    }

    /// Each reference's value, in order; the first that fails is the error.
    pub async fn resolve_all(&self, references: &[&str]) -> Result<Vec<String>, VaultClientError> {
        let mut values = Vec::with_capacity(references.len());
        for reference in references {
            values.push(self.resolve(reference).await?);
        }
        Ok(values)
    }
}

/// What `add_device` did.
#[derive(Debug)]
pub struct AddedDevice {
    /// Enrolled now, with this id.
    pub id: Option<String>,
    /// Or waiting for an approval from a device already there.
    pub pending: Option<primary::Pending>,
    /// A person's first device: their recovery codes, shown once.
    pub recovery_codes: Option<Vec<String>>,
}

/// What waits for a person, the approver devices, and what the caller should know.
#[derive(Debug)]
pub struct Approvals {
    pub pending: Vec<primary::Pending>,
    pub devices: Vec<approvals::ApproverDevice>,
    /// About the caller's own account, newest last.
    pub notices: Vec<primary::Notice>,
    pub recovery_codes_left: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    /// A stand-in harar on a unix socket: answers each request with
    /// `reply(request)` and records what it was asked.
    async fn harar(reply: fn(&serde_json::Value) -> String) -> (tempfile::TempDir, PathBuf, tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let socket = dir.path().join("h.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let (asked, requests) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let mut body = Vec::new();
                conn.read_to_end(&mut body).await.expect("read");
                let request: serde_json::Value = serde_json::from_slice(&body).expect("json");
                let answer = reply(&request);
                asked.send(request).expect("record");
                conn.write_all(answer.as_bytes()).await.expect("write");
            }
        });
        (dir, socket, requests)
    }

    #[tokio::test]
    async fn resolve_reads_the_key_a_reference_names() {
        let (_dir, socket, mut requests) = harar(|r| match r["key"].as_str() {
            Some("prod/shop/STRIPE_KEY") => r#"{"ok":true,"value":"sk_live_real"}"#.into(),
            Some("prod/shop/OTHER") => r#"{"ok":true,"value":"other"}"#.into(),
            _ => r#"{"ok":false,"error":"not_found"}"#.into(),
        })
        .await;
        let v = VaultClient::from_socket_path(&socket);
        assert_eq!(v.secrets().resolve("harar://prod/shop/STRIPE_KEY").await.unwrap(), "sk_live_real");
        assert_eq!(requests.recv().await.unwrap(), serde_json::json!({ "op": "get", "key": "prod/shop/STRIPE_KEY" }));
        assert_eq!(
            v.secrets().resolve_all(&["harar://prod/shop/STRIPE_KEY", "harar://prod/shop/OTHER"]).await.unwrap(),
            ["sk_live_real", "other"]
        );
        assert!(matches!(v.secrets().resolve("harar://prod/shop/GONE").await, Err(VaultClientError::Vault(reason)) if reason == "not_found"));
        // Not a reference: refused before harar is asked anything.
        for not_one in ["prod/shop/STRIPE_KEY", "op://Prod/Stripe/credential", "harar://", "harar://a b"] {
            assert!(matches!(v.secrets().resolve(not_one).await, Err(VaultClientError::Reference(_))), "{not_one}");
        }
        drop(v);
        let mut asked = 1;
        while requests.try_recv().is_ok() {
            asked += 1;
        }
        assert_eq!(asked, 4, "the three references after the first, and nothing for the non-references");
    }

    #[test]
    fn vault_finds_the_agent_where_harar_agent_listens() {
        assert_eq!(vault().socket_path, default_agent_socket());
        assert_eq!(default_agent_socket(), agent_dir().join("agent.sock"));
    }
}
