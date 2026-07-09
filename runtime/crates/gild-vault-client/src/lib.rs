use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use seam_ir::{SeamBoundary, SeamContract, SeamDefinition, SeamPrimitive, SeamRecord, SeamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

const DEFAULT_SOCKET_PATH: &str = "/run/tana-vault.sock";
pub const DEFAULT_GILD_VAULT_SOCKET_PATH: &str = "/run/gild-vault.sock";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const ISSUER: &str = "harar";
const MAX_SUBJECT_LEN: usize = 256;
const MAX_RUN_ID_LEN: usize = 128;

fn b64_url(bytes: impl AsRef<[u8]>) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn b64_url_decode(value: &str) -> Result<Vec<u8>, TokenError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| TokenError::InvalidToken("invalid base64url".to_string()))
}

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

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HararTokenTemplate {
    AgentSession,
    RunScoped,
    Service,
}

impl HararTokenTemplate {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "agent-session" => Some(Self::AgentSession),
            "run-scoped" => Some(Self::RunScoped),
            "service" => Some(Self::Service),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::AgentSession => "agent-session",
            Self::RunScoped => "run-scoped",
            Self::Service => "service",
        }
    }

    pub fn ttl_cap_seconds(&self) -> u64 {
        match self {
            Self::AgentSession => 3600,
            Self::RunScoped => 600,
            Self::Service => 900,
        }
    }

    pub fn audience(&self) -> &'static str {
        "linkhash"
    }

    fn scopes(&self, run_id: Option<&str>) -> Result<Vec<String>, TokenError> {
        match self {
            Self::AgentSession => Ok(vec!["agent:session".to_string()]),
            Self::RunScoped => {
                let run_id = run_id.ok_or(TokenError::MissingRunId)?;
                Ok(vec![
                    format!("run:{run_id}:read"),
                    format!("run:{run_id}:write"),
                ])
            }
            Self::Service => Ok(vec!["service:auth".to_string()]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MintTokenRequest {
    pub template: HararTokenTemplate,
    pub subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub ttl_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MintedToken {
    pub token: String,
    pub jti: String,
    pub exp: u64,
    pub aud: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyTokenRequest {
    pub token: String,
    pub audience: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VerifyTokenResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub scopes: Vec<String>,
    pub jti: String,
    pub exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    UnknownTemplate,
    MissingRunId,
    UnexpectedRunId,
    EmptySubject,
    InvalidSubject,
    InvalidRunId,
    TtlOutOfBounds { cap_seconds: u64 },
    InvalidToken(String),
    KeyNotFound,
    Expired,
    WrongAudience,
    BadSignature,
    Json(String),
}

#[derive(Debug, serde::Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum VaultRequest<'a> {
    Get {
        key: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        shop_id: Option<&'a str>,
    },
    Put {
        key: &'a str,
        value: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        shop_id: Option<&'a str>,
    },
    List {
        #[serde(skip_serializing_if = "Option::is_none")]
        shop_id: Option<&'a str>,
    },
    Delete {
        key: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        shop_id: Option<&'a str>,
    },
    Mint {
        template: &'a HararTokenTemplate,
        subject: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        run_id: Option<&'a str>,
        ttl_seconds: u64,
    },
    Verify {
        token: &'a str,
        audience: &'a str,
    },
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
    epoch: Option<u64>,
    fenced: Option<bool>,
    mode: Option<String>,
    token: Option<String>,
    jti: Option<String>,
    exp: Option<u64>,
    aud: Option<String>,
    scopes: Option<Vec<String>>,
    valid: Option<bool>,
    sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultHealth {
    pub version: Option<String>,
    pub uptime_seconds: Option<u64>,
    pub key_count: Option<usize>,
    pub epoch: Option<u64>,
    pub fenced: Option<bool>,
    pub mode: Option<String>,
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
        Self::from_socket_path(default_vault_socket_path())
    }

    pub fn from_socket_path(path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    pub async fn get(&self, key: &str) -> Result<String, VaultClientError> {
        self.get_scoped(key, None).await
    }

    pub async fn get_for_shop(&self, key: &str, shop_id: &str) -> Result<String, VaultClientError> {
        self.get_scoped(key, Some(shop_id)).await
    }

    async fn get_scoped(
        &self,
        key: &str,
        shop_id: Option<&str>,
    ) -> Result<String, VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self.request(&VaultRequest::Get { key, shop_id }).await?;
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
        self.put_scoped(key, value, None).await
    }

    pub async fn put_for_shop(
        &self,
        key: &str,
        value: &str,
        shop_id: &str,
    ) -> Result<(), VaultClientError> {
        self.put_scoped(key, value, Some(shop_id)).await
    }

    async fn put_scoped(
        &self,
        key: &str,
        value: &str,
        shop_id: Option<&str>,
    ) -> Result<(), VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self
            .request(&VaultRequest::Put {
                key,
                value,
                shop_id,
            })
            .await?;
        if response.ok {
            Ok(())
        } else {
            Err(VaultClientError::Vault(
                response.error.unwrap_or_else(|| "put_failed".to_string()),
            ))
        }
    }

    pub async fn list(&self) -> Result<Vec<String>, VaultClientError> {
        self.list_scoped(None).await
    }

    pub async fn list_for_shop(&self, shop_id: &str) -> Result<Vec<String>, VaultClientError> {
        self.list_scoped(Some(shop_id)).await
    }

    async fn list_scoped(&self, shop_id: Option<&str>) -> Result<Vec<String>, VaultClientError> {
        let response = self.request(&VaultRequest::List { shop_id }).await?;
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
        self.delete_scoped(key, None).await
    }

    pub async fn delete_for_shop(&self, key: &str, shop_id: &str) -> Result<(), VaultClientError> {
        self.delete_scoped(key, Some(shop_id)).await
    }

    async fn delete_scoped(
        &self,
        key: &str,
        shop_id: Option<&str>,
    ) -> Result<(), VaultClientError> {
        if key.is_empty() {
            return Err(VaultClientError::EmptyKey);
        }
        let response = self.request(&VaultRequest::Delete { key, shop_id }).await?;
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
                epoch: response.epoch,
                fenced: response.fenced,
                mode: response.mode,
            })
        } else {
            Err(VaultClientError::Vault(
                response
                    .error
                    .unwrap_or_else(|| "health_failed".to_string()),
            ))
        }
    }

    pub async fn mint_token(
        &self,
        request: &MintTokenRequest,
    ) -> Result<MintedToken, VaultClientError> {
        let response = self
            .request(&VaultRequest::Mint {
                template: &request.template,
                subject: &request.subject,
                run_id: request.run_id.as_deref(),
                ttl_seconds: request.ttl_seconds,
            })
            .await?;
        if response.ok {
            Ok(MintedToken {
                token: response.token.ok_or_else(|| {
                    VaultClientError::InvalidResponse("missing token".to_string())
                })?,
                jti: response
                    .jti
                    .ok_or_else(|| VaultClientError::InvalidResponse("missing jti".to_string()))?,
                exp: response
                    .exp
                    .ok_or_else(|| VaultClientError::InvalidResponse("missing exp".to_string()))?,
                aud: response
                    .aud
                    .ok_or_else(|| VaultClientError::InvalidResponse("missing aud".to_string()))?,
                scopes: response.scopes.ok_or_else(|| {
                    VaultClientError::InvalidResponse("missing scopes".to_string())
                })?,
            })
        } else {
            Err(VaultClientError::Vault(
                response.error.unwrap_or_else(|| "mint_failed".to_string()),
            ))
        }
    }

    pub async fn verify_token(
        &self,
        request: &VerifyTokenRequest,
    ) -> Result<VerifyTokenResponse, VaultClientError> {
        let response = self
            .request(&VaultRequest::Verify {
                token: &request.token,
                audience: &request.audience,
            })
            .await?;
        if response.ok {
            Ok(VerifyTokenResponse {
                valid: response.valid.unwrap_or(false),
                sub: response.sub,
                jti: response.jti,
                exp: response.exp,
                error: response.error,
            })
        } else {
            Err(VaultClientError::Vault(
                response
                    .error
                    .unwrap_or_else(|| "verify_failed".to_string()),
            ))
        }
    }

    pub async fn jwks(&self) -> Result<Jwks, VaultClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .map_err(VaultClientError::Io)?;
        let request = "GET /v1/jwks HTTP/1.1\r\nHost: harar\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(VaultClientError::Io)?;
        stream.shutdown().await.map_err(VaultClientError::Io)?;

        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES as u64)
            .read_to_end(&mut response)
            .await
            .map_err(VaultClientError::Io)?;
        parse_http_json_response(&response).map_err(|err| match err {
            SecretsError::AgentStatus { status, body } => VaultClientError::InvalidResponse(
                format!("JWKS endpoint returned HTTP {status}: {body}"),
            ),
            SecretsError::InvalidResponse(message) => VaultClientError::InvalidResponse(message),
            SecretsError::Json(err) => VaultClientError::Json(err),
            SecretsError::Io(err) => VaultClientError::Io(err),
            SecretsError::EmptyKey => VaultClientError::InvalidResponse("empty key".into()),
        })
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

pub fn default_vault_socket_path() -> String {
    std::env::var("HARAR_SOCKET")
        .or_else(|_| std::env::var("VAULT_SOCKET"))
        .or_else(|_| std::env::var("GILD_VAULT_SOCKET"))
        .unwrap_or_else(|_| DEFAULT_GILD_VAULT_SOCKET_PATH.to_string())
}

pub fn harar_auth_contract() -> SeamContract {
    fn primitive(name: SeamPrimitive) -> SeamType {
        SeamType::Primitive { name }
    }
    fn string() -> SeamType {
        primitive(SeamPrimitive::String)
    }
    fn int() -> SeamType {
        primitive(SeamPrimitive::Int)
    }
    fn bool_type() -> SeamType {
        primitive(SeamPrimitive::Bool)
    }
    fn option(item: SeamType) -> SeamType {
        SeamType::Option {
            item: Box::new(item),
        }
    }
    fn list(item: SeamType) -> SeamType {
        SeamType::List {
            item: Box::new(item),
        }
    }
    fn named(name: &str) -> SeamType {
        SeamType::Named {
            name: name.to_string(),
        }
    }
    fn record(name: &str, fields: &[(&str, SeamType)]) -> SeamDefinition {
        SeamDefinition::Record(SeamRecord {
            name: name.to_string(),
            fields: fields
                .iter()
                .map(|(name, ty)| ((*name).to_string(), ty.clone()))
                .collect(),
        })
    }

    let mut contract = SeamContract::new("harar_auth", 1);
    contract.boundaries = vec![
        SeamBoundary {
            function: "mint".to_string(),
            request: "HararMintTokenRequest".to_string(),
            response: "HararMintTokenResponse".to_string(),
        },
        SeamBoundary {
            function: "verify".to_string(),
            request: "HararVerifyTokenRequest".to_string(),
            response: "HararVerifyTokenResponse".to_string(),
        },
        SeamBoundary {
            function: "jwks".to_string(),
            request: "HararJwksRequest".to_string(),
            response: "HararJwksResponse".to_string(),
        },
    ];
    contract.definitions = vec![
        record(
            "HararMintTokenRequest",
            &[
                ("template", string()),
                ("subject", string()),
                ("run_id", option(string())),
                ("ttl_seconds", int()),
            ],
        ),
        record(
            "HararMintTokenResponse",
            &[
                ("ok", bool_type()),
                ("token", option(string())),
                ("jti", option(string())),
                ("exp", option(int())),
                ("aud", option(string())),
                ("scopes", option(list(string()))),
                ("error", option(string())),
            ],
        ),
        record(
            "HararVerifyTokenRequest",
            &[("token", string()), ("audience", string())],
        ),
        record(
            "HararVerifyTokenResponse",
            &[
                ("ok", bool_type()),
                ("valid", option(bool_type())),
                ("sub", option(string())),
                ("jti", option(string())),
                ("exp", option(int())),
                ("error", option(string())),
            ],
        ),
        record("HararJwksRequest", &[]),
        record(
            "HararJwk",
            &[
                ("kty", string()),
                ("kid", string()),
                ("crv", string()),
                ("alg", string()),
                ("use", string()),
                ("x", string()),
            ],
        ),
        record("HararJwksResponse", &[("keys", list(named("HararJwk")))]),
    ];
    contract
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, TokenError> {
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TokenError::InvalidToken("signing key must be 32 bytes".to_string()))?;
    Ok(SigningKey::from_bytes(&key))
}

pub fn signing_key_bytes(key: &SigningKey) -> [u8; 32] {
    key.to_bytes()
}

pub fn key_id(verifying_key: &VerifyingKey) -> String {
    format!("harar-{}", &b64_url(verifying_key.as_bytes())[..16])
}

pub fn jwks_for_key(verifying_key: &VerifyingKey) -> Jwks {
    Jwks {
        keys: vec![Jwk {
            kty: "OKP".to_string(),
            kid: key_id(verifying_key),
            crv: "Ed25519".to_string(),
            alg: "EdDSA".to_string(),
            key_use: "sig".to_string(),
            x: b64_url(verifying_key.as_bytes()),
        }],
    }
}

pub fn mint_token(
    signing_key: &SigningKey,
    request: &MintTokenRequest,
    now_epoch_seconds: u64,
) -> Result<MintedToken, TokenError> {
    if request.subject.trim().is_empty() {
        return Err(TokenError::EmptySubject);
    }
    if !valid_bounded_token_param(&request.subject, MAX_SUBJECT_LEN, true) {
        return Err(TokenError::InvalidSubject);
    }
    if request.ttl_seconds == 0 || request.ttl_seconds > request.template.ttl_cap_seconds() {
        return Err(TokenError::TtlOutOfBounds {
            cap_seconds: request.template.ttl_cap_seconds(),
        });
    }
    if request.template != HararTokenTemplate::RunScoped && request.run_id.is_some() {
        return Err(TokenError::UnexpectedRunId);
    }
    if let Some(run_id) = request.run_id.as_deref() {
        if !valid_bounded_token_param(run_id, MAX_RUN_ID_LEN, false) {
            return Err(TokenError::InvalidRunId);
        }
    }
    let scopes = request.template.scopes(request.run_id.as_deref())?;
    let exp = now_epoch_seconds.saturating_add(request.ttl_seconds);
    let jti = random_jti();
    let claims = TokenClaims {
        iss: ISSUER.to_string(),
        sub: request.subject.clone(),
        aud: request.template.audience().to_string(),
        scopes: scopes.clone(),
        jti: jti.clone(),
        exp,
        run_id: request.run_id.clone(),
    };
    let token = sign_claims(signing_key, &claims)?;
    Ok(MintedToken {
        token,
        jti,
        exp,
        aud: request.template.audience().to_string(),
        scopes,
    })
}

pub fn verify_token(
    jwks: &Jwks,
    token: &str,
    audience: &str,
    now_epoch_seconds: u64,
) -> Result<TokenClaims, TokenError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err(TokenError::InvalidToken(
            "token must have three JWT segments".to_string(),
        ));
    }
    let header: serde_json::Value = serde_json::from_slice(&b64_url_decode(parts[0])?)
        .map_err(|err| TokenError::Json(err.to_string()))?;
    if header.get("alg").and_then(|value| value.as_str()) != Some("EdDSA") {
        return Err(TokenError::InvalidToken(
            "token alg must be EdDSA".to_string(),
        ));
    }
    let kid = header
        .get("kid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| TokenError::InvalidToken("missing kid".to_string()))?;
    let jwk = jwks
        .keys
        .iter()
        .find(|key| key.kid == kid)
        .ok_or(TokenError::KeyNotFound)?;
    if jwk.kty != "OKP" || jwk.crv != "Ed25519" || jwk.alg != "EdDSA" {
        return Err(TokenError::InvalidToken("unsupported jwk".to_string()));
    }
    let key_bytes = b64_url_decode(&jwk.x)?;
    let key_array: [u8; 32] = key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TokenError::InvalidToken("bad Ed25519 key".to_string()))?;
    let verifying_key = VerifyingKey::from_bytes(&key_array)
        .map_err(|_| TokenError::InvalidToken("bad Ed25519 key".to_string()))?;
    let signature_bytes = b64_url_decode(parts[2])?;
    let signature_array: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| TokenError::InvalidToken("bad signature length".to_string()))?;
    let signature = Signature::from_bytes(&signature_array);
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| TokenError::BadSignature)?;

    let claims: TokenClaims = serde_json::from_slice(&b64_url_decode(parts[1])?)
        .map_err(|err| TokenError::Json(err.to_string()))?;
    if claims.iss != ISSUER {
        return Err(TokenError::InvalidToken("wrong issuer".to_string()));
    }
    if claims.aud != audience {
        return Err(TokenError::WrongAudience);
    }
    if claims.exp <= now_epoch_seconds {
        return Err(TokenError::Expired);
    }
    Ok(claims)
}

fn sign_claims(signing_key: &SigningKey, claims: &TokenClaims) -> Result<String, TokenError> {
    let verifying_key = signing_key.verifying_key();
    let header = serde_json::json!({
        "alg": "EdDSA",
        "typ": "JWT",
        "kid": key_id(&verifying_key),
    });
    let header =
        b64_url(serde_json::to_vec(&header).map_err(|err| TokenError::Json(err.to_string()))?);
    let payload =
        b64_url(serde_json::to_vec(claims).map_err(|err| TokenError::Json(err.to_string()))?);
    let signing_input = format!("{header}.{payload}");
    let signature = signing_key.sign(signing_input.as_bytes());
    Ok(format!("{signing_input}.{}", b64_url(signature.to_bytes())))
}

fn random_jti() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("jti_{}", b64_url(bytes))
}

fn valid_bounded_token_param(value: &str, max_len: usize, allow_colon: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b'@' | b'/')
                || (allow_colon && byte == b':')
        })
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

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::UnknownTemplate => write!(f, "unknown template"),
            TokenError::MissingRunId => write!(f, "run-scoped template requires run_id"),
            TokenError::UnexpectedRunId => write!(f, "run_id is only allowed for run-scoped"),
            TokenError::EmptySubject => write!(f, "subject cannot be empty"),
            TokenError::InvalidSubject => write!(
                f,
                "subject must be ASCII and contain only letters, numbers, _, -, ., @, /, or :"
            ),
            TokenError::InvalidRunId => write!(
                f,
                "run_id must be ASCII and contain only letters, numbers, _, -, ., @, or /"
            ),
            TokenError::TtlOutOfBounds { cap_seconds } => {
                write!(f, "ttl_seconds must be between 1 and {cap_seconds}")
            }
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
    let json: serde_json::Value = parse_http_json_response(response)?;
    json.get("value")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| SecretsError::InvalidResponse("missing string field `value`".into()))
}

fn parse_http_json_response<T: serde::de::DeserializeOwned>(
    response: &[u8],
) -> Result<T, SecretsError> {
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

    serde_json::from_slice(body).map_err(SecretsError::Json)
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

    #[test]
    fn named_template_mint_and_jwks_verify_round_trip() {
        let key = generate_signing_key();
        let request = MintTokenRequest {
            template: HararTokenTemplate::RunScoped,
            subject: "agent:khalid".to_string(),
            run_id: Some("run_123".to_string()),
            ttl_seconds: 300,
        };

        let minted = mint_token(&key, &request, 1000).unwrap();
        let claims = verify_token(
            &jwks_for_key(&key.verifying_key()),
            &minted.token,
            "linkhash",
            1200,
        )
        .unwrap();

        assert_eq!(claims.iss, "harar");
        assert_eq!(claims.sub, "agent:khalid");
        assert_eq!(claims.aud, "linkhash");
        assert_eq!(claims.jti, minted.jti);
        assert_eq!(claims.exp, 1300);
        assert_eq!(
            claims.scopes,
            vec![
                "run:run_123:read".to_string(),
                "run:run_123:write".to_string()
            ]
        );
        assert_eq!(claims.run_id.as_deref(), Some("run_123"));
    }

    #[test]
    fn mint_rejects_free_form_shape_and_ttl_over_cap() {
        let key = generate_signing_key();
        let err = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::AgentSession,
                subject: "agent:khalid".to_string(),
                run_id: Some("run_123".to_string()),
                ttl_seconds: 60,
            },
            1000,
        )
        .unwrap_err();
        assert_eq!(err, TokenError::UnexpectedRunId);

        let err = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::RunScoped,
                subject: "agent:khalid".to_string(),
                run_id: Some("run_123".to_string()),
                ttl_seconds: 601,
            },
            1000,
        )
        .unwrap_err();
        assert_eq!(err, TokenError::TtlOutOfBounds { cap_seconds: 600 });
    }

    #[test]
    fn mint_bounds_subject_and_run_id_parameters() {
        let key = generate_signing_key();

        let err = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::AgentSession,
                subject: "agent khalid".to_string(),
                run_id: None,
                ttl_seconds: 60,
            },
            1000,
        )
        .unwrap_err();
        assert_eq!(err, TokenError::InvalidSubject);

        let err = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::RunScoped,
                subject: "agent:khalid".to_string(),
                run_id: Some("run:scope-injection".to_string()),
                ttl_seconds: 60,
            },
            1000,
        )
        .unwrap_err();
        assert_eq!(err, TokenError::InvalidRunId);
    }

    #[test]
    fn verify_rejects_wrong_audience_expired_and_tampered_tokens() {
        let key = generate_signing_key();
        let minted = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::Service,
                subject: "service:gild".to_string(),
                run_id: None,
                ttl_seconds: 60,
            },
            1000,
        )
        .unwrap();
        let jwks = jwks_for_key(&key.verifying_key());

        assert_eq!(
            verify_token(&jwks, &minted.token, "deka", 1001).unwrap_err(),
            TokenError::WrongAudience
        );
        assert_eq!(
            verify_token(&jwks, &minted.token, "linkhash", 1060).unwrap_err(),
            TokenError::Expired
        );

        let mut parts = minted
            .token
            .split('.')
            .map(str::to_string)
            .collect::<Vec<_>>();
        parts[1].push('a');
        let tampered = parts.join(".");
        assert_eq!(
            verify_token(&jwks, &tampered, "linkhash", 1001).unwrap_err(),
            TokenError::BadSignature
        );
    }

    #[test]
    fn verify_rejects_unknown_kid() {
        let key = generate_signing_key();
        let minted = mint_token(
            &key,
            &MintTokenRequest {
                template: HararTokenTemplate::Service,
                subject: "service:gild".to_string(),
                run_id: None,
                ttl_seconds: 60,
            },
            1000,
        )
        .unwrap();
        let mut parts = minted
            .token
            .split('.')
            .map(str::to_string)
            .collect::<Vec<_>>();
        let header = serde_json::json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "harar-wrong-key",
        });
        parts[0] = b64_url(serde_json::to_vec(&header).unwrap());
        let wrong_kid = parts.join(".");

        assert_eq!(
            verify_token(
                &jwks_for_key(&key.verifying_key()),
                &wrong_kid,
                "linkhash",
                1001
            )
            .unwrap_err(),
            TokenError::KeyNotFound
        );
    }

    #[test]
    fn harar_auth_contract_contains_public_jwks_only() {
        let contract = harar_auth_contract();
        let json = serde_json::to_value(&contract).unwrap();

        assert_eq!(json["format"], "seam.contract@1");
        assert_eq!(json["name"], "harar_auth");
        let serialized = json.to_string();
        assert!(serialized.contains("HararMintTokenResponse"));
        assert!(serialized.contains("HararVerifyTokenResponse"));
        assert!(serialized.contains("HararJwksResponse"));
        assert!(!serialized.contains("\"d\""));
        assert!(!serialized.contains("private"));
        assert!(!serialized.contains("signing"));
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
