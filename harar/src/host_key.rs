//! A host's own key, which it signs token assertions with. On a Mac it lives
//! in the Secure Enclave (T2 or Apple silicon) and harar keeps only the
//! enclave's handle; elsewhere it is a key file, and says so.

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as B64URL};
use harar_client::Jwk;
use harar_client::hosts::{HostAssertion, HostTier};
use p256::ecdsa::signature::Signer;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

pub enum HostKey {
    #[cfg(target_os = "macos")]
    Enclave(crate::enclave::EnclaveKey),
    Software(p256::ecdsa::SigningKey),
}

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyFile {
    format: String,
    /// The name the host enrolled as.
    name: String,
    tier: HostTier,
    /// The enclave handle, or the software key's scalar.
    key: String,
}

const FORMAT: &str = "harar.host-key@1";

/// Where `harar host enroll` keeps the key unless told otherwise.
pub fn default_path() -> std::path::PathBuf {
    if cfg!(target_os = "macos") {
        crate::master_key::default_master_key_path().with_file_name("host.key")
    } else {
        std::path::PathBuf::from("/var/lib/harar/host.key")
    }
}

impl HostKey {
    /// A new key: in the Secure Enclave when this Mac has one, unless
    /// `software` is asked for.
    pub fn create(software: bool) -> Result<Self> {
        #[cfg(target_os = "macos")]
        if !software && crate::enclave::available() {
            return Ok(Self::Enclave(crate::enclave::EnclaveKey::create(crate::enclave::Presence::NotRequired)?));
        }
        let _ = software;
        Ok(Self::Software(harar_client::oidc::generate_es256_key()))
    }

    pub fn tier(&self) -> HostTier {
        match self {
            #[cfg(target_os = "macos")]
            Self::Enclave(_) => HostTier::SecureEnclave,
            Self::Software(_) => HostTier::Software,
        }
    }

    pub fn verifying_key(&self) -> Result<p256::ecdsa::VerifyingKey> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Enclave(key) => p256::ecdsa::VerifyingKey::from_sec1_bytes(&key.public_key()?)
                .context("Secure Enclave public key"),
            Self::Software(key) => Ok(*key.verifying_key()),
        }
    }

    pub fn jwk(&self, name: &str) -> Result<Jwk> {
        Ok(harar_client::oidc::p256_jwk(format!("host:{name}"), &self.verifying_key()?))
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        match self {
            #[cfg(target_os = "macos")]
            Self::Enclave(key) => key.sign(message),
            Self::Software(key) => {
                let signature: p256::ecdsa::Signature = key.sign(message);
                Ok(signature.to_bytes().into())
            }
        }
    }

    /// A signed assertion (an ES256 JWT) the issuer trades for a token.
    pub fn assert(&self, name: &str, assertion: &HostAssertion) -> Result<String> {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": format!("host:{name}") });
        let input = format!(
            "{}.{}",
            B64URL.encode(serde_json::to_vec(&header)?),
            B64URL.encode(serde_json::to_vec(assertion)?)
        );
        Ok(format!("{input}.{}", B64URL.encode(self.sign(input.as_bytes())?)))
    }

    /// Writes the key file (mode 0600). It never already exists: enrolling
    /// twice would orphan the first key.
    pub fn save(&self, path: &Path, name: &str) -> Result<()> {
        let key = match self {
            #[cfg(target_os = "macos")]
            Self::Enclave(key) => BASE64.encode(key.handle()?),
            Self::Software(key) => BASE64.encode(harar_client::oidc::es256_key_bytes(key)),
        };
        let file = KeyFile { format: FORMAT.to_string(), name: name.to_string(), tier: self.tier(), key };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        let mut out = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create host key {} (is this host already enrolled?)", path.display()))?;
        out.write_all(&serde_json::to_vec(&file)?)?;
        out.sync_all()?;
        Ok(())
    }

    /// The key and the name the host enrolled as.
    pub fn load(path: &Path) -> Result<(Self, String)> {
        let text = fs::read_to_string(path).with_context(|| format!("read host key {}", path.display()))?;
        let file: KeyFile = serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
        if file.format != FORMAT {
            return Err(anyhow!("{} is not a harar host key", path.display()));
        }
        let bytes = BASE64.decode(&file.key).context("host key encoding")?;
        let key = match file.tier {
            #[cfg(target_os = "macos")]
            HostTier::SecureEnclave => Self::Enclave(crate::enclave::EnclaveKey::from_handle(&bytes)?),
            #[cfg(not(target_os = "macos"))]
            HostTier::SecureEnclave => {
                return Err(anyhow!("{} holds a Secure Enclave key; this is not that Mac", path.display()));
            }
            HostTier::Software => {
                Self::Software(harar_client::oidc::es256_key_from_bytes(&bytes).map_err(|err| anyhow!("{err}"))?)
            }
        };
        Ok((key, file.name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use harar_client::oidc::TokenAsk;

    fn assertion() -> HostAssertion {
        HostAssertion {
            iss: "host:bugsy".into(),
            sub: "svc:gild@bugsy".into(),
            aud: "https://id.example.test".into(),
            iat: 1,
            exp: 61,
            jti: "j".into(),
            ask: TokenAsk { audience: "https://x".into(), scopes: vec![], ttl_seconds: None, act: None, alg: None },
        }
    }

    fn check_round_trip(key: HostKey) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.key");
        key.save(&path, "bugsy").unwrap();
        assert!(key.save(&path, "bugsy").is_err(), "never overwrites a host key");
        let (again, name) = HostKey::load(&path).unwrap();
        assert_eq!(name, "bugsy");
        assert_eq!(again.tier(), key.tier());
        let jwk = key.jwk("bugsy").unwrap();
        assert_eq!(again.jwk("bugsy").unwrap(), jwk);

        let token = again.assert("bugsy", &assertion()).unwrap();
        let payload = harar_client::oidc::verify_signature(&harar_client::Jwks { keys: vec![jwk] }, &token).unwrap();
        let back: HostAssertion = serde_json::from_slice(&payload).unwrap();
        assert_eq!(back, assertion());
    }

    #[test]
    fn software_keys_save_load_and_sign() {
        check_round_trip(HostKey::create(true).unwrap());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn enclave_keys_save_load_and_sign() {
        if crate::enclave::tests::test_key().is_none() {
            return;
        }
        let key = HostKey::create(false).unwrap();
        assert_eq!(key.tier(), HostTier::SecureEnclave);
        check_round_trip(key);
    }
}
