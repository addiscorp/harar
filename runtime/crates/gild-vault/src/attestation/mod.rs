use crate::{ResolvedWorkload, TOKEN_TTL_SECONDS, VaultClaims};
use anyhow::{Context, Result, bail};
#[cfg(any(test, feature = "tpm"))]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
#[cfg(any(test, feature = "tpm"))]
use serde::Serialize;
#[cfg(test)]
use sha2::{Digest as _, Sha256};
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "tpm")]
pub mod tpm;

#[derive(Clone)]
pub enum AttestationProvider {
    Hs256Dev(Arc<Vec<u8>>),
    #[cfg(feature = "tpm")]
    Tpm(Arc<tpm::TpmProvider>),
}

impl AttestationProvider {
    pub fn load(config_dir: &Path) -> Result<Self> {
        match selected_provider().as_str() {
            "hs256-dev" => Ok(Self::Hs256Dev(Arc::new(crate::load_hs256_key(
                &config_dir.join("dev-key"),
            )?))),
            "tpm" => {
                #[cfg(feature = "tpm")]
                {
                    Ok(Self::Tpm(Arc::new(tpm::TpmProvider::new()?)))
                }

                #[cfg(not(feature = "tpm"))]
                bail!(
                    "TANA_VAULT_AGENT_ATTESTATION=tpm requires building gild-vault with --features tpm"
                );
            }
            other => bail!(
                "unsupported TANA_VAULT_AGENT_ATTESTATION={other:?}; expected hs256-dev or tpm"
            ),
        }
    }

    pub fn mint_jwt(&self, workload: &ResolvedWorkload, now: u64) -> Result<String> {
        let claims = VaultClaims {
            sub: workload.identity.clone(),
            scope: format!("vault:read:{}/*", workload.namespace),
            iat: now,
            exp: now + TOKEN_TTL_SECONDS,
        };

        match self {
            Self::Hs256Dev(key) => encode(
                &Header::new(Algorithm::HS256),
                &claims,
                &EncodingKey::from_secret(key),
            )
            .context("mint HS256 JWT"),
            #[cfg(feature = "tpm")]
            Self::Tpm(provider) => provider.mint_jwt(&claims),
        }
    }
}

fn selected_provider() -> String {
    std::env::var("TANA_VAULT_AGENT_ATTESTATION").unwrap_or_else(|_| "hs256-dev".to_string())
}

#[cfg(any(test, feature = "tpm"))]
pub(crate) fn rs256_signing_input(claims: &VaultClaims) -> Result<String> {
    let header = JwtHeader {
        alg: "RS256",
        typ: "JWT",
    };
    Ok(format!(
        "{}.{}",
        base64_json(&header).context("encode JWT header")?,
        base64_json(claims).context("encode JWT claims")?
    ))
}

#[cfg(feature = "tpm")]
pub(crate) fn rs256_jwt_from_signature(signing_input: &str, signature: &[u8]) -> String {
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

#[cfg(test)]
pub(crate) fn sha256_digest(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

#[cfg(any(test, feature = "tpm"))]
fn base64_json<T: Serialize>(value: &T) -> Result<String> {
    let json = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(json))
}

#[cfg(any(test, feature = "tpm"))]
#[derive(Serialize)]
struct JwtHeader {
    alg: &'static str,
    typ: &'static str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn builds_rs256_signing_input() {
        let claims = VaultClaims {
            sub: "prod/deka.gg".to_string(),
            scope: "vault:read:prod/deka.gg/*".to_string(),
            iat: 1,
            exp: 2,
        };

        let signing_input = rs256_signing_input(&claims).expect("signing input");
        let header = signing_input.split('.').next().expect("header segment");
        let decoded = URL_SAFE_NO_PAD.decode(header).expect("decode header");

        assert_eq!(decoded, br#"{"alg":"RS256","typ":"JWT"}"#);
    }

    #[test]
    fn computes_sha256_digest_for_tpm_signing() {
        let digest = sha256_digest(b"abc");
        assert_eq!(
            hex(&digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
