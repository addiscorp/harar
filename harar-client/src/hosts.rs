//! Hosts that join the fleet (scenario S6). A new host makes a hardware key,
//! sends its public half to the issuer and shows a short code; a person with
//! admin rights on the issuer approves it with that code. After that, the
//! host gets tokens for its workloads by signing short assertions.

use crate::Jwk;
use sha2::{Digest, Sha256};

pub const ENROLL_PATH: &str = "/v1/hosts/enroll";
pub const TOKEN_PATH: &str = "/v1/token";
/// How long a host's assertion may live, end to end.
pub const MAX_ASSERTION_SECONDS: u64 = 120;

/// Where a host's key lives. Grants can refuse hosts without hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostTier {
    SecureEnclave,
    /// A key file on disk: for hosts with no Secure Enclave or TPM.
    Software,
}

impl HostTier {
    pub fn is_hardware(self) -> bool {
        self != Self::Software
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EnrollAsk {
    pub name: String,
    pub jwk: Jwk,
    pub tier: HostTier,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingHost {
    pub name: String,
    pub jwk: Jwk,
    pub tier: HostTier,
    pub code: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Host {
    pub name: String,
    pub jwk: Jwk,
    pub tier: HostTier,
    pub approved_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostsState {
    #[serde(default)]
    pub pending: std::collections::BTreeMap<String, PendingHost>,
    #[serde(default)]
    pub hosts: std::collections::BTreeMap<String, Host>,
}

/// What a host signs to ask for a token: who on it is asking, and what for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HostAssertion {
    /// `host:<name>`.
    pub iss: String,
    /// The workload, which must end in `@<name>`.
    pub sub: String,
    /// The issuer's URL.
    pub aud: String,
    pub iat: u64,
    pub exp: u64,
    pub jti: String,
    pub ask: crate::oidc::TokenAsk,
}

/// The code a person compares on both screens: 32 bits of the key's hash,
/// as `XXXX-XXXX`.
pub fn enrollment_code(jwk: &Jwk) -> String {
    let digest = Sha256::digest(format!("{}.{}", jwk.x, jwk.y.as_deref().unwrap_or("")).as_bytes());
    let hex: String = digest[..4].iter().map(|b| format!("{b:02X}")).collect();
    format!("{}-{}", &hex[..4], &hex[4..])
}
