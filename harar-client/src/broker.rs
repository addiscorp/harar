//! The egress broker's shared shapes. An agent in a VM holds only a
//! placeholder; the broker, outside the VM, asks the vault what the
//! placeholder stands for on every request and adds the real credential on the
//! way out.

use sha2::{Digest, Sha256};

/// Placeholders start with this, so they're easy to spot in logs and env.
pub const PLACEHOLDER_PREFIX: &str = "harar-ph-";

/// A service the broker can reach for agents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrokerService {
    pub name: String,
    /// Where requests go, such as https://api.anthropic.com. The agent only
    /// chooses the path under it.
    pub upstream: String,
    /// The header the credential travels in, such as `x-api-key`.
    pub header: String,
    /// Whether the header holds `Bearer <value>` or the bare value.
    #[serde(default)]
    pub bearer: bool,
    /// The vault key holding the real credential.
    pub secret: String,
}

/// Lets sessions whose subject matches `to` use `service`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrokerGrant {
    pub service: String,
    pub to: String,
}

/// A placeholder, kept only as its hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Placeholder {
    pub sid: String,
    pub service: String,
    pub created_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
}

/// An agent asking for a service it wasn't granted.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AccessRequest {
    pub id: String,
    pub sid: String,
    pub sub: String,
    pub service: String,
    pub reason: String,
    pub created_at: u64,
    pub status: RequestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_until: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BrokerState {
    #[serde(default)]
    pub services: Vec<BrokerService>,
    #[serde(default)]
    pub grants: Vec<BrokerGrant>,
    /// Workloads allowed to resolve placeholders: the brokers themselves.
    #[serde(default)]
    pub brokers: Vec<String>,
    /// By placeholder hash.
    #[serde(default)]
    pub placeholders: std::collections::BTreeMap<String, Placeholder>,
    #[serde(default)]
    pub requests: std::collections::BTreeMap<String, AccessRequest>,
}

/// What the vault tells a broker a placeholder stands for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Resolved {
    pub sid: String,
    pub sub: String,
    pub upstream: String,
    pub header: String,
    pub bearer: bool,
    pub value: String,
}

pub fn placeholder_hash(placeholder: &str) -> String {
    Sha256::digest(placeholder.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn new_placeholder() -> String {
    crate::random_id(PLACEHOLDER_PREFIX)
}
