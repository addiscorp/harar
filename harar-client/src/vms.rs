//! VMs a host runs for agents and CI (scenario S2 A). The host registers each
//! VM's vsock CID with what it runs for; a VM asks the host over vsock, and
//! the kernel says which CID is asking, so no VM can speak for another.

/// What a VM runs for.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VmFor {
    /// An agent's session: tokens act for it, within its reach.
    Session(String),
    /// A CI run: its env secrets and deploy tokens.
    Run(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Vm {
    /// `vm:<name>`.
    pub id: String,
    pub cid: u32,
    /// The workload that registered it, which runs the vsock service.
    pub host_workload: String,
    pub runs_for: VmFor,
    pub created_at: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VmsState {
    /// By `<host workload>/<cid>`: CIDs are only unique on one host.
    #[serde(default)]
    pub vms: std::collections::BTreeMap<String, Vm>,
}

/// The default vsock port of `harar vm serve`.
pub const DEFAULT_PORT: u32 = 1024;

/// One request from inside a VM, one line of JSON.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum VmRequest {
    Token(crate::oidc::TokenAsk),
    Secrets { env: String },
}
