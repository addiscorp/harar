//! What a client says to a harar primary over its local socket, and what it
//! hears back. Secret reads and writes use the same `get`/`put`/`list`/
//! `delete` shape as the per-user agent, so one client speaks to both.

use crate::approvals::{Approval, ApprovalRequest, ApproverDevice};
use crate::model::{Action, Binding, Name, Policy, Profile, Role, Zone};
use crate::oidc::{IdentityClaims, TokenAsk};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PrimaryRequest {
    Get { key: String },
    Put { key: String, value: String },
    Delete { key: String },
    /// The secret paths the caller may read.
    List,
    /// The hosts the caller may send `key` to (patterns, `*.` for any name
    /// under one): what a station opens for that secret.
    Hosts { key: String },
    /// The value of `key`, to put into a request for `host` only: allowed by
    /// a `send` permission, without `read`, and recorded with the host.
    Send { key: String, host: String },
    /// The per-user agent's own list of where a secret may go. A primary
    /// refuses them: there, a host is a role's `send` permission.
    AllowHost { key: String, host: String },
    RevokeHost { key: String, host: String },
    /// An identity token for the calling actor.
    Token(TokenAsk),
    Health,
    /// The policy and which OS users speak as which actors.
    PolicyShow,
    PolicyChange { change: PolicyChange },
    /// A dry run of the request rule: would `actor` (the caller if absent),
    /// in this primary's machine zone, be allowed `action`?
    Decide {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor: Option<Name>,
        action: Action,
    },
    /// The requests waiting for a person, and the approver devices.
    Approvals,
    /// A person's decision on a waiting request, signed by one of their devices.
    Submit { approval: Approval },
    /// Enrolls an approver device for the calling human. The primary sets its
    /// id, owner and enrollment time; a human's first device is enrolled at
    /// once, another one waits for an approval from a device they already have.
    AddDevice { device: ApproverDevice },
    /// Asks to revoke one of the calling human's devices: a reserved
    /// `device.remove` request one of their own devices approves (never the
    /// OS account alone), refused if it would leave no device that could
    /// approve a widening (then recovery codes are the way back).
    RemoveDevice { id: String },
    /// Enrolls a new Mac key for the calling human with one of their
    /// recovery codes, when they have no device left (architecture, §6). The
    /// code is used up; the device may approve reserved classes only after a
    /// day.
    Recover { code: String, device: ApproverDevice },
    /// Asks for a new set of recovery codes for the calling human, replacing
    /// the old one: a reserved `recovery.codes` change their own device
    /// approves, and the approval returns the codes.
    NewRecoveryCodes,
}

/// What a waiting request would do once approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "waiting", rename_all = "snake_case")]
pub enum Waiting {
    Policy { change: PolicyChange },
    Device { device: ApproverDevice },
    /// A new set of recovery codes for `human`.
    RecoveryCodes { human: crate::model::Name },
    /// Revoke `human`'s approver device `id`.
    RemoveDevice { id: String, human: crate::model::Name },
}

/// SHA-256 (hex) of exactly what a waiting request would do: its
/// `ApprovalRequest::detail`, signed with it. The primary sets it; a device
/// recomputes it from what it shows the person before signing.
pub fn waiting_detail(waiting: &Waiting) -> String {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(waiting).expect("a waiting change serializes");
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// A request waiting for a person, as the primary shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    /// What a device signs over (`ApprovalRequest::challenge`).
    pub request: ApprovalRequest,
    pub waiting: Waiting,
    /// One line for a person: who asks, from where, for exactly what.
    pub description: String,
}

/// One change to the policy. Narrowing changes apply at once; widening ones
/// need the right to widen (and, once approver devices exist, an approval).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum PolicyChange {
    SetRole { role: Role },
    RemoveRole { name: Name },
    Bind { binding: Binding },
    Unbind { binding: Binding },
    SetProfile { profile: Profile },
    RemoveProfile { name: Name },
    AddZone { zone: Zone },
    RevokeZone { name: Name },
    /// Lets the OS user `user` on this machine speak as `actor`.
    MapUser { user: String, actor: Name },
    UnmapUser { user: String },
}

impl PolicyChange {
    /// Whether the change can only take away. Those never wait.
    pub fn narrows(&self) -> bool {
        matches!(
            self,
            PolicyChange::RemoveRole { .. }
                | PolicyChange::Unbind { .. }
                | PolicyChange::RemoveProfile { .. }
                | PolicyChange::RevokeZone { .. }
                | PolicyChange::UnmapUser { .. }
        )
    }
}

/// The policy as the primary shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyView {
    pub policy: Policy,
    /// OS user on the primary's machine → the actor it speaks as.
    pub users: BTreeMap<String, Name>,
    /// The primary's own machine zone and broker.
    pub zone: Name,
    pub broker: Name,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrimaryResponse {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keys: Option<Vec<String>>,
    /// For `hosts`: where the secret may go.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claims: Option<IdentityClaims>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyView>,
    /// For `decide`: `allow by <role>` or the reason it was refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// A change that now waits for a person instead of applying.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<Pending>,
    /// For `approvals`: what waits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approvals: Option<Vec<Pending>>,
    /// For `approvals` and `add_device`: the approver devices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<ApproverDevice>>,
    /// One-time recovery codes, shown once: for a person's first device, and
    /// for an approved new set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes: Option<Vec<String>>,
    /// For `approvals`: what happened to the caller's own account lately (a
    /// device recovered with a code, codes replaced), and how many of their
    /// recovery codes are left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notices: Option<Vec<Notice>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_codes_left: Option<usize>,
}

/// Something a person should know about their own account, kept a week.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    pub human: crate::model::Name,
    pub at: u64,
    pub text: String,
}

impl PrimaryResponse {
    pub fn ok() -> PrimaryResponse {
        PrimaryResponse { ok: true, ..PrimaryResponse::default() }
    }

    pub fn error(error: impl Into<String>) -> PrimaryResponse {
        PrimaryResponse { ok: false, error: Some(error.into()), ..PrimaryResponse::default() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_requests_keep_the_agent_shape() {
        let get: PrimaryRequest = serde_json::from_str(r#"{"op":"get","key":"prod/a"}"#).unwrap();
        assert_eq!(get, PrimaryRequest::Get { key: "prod/a".into() });
        assert_eq!(serde_json::to_string(&PrimaryRequest::List).unwrap(), r#"{"op":"list"}"#);
        let token: PrimaryRequest = serde_json::from_str(r#"{"op":"token","audience":"https://api.simien.dev","scopes":["deploy:site"]}"#).unwrap();
        assert!(matches!(token, PrimaryRequest::Token(ask) if ask.audience == "https://api.simien.dev"));
    }

    #[test]
    fn changes_say_whether_they_only_take_away() {
        let user = PolicyChange::UnmapUser { user: "site".into() };
        assert!(user.narrows());
        let map = PolicyChange::MapUser { user: "site".into(), actor: "gg.addis.service.site".parse().unwrap() };
        assert!(!map.narrows());
        let json = serde_json::to_string(&PrimaryRequest::PolicyChange { change: map.clone() }).unwrap();
        assert_eq!(serde_json::from_str::<PrimaryRequest>(&json).unwrap(), PrimaryRequest::PolicyChange { change: map });
    }
}
