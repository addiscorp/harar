//! What a client says to a harar primary over its local socket, and what it
//! hears back. Secret reads and writes use the same `get`/`put`/`list`/
//! `delete` shape as the per-user agent, so one client speaks to both.

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
