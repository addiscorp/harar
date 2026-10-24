//! `harar token` and `harar policy`: identity tokens from the primary, and the
//! rules it decides by (architecture, §3–4).

use crate::cli::{SocketArgs, print_json};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::model::{Action, Binding, Name, NamePattern, Permission, Profile, Role, Verb, Zone, ZoneKind, ZoneMatch};
use harar_client::oidc::{Alg, TokenAsk};
use harar_client::primary::PolicyChange;

/// Get an identity token for this process's actor.
///
/// Who you are comes from the OS user calling harar's socket, never from a
/// flag. Tokens last 5 minutes unless --ttl says otherwise, and never more
/// than an hour.
#[derive(Debug, Args)]
pub struct Token {
    #[command(flatten)]
    socket: SocketArgs,
    /// The service the token is for, such as https://api.simien.dev.
    #[arg(long = "aud")]
    audience: String,
    /// A scope to ask for (may repeat).
    #[arg(long = "scope")]
    scopes: Vec<String>,
    /// How long it lasts: 300, 300s, 5m or 1h.
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<u64>,
    /// ES256 (default; what most clouds accept) or EdDSA.
    #[arg(long, value_parser = parse_alg)]
    alg: Option<Alg>,
    /// Print only the token, for `Authorization: Bearer $(harar token …)`.
    #[arg(long)]
    raw: bool,
}

pub async fn token(cmd: Token) -> Result<()> {
    let ask = TokenAsk { audience: cmd.audience, scopes: cmd.scopes, ttl_seconds: cmd.ttl, act: None, alg: cmd.alg };
    let (token, claims) = VaultClient::from_socket_path(cmd.socket.socket).token(&ask).await?;
    if cmd.raw {
        println!("{token}");
        Ok(())
    } else {
        print_json(&serde_json::json!({ "token": token, "claims": claims }))
    }
}

/// The primary's policy: roles, bindings, zones, profiles, and which OS users
/// on its machine speak as which actors.
#[derive(Debug, Args)]
pub struct PolicyCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: PolicyAction,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    Show,
    /// What ACTOR (default: you) would be allowed, without doing it.
    Test {
        #[arg(long)]
        actor: Option<Name>,
        #[command(flatten)]
        action: OneAction,
    },
    #[command(subcommand)]
    Role(RoleAction),
    /// Give ACTOR (a name, or a pattern ending in *) a role in some zones.
    Bind(BindArgs),
    /// Take a binding away.
    Unbind(BindArgs),
    #[command(subcommand)]
    Zone(ZoneAction),
    #[command(subcommand)]
    Profile(ProfileAction),
    #[command(subcommand)]
    User(UserAction),
}

#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
struct OneAction {
    #[arg(long)]
    read: Option<String>,
    #[arg(long)]
    write: Option<String>,
    /// "AUDIENCE SCOPE…", e.g. "https://api.simien.dev deploy:site".
    #[arg(long)]
    token: Option<String>,
    #[arg(long)]
    launch: Option<Name>,
    #[arg(long)]
    approve: Option<String>,
}

#[derive(Debug, Subcommand)]
enum RoleAction {
    /// Create or replace a role. Each flag may repeat.
    Set {
        name: Name,
        #[arg(long)]
        read: Vec<String>,
        #[arg(long)]
        write: Vec<String>,
        /// "AUDIENCE SCOPE…", e.g. "https://api.simien.dev deploy:*".
        #[arg(long)]
        token: Vec<String>,
        #[arg(long)]
        launch: Vec<String>,
        #[arg(long)]
        approve: Vec<String>,
    },
    Remove { name: Name },
}

#[derive(Debug, Args)]
struct BindArgs {
    actor: NamePattern,
    #[arg(long)]
    role: Name,
    /// Zones by name (or a pattern ending in *): machines and services.
    #[arg(long, conflicts_with = "profile", required_unless_present = "profile")]
    zone: Option<NamePattern>,
    /// Zones a broker launched with this profile.
    #[arg(long)]
    profile: Option<Name>,
}

#[derive(Debug, Subcommand)]
enum ZoneAction {
    /// Register a machine or a service on one.
    Add {
        name: Name,
        #[arg(long, value_parser = parse_zone_kind)]
        kind: ZoneKind,
        #[arg(long)]
        parent: Option<Name>,
        /// The broker that vouches for it.
        #[arg(long)]
        broker: Option<Name>,
    },
    /// Revoke a zone and every zone under it, at once.
    Revoke { name: Name },
}

#[derive(Debug, Subcommand)]
enum ProfileAction {
    /// What kind of zone a broker may launch, and for how long.
    Set {
        name: Name,
        #[arg(long = "kind", value_parser = parse_zone_kind, required = true)]
        kinds: Vec<ZoneKind>,
        #[arg(long, value_parser = parse_duration)]
        max: u64,
    },
    Remove { name: Name },
}

#[derive(Debug, Subcommand)]
enum UserAction {
    /// Let the OS user USER on the primary's machine speak as ACTOR.
    Map { user: String, actor: Name },
    Unmap { user: String },
}

fn one_action(action: OneAction) -> Result<Action> {
    if let Some(path) = action.read {
        return Ok(Action::Read { path });
    }
    if let Some(path) = action.write {
        return Ok(Action::Write { path });
    }
    if let Some(token) = action.token {
        let (audience, scopes) = audience_and_scopes(&token);
        return Ok(Action::Token { audience, scopes });
    }
    if let Some(profile) = action.launch {
        return Ok(Action::Launch { profile });
    }
    action.approve.map(|class| Action::Approve { class }).ok_or_else(|| anyhow!("say what to test"))
}

fn audience_and_scopes(value: &str) -> (String, Vec<String>) {
    let mut parts = value.split_whitespace();
    let audience = parts.next().unwrap_or_default().to_string();
    (audience, parts.map(str::to_string).collect())
}

fn binding(args: BindArgs) -> Binding {
    let zone = match (args.zone, args.profile) {
        (_, Some(profile)) => ZoneMatch::Profile(profile),
        (Some(zone), None) => ZoneMatch::Name(zone),
        (None, None) => unreachable!("clap requires --zone or --profile"),
    };
    Binding { actor: args.actor, zone, role: args.role }
}

pub async fn policy(cmd: PolicyCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let change = match cmd.action {
        PolicyAction::Show => return print_json(&client.policy_show().await?),
        PolicyAction::Test { actor, action } => {
            let decision = client.decide(actor, one_action(action)?).await?;
            return print_json(&serde_json::json!({ "decision": decision }));
        }
        PolicyAction::Role(RoleAction::Set { name, read, write, token, launch, approve }) => {
            let plain = |verb, resources: Vec<String>| resources.into_iter().map(move |resource| Permission { verb, resource, scopes: vec![] });
            let mut allows: Vec<Permission> = plain(Verb::Read, read).chain(plain(Verb::Write, write)).chain(plain(Verb::Launch, launch)).chain(plain(Verb::Approve, approve)).collect();
            allows.extend(token.iter().map(|value| {
                let (resource, scopes) = audience_and_scopes(value);
                Permission { verb: Verb::Token, resource, scopes }
            }));
            PolicyChange::SetRole { role: Role { name, allows } }
        }
        PolicyAction::Role(RoleAction::Remove { name }) => PolicyChange::RemoveRole { name },
        PolicyAction::Bind(args) => PolicyChange::Bind { binding: binding(args) },
        PolicyAction::Unbind(args) => PolicyChange::Unbind { binding: binding(args) },
        PolicyAction::Zone(ZoneAction::Add { name, kind, parent, broker }) => PolicyChange::AddZone {
            zone: Zone { name, kind, parent, broker, profile: None, created_at: crate::common::now_epoch_seconds(), expires_at: None, revoked: false },
        },
        PolicyAction::Zone(ZoneAction::Revoke { name }) => PolicyChange::RevokeZone { name },
        PolicyAction::Profile(ProfileAction::Set { name, kinds, max }) => PolicyChange::SetProfile { profile: Profile { name, kinds, max_seconds: max } },
        PolicyAction::Profile(ProfileAction::Remove { name }) => PolicyChange::RemoveProfile { name },
        PolicyAction::User(UserAction::Map { user, actor }) => PolicyChange::MapUser { user, actor },
        PolicyAction::User(UserAction::Unmap { user }) => PolicyChange::UnmapUser { user },
    };
    client.policy_change(&change).await?;
    print_json(&serde_json::json!({ "ok": true }))
}

pub(crate) fn parse_duration(value: &str) -> Result<u64> {
    let (digits, unit) = match value.find(|c: char| !c.is_ascii_digit()) {
        Some(at) => value.split_at(at),
        None => (value, "s"),
    };
    let amount: u64 = digits.parse().map_err(|_| anyhow!("expected a duration like 300, 5m or 1h"))?;
    let scale = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return Err(anyhow!("expected a duration like 300, 5m or 1h")),
    };
    amount.checked_mul(scale).ok_or_else(|| anyhow!("duration is too long"))
}

fn parse_alg(value: &str) -> Result<Alg> {
    Alg::parse(value).ok_or_else(|| anyhow!("expected ES256 or EdDSA"))
}

fn parse_zone_kind(value: &str) -> Result<ZoneKind> {
    serde_json::from_value(serde_json::Value::String(value.into())).map_err(|_| anyhow!("expected machine, vm, container, sandbox, service or run"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_read_like_people_write_them() {
        assert_eq!(parse_duration("300").unwrap(), 300);
        assert_eq!(parse_duration("45s").unwrap(), 45);
        assert_eq!(parse_duration("5m").unwrap(), 300);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        for bad in ["", "m", "5d", "1.5h", "-5m"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_token_permission_is_an_audience_then_scopes() {
        assert_eq!(audience_and_scopes("https://api.simien.dev deploy:site deploy:docs"), ("https://api.simien.dev".into(), vec!["deploy:site".into(), "deploy:docs".into()]));
        assert_eq!(parse_zone_kind("vm").unwrap(), ZoneKind::Vm);
        assert!(parse_zone_kind("toaster").is_err());
    }
}
