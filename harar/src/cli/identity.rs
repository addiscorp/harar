//! `harar token`, `harar workload` and `harar policy`: asking the issuer for
//! identity tokens, and the rules it decides by.

use crate::cli::{SocketArgs, print_json};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::oidc::{Actor, Alg, Grant, TokenAsk, Workload};

/// Get an identity token for this process's workload.
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
    /// Act for this subject, such as agent:ava.
    #[arg(long)]
    act: Option<String>,
    /// The session of the subject in --act.
    #[arg(long, requires = "act")]
    session: Option<String>,
    /// ES256 (default; what most clouds accept) or EdDSA.
    #[arg(long, value_parser = parse_alg)]
    alg: Option<Alg>,
    /// Print only the token, for `Authorization: Bearer $(harar token …)`.
    #[arg(long)]
    raw: bool,
}

pub async fn token(cmd: Token) -> Result<()> {
    let ask = TokenAsk {
        audience: cmd.audience,
        scopes: cmd.scopes,
        ttl_seconds: cmd.ttl,
        act: cmd.act.map(|sub| Actor { sub, sid: cmd.session, act: None }),
        alg: cmd.alg,
    };
    let (token, claims) = VaultClient::from_socket_path(cmd.socket.socket).token(&ask).await?;
    if cmd.raw {
        println!("{token}");
        Ok(())
    } else {
        print_json(&serde_json::json!({ "token": token, "claims": claims }))
    }
}

/// The OS users that speak as workloads.
#[derive(Debug, Args)]
pub struct WorkloadCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: WorkloadAction,
}

#[derive(Debug, Subcommand)]
enum WorkloadAction {
    /// Let an OS user on this host speak as SUB, such as svc:gild@demon.
    Add {
        sub: String,
        #[arg(long)]
        user: String,
    },
    /// Remove a workload and everything granted to it.
    Remove { sub: String },
    List,
}

pub async fn workload(cmd: WorkloadCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let policy = match cmd.action {
        WorkloadAction::Add { sub, user } => client.workload_add(&Workload { sub, user }).await?,
        WorkloadAction::Remove { sub } => client.workload_remove(&sub).await?,
        WorkloadAction::List => client.identity().await?,
    };
    print_json(&policy.workloads)
}

/// What each workload may ask the issuer for.
#[derive(Debug, Args)]
pub struct PolicyCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: PolicyAction,
}

#[derive(Debug, Subcommand)]
enum PolicyAction {
    /// Let SUB ask AUD for these scopes, optionally acting for others.
    /// Scopes and subjects are exact, or a prefix ending in `*`.
    Allow {
        sub: String,
        #[arg(long = "aud")]
        audience: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long = "may-act-for")]
        may_act_for: Vec<String>,
    },
    /// Remove everything SUB may ask of AUD.
    Remove {
        sub: String,
        #[arg(long = "aud")]
        audience: String,
    },
    List,
    /// What the OS user USER would get for this request, without issuing it.
    Test {
        user: String,
        #[arg(long = "aud")]
        audience: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long)]
        act: Option<String>,
    },
}

pub async fn policy(cmd: PolicyCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    match cmd.action {
        PolicyAction::Allow { sub, audience, scopes, may_act_for } => {
            let policy = client.grant(&Grant { sub, audience, scopes, may_act_for }).await?;
            print_json(&policy.grants)
        }
        PolicyAction::Remove { sub, audience } => print_json(&client.ungrant(&sub, &audience).await?.grants),
        PolicyAction::List => print_json(&client.identity().await?),
        PolicyAction::Test { user, audience, scopes, act } => {
            let policy = client.identity().await?;
            let ask = TokenAsk {
                audience,
                scopes,
                ttl_seconds: None,
                act: act.map(|sub| Actor { sub, sid: None, act: None }),
                alg: None,
            };
            match crate::identity::decide(&policy, &user, &ask) {
                Ok(request) => print_json(&serde_json::json!({
                    "allowed": true,
                    "sub": request.sub,
                    "aud": request.aud,
                    "scope": request.scopes.join(" "),
                    "ttl_seconds": request.ttl_seconds,
                })),
                Err(reason) => print_json(&serde_json::json!({ "allowed": false, "reason": reason })),
            }
        }
    }
}

fn parse_duration(value: &str) -> Result<u64> {
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
}
