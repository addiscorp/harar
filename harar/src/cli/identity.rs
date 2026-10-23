//! `harar token`, `harar workload` and `harar policy`: asking the issuer for
//! identity tokens, and the rules it decides by.

use crate::cli::secret_input::SecretInput;
use crate::cli::{SocketArgs, print_json};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::oidc::{Actor, Alg, ExchangeAsk, Grant, SessionGrant, SessionStartAsk, TokenAsk, Workload};

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
        /// Subjects it may start sessions for, such as 'agent:*' (may repeat).
        #[arg(long = "sessions-for")]
        sessions_for: Vec<String>,
        /// Repos it may register CI runs for, such as 'addiscorp/*' (may repeat).
        #[arg(long = "runs-for")]
        runs_for: Vec<String>,
    },
    /// Remove a workload and everything granted to it.
    Remove { sub: String },
    List,
}

pub async fn workload(cmd: WorkloadCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let policy = match cmd.action {
        WorkloadAction::Add { sub, user, sessions_for, runs_for } => {
            client.workload_add(&Workload { sub, user, sessions_for, runs_for }).await?
        }
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

/// Agent sessions: started by a workload, narrowed by `harar exchange`, and
/// revoked together with everything under them.
#[derive(Debug, Args)]
pub struct SessionCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: SessionAction,
}

#[derive(Debug, Subcommand)]
enum SessionAction {
    /// Start a session for SUB, such as agent:ava. Prints it and its session
    /// token, which the agent keeps.
    Start {
        sub: String,
        /// Who the agent works for, such as user:sami.
        #[arg(long = "for")]
        for_sub: Option<String>,
        /// How long it lasts (default 8h, at most 24h).
        #[arg(long, value_parser = parse_duration)]
        ttl: Option<u64>,
        /// What it may reach: AUDIENCE=scope,scope (may repeat).
        #[arg(long = "grant", value_parser = parse_session_grant)]
        grants: Vec<SessionGrant>,
    },
    /// A fresh session token, given the current one.
    Refresh {
        #[command(flatten)]
        token: SecretInput,
    },
    /// End a session and every session under it.
    Revoke { sid: String },
    /// The sessions you started.
    List,
    /// A session and everything under it.
    Tree { sid: String },
}

pub async fn session(cmd: SessionCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    match cmd.action {
        SessionAction::Start { sub, for_sub, ttl, grants } => {
            let ask = SessionStartAsk { sub, for_sub, ttl_seconds: ttl, grants };
            let (session, token) = client.session_start(&ask).await?;
            print_json(&serde_json::json!({ "session": session, "session_token": token }))
        }
        SessionAction::Refresh { token } => {
            let (session, token) = client.session_refresh(&token.read("Session token")?).await?;
            print_json(&serde_json::json!({ "session": session, "session_token": token }))
        }
        SessionAction::Revoke { sid } => print_json(&client.session_revoke(&sid).await?),
        SessionAction::List => print_json(&client.sessions(None).await?),
        SessionAction::Tree { sid } => print_json(&client.sessions(Some(&sid)).await?),
    }
}

/// Trade your session token for a narrower child: a child session, and a
/// token for one audience with fewer scopes, ending no later than yours.
#[derive(Debug, Args)]
pub struct Exchange {
    #[command(flatten)]
    socket: SocketArgs,
    /// Your session token.
    #[command(flatten)]
    token: SecretInput,
    /// The child's name; it becomes <your subject>/<name>.
    #[arg(long)]
    name: String,
    #[arg(long = "aud")]
    audience: String,
    #[arg(long = "scope")]
    scopes: Vec<String>,
    #[arg(long, value_parser = parse_duration)]
    ttl: Option<u64>,
}

pub async fn exchange(cmd: Exchange) -> Result<()> {
    let ask = ExchangeAsk {
        session_token: cmd.token.read("Session token")?,
        name: cmd.name,
        audience: cmd.audience,
        scopes: cmd.scopes,
        ttl_seconds: cmd.ttl,
    };
    print_json(&VaultClient::from_socket_path(cmd.socket.socket).exchange(&ask).await?)
}

/// `AUDIENCE=scope,scope`. Audiences can contain `=`; scopes can't, so the
/// last one splits them.
fn parse_session_grant(value: &str) -> Result<SessionGrant> {
    let (audience, scopes) = value
        .rsplit_once('=')
        .ok_or_else(|| anyhow!("expected AUDIENCE=scope,scope"))?;
    if audience.is_empty() {
        return Err(anyhow!("expected AUDIENCE=scope,scope"));
    }
    Ok(SessionGrant {
        audience: audience.to_string(),
        scopes: scopes.split(',').filter(|s| !s.is_empty()).map(str::to_string).collect(),
    })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_grants_split_on_the_last_equals() {
        let grant = parse_session_grant("https://x.test/?a=b=deploy:staging,logs:read").unwrap();
        assert_eq!(grant.audience, "https://x.test/?a=b");
        assert_eq!(grant.scopes, ["deploy:staging", "logs:read"]);
        assert_eq!(parse_session_grant("https://x.test=").unwrap().scopes, Vec::<String>::new());
        assert!(parse_session_grant("no-equals").is_err());
        assert!(parse_session_grant("=deploy:x").is_err());
    }

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
