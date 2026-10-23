//! `harar host`: joining the fleet with a hardware key, approving hosts, and
//! getting tokens on an enrolled host.

use crate::cli::identity::parse_duration;
use crate::cli::{SocketArgs, print_json};
use crate::host_key::HostKey;
use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::hosts::{ENROLL_PATH, EnrollAsk, HostAssertion, MAX_ASSERTION_SECONDS, TOKEN_PATH};
use harar_client::oidc::{Actor, Alg, TokenAsk};
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct HostCmd {
    #[command(subcommand)]
    action: HostAction,
}

#[derive(Debug, Subcommand)]
enum HostAction {
    /// On a new host: make its key and ask the issuer to enroll it. Shows a
    /// code to read to whoever approves.
    Enroll {
        name: String,
        /// The issuer's URL, such as https://id.simien.dev.
        #[arg(long)]
        issuer: String,
        #[arg(long, default_value_os_t = crate::host_key::default_path())]
        key_file: PathBuf,
        /// Use a key file even where a Secure Enclave exists.
        #[arg(long)]
        software: bool,
    },
    /// On an enrolled host: a token for one of its workloads.
    Token {
        #[arg(long)]
        issuer: String,
        /// The workload, such as svc:gild@bugsy.
        #[arg(long = "as")]
        sub: String,
        #[arg(long = "aud")]
        audience: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long, value_parser = parse_duration)]
        ttl: Option<u64>,
        #[arg(long)]
        act: Option<String>,
        #[arg(long, requires = "act")]
        session: Option<String>,
        #[arg(long)]
        raw: bool,
        #[arg(long, default_value_os_t = crate::host_key::default_path())]
        key_file: PathBuf,
    },
    /// On the issuer: enroll NAME if CODE is what its screen shows.
    Approve {
        name: String,
        #[arg(long)]
        code: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// On the issuer: drop a pending enrollment.
    Reject {
        name: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// On the issuer: forget an enrolled host; its assertions stop working.
    Remove {
        name: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    List {
        #[command(flatten)]
        socket: SocketArgs,
    },
}

pub async fn host(cmd: HostCmd) -> Result<()> {
    match cmd.action {
        HostAction::Enroll { name, issuer, key_file, software } => enroll(name, issuer, key_file, software).await,
        HostAction::Token { issuer, sub, audience, scopes, ttl, act, session, raw, key_file } => {
            let ask = TokenAsk {
                audience,
                scopes,
                ttl_seconds: ttl,
                act: act.map(|sub| Actor { sub, sid: session, act: None }),
                alg: Some(Alg::ES256),
            };
            let reply = token(&issuer, &key_file, sub, ask).await?;
            if raw {
                println!("{}", reply["token"].as_str().unwrap_or_default());
                Ok(())
            } else {
                print_json(&reply)
            }
        }
        HostAction::Approve { name, code, socket } => {
            let hosts = VaultClient::from_socket_path(socket.socket).host_approve(&name, &code).await?;
            print_json(&hosts.hosts[&name])
        }
        HostAction::Reject { name, socket } => print_json(&VaultClient::from_socket_path(socket.socket).host_reject(&name).await?),
        HostAction::Remove { name, socket } => print_json(&VaultClient::from_socket_path(socket.socket).host_remove(&name).await?),
        HostAction::List { socket } => print_json(&VaultClient::from_socket_path(socket.socket).hosts().await?),
    }
}

async fn enroll(name: String, issuer: String, key_file: PathBuf, software: bool) -> Result<()> {
    let key = HostKey::create(software)?;
    key.save(&key_file, &name)?;
    let ask = EnrollAsk { name: name.clone(), jwk: key.jwk(&name)?, tier: key.tier() };
    let reply = match post(&issuer, ENROLL_PATH, &serde_json::to_value(&ask)?).await {
        Ok(reply) => reply,
        Err(err) => {
            // Nothing was enrolled, so the key is no use to anyone.
            let _ = std::fs::remove_file(&key_file);
            return Err(err);
        }
    };
    let code = reply["code"].as_str().ok_or_else(|| anyhow!("the issuer sent no code"))?;
    eprintln!("Approve on the issuer with: harar host approve {name} --code {code}");
    print_json(&serde_json::json!({ "name": name, "code": code, "tier": key.tier(), "key_file": key_file }))
}

async fn token(issuer: &str, key_file: &std::path::Path, sub: String, ask: TokenAsk) -> Result<serde_json::Value> {
    let (key, name) = HostKey::load(key_file)?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let assertion = HostAssertion {
        iss: format!("host:{name}"),
        sub,
        aud: issuer.trim_end_matches('/').to_string(),
        iat: now,
        exp: now + MAX_ASSERTION_SECONDS / 2,
        jti: harar_client::random_id("a_"),
        ask,
    };
    let signed = key.assert(&name, &assertion)?;
    post(issuer, TOKEN_PATH, &serde_json::json!({ "assertion": signed })).await
}

async fn post(issuer: &str, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let url = format!("{}{path}", issuer.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(&url)
        .json(body)
        .timeout(std::time::Duration::from_secs(30))
        .send()
        .await
        .with_context(|| format!("reach {url}"))?;
    let status = response.status();
    let reply: serde_json::Value = response.json().await.with_context(|| format!("read the reply from {url}"))?;
    if !status.is_success() {
        let reason = reply["error"].as_str().unwrap_or("refused");
        return Err(anyhow!("{url}: {reason}"));
    }
    Ok(reply)
}
