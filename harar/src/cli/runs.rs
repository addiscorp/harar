//! `harar env` and `harar runs`: which CI runs may build for an environment,
//! and the runs a gild host registers.

use crate::cli::identity::parse_duration;
use crate::cli::secret_input::SecretInput;
use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::runs::{EnvRule, RunFacts, RunRegisterAsk};

/// Environments and the rules for which runs may use them.
#[derive(Debug, Args)]
pub struct EnvCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: EnvAction,
}

#[derive(Debug, Subcommand)]
enum EnvAction {
    /// Say which runs may build for NAME. Patterns are exact or end in `*`.
    Rule {
        name: String,
        #[arg(long)]
        repo: String,
        #[arg(long = "ref")]
        git_ref: String,
        #[arg(long)]
        workflow: String,
        /// Vault keys the build gets, such as 'prod/site/*' (may repeat).
        #[arg(long = "secrets")]
        secrets: Vec<String>,
        /// Services the run may get tokens for (may repeat).
        #[arg(long = "aud")]
        audiences: Vec<String>,
        /// Runs started by an agent wait for `harar approvals approve`.
        #[arg(long)]
        approve_when_agent: bool,
    },
    Remove { name: String },
    List,
}

pub async fn env(cmd: EnvCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let state = match cmd.action {
        EnvAction::Rule { name, repo, git_ref, workflow, secrets, audiences, approve_when_agent } => {
            let rule = EnvRule { name, repo, git_ref, workflow, secrets, audiences, approve_when_agent };
            client.env_rule(&rule).await?
        }
        EnvAction::Remove { name } => client.env_rule_remove(&name).await?,
        EnvAction::List => client.runs().await?,
    };
    print_json(&state.rules)
}

/// CI runs: registered by the host that runs them.
#[derive(Debug, Args)]
pub struct RunsCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: RunsAction,
}

#[derive(Debug, Subcommand)]
enum RunsAction {
    /// Register a run's facts. Prints the run and its run token, which goes
    /// into the run's VM.
    Register {
        #[arg(long)]
        repo: String,
        #[arg(long)]
        sha: String,
        #[arg(long = "ref")]
        git_ref: String,
        #[arg(long)]
        workflow: String,
        #[arg(long)]
        env: String,
        /// Who started it, such as agent:ava.
        #[arg(long)]
        actor: String,
        /// Whom the actor works for, such as user:sami.
        #[arg(long = "for")]
        for_sub: Option<String>,
        /// How long it may run (default 1h, at most 6h).
        #[arg(long, value_parser = parse_duration)]
        ttl: Option<u64>,
    },
    /// From inside a run: a token for AUD carrying the run's facts.
    Token {
        #[command(flatten)]
        run_token: SecretInput,
        #[arg(long = "aud")]
        audience: String,
        #[arg(long)]
        raw: bool,
    },
    Finish { id: String },
    List,
}

pub async fn runs(cmd: RunsCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    match cmd.action {
        RunsAction::Register { repo, sha, git_ref, workflow, env, actor, for_sub, ttl } => {
            let facts = RunFacts { repo, sha, git_ref, workflow, env, actor, for_sub };
            let (run, token) = client.run_register(&RunRegisterAsk { facts, ttl_seconds: ttl }).await?;
            print_json(&serde_json::json!({ "run": run, "run_token": token }))
        }
        RunsAction::Token { run_token, audience, raw } => {
            let (token, claims) = client.run_token(&run_token.read("Run token")?, &audience).await?;
            if raw {
                println!("{token}");
                Ok(())
            } else {
                print_json(&serde_json::json!({ "token": token, "claims": claims }))
            }
        }
        RunsAction::Finish { id } => print_json(&client.run_finish(&id).await?),
        RunsAction::List => print_json(&client.runs().await?.runs.values().collect::<Vec<_>>()),
    }
}
