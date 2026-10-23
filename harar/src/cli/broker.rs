//! `harar broker`, `harar request` and `harar approvals`: the egress broker
//! that adds real credentials outside an agent's VM, and asking for more.

use crate::cli::identity::parse_duration;
use crate::cli::secret_input::SecretInput;
use crate::cli::{SocketArgs, print_json};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::broker::{BrokerGrant, BrokerService, RequestStatus};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct BrokerCmd {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: BrokerAction,
}

#[derive(Debug, Subcommand)]
enum BrokerAction {
    /// Run the broker. VMs call http://<listen>/<service>/<path> with a
    /// placeholder; nothing else is reachable through it.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8899")]
        listen: SocketAddr,
        /// One JSON line per request: session, service, path, status.
        #[arg(long)]
        audit_log: Option<PathBuf>,
    },
    /// Services the broker can reach.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Let sessions whose subject matches --to use SERVICE.
    Allow {
        service: String,
        #[arg(long)]
        to: String,
    },
    Disallow {
        service: String,
        #[arg(long)]
        to: String,
    },
    /// Let the workload SUB resolve placeholders, that is, run a broker.
    Trust { sub: String },
    /// Services, grants, brokers and requests.
    List,
    /// A placeholder for a session's VM to hold in place of the real key.
    Placeholder {
        service: String,
        #[arg(long)]
        session: String,
    },
}

#[derive(Debug, Subcommand)]
enum ServiceAction {
    Add {
        name: String,
        /// Such as https://api.anthropic.com.
        #[arg(long)]
        upstream: String,
        /// The header the credential goes in, such as x-api-key.
        #[arg(long)]
        header: String,
        /// Send it as `Bearer <value>`.
        #[arg(long)]
        bearer: bool,
        /// The vault key holding the real credential.
        #[arg(long)]
        secret: String,
    },
    Remove { name: String },
}

pub async fn broker(cmd: BrokerCmd) -> Result<()> {
    let client = VaultClient::from_socket_path(&cmd.socket.socket);
    let state = match cmd.action {
        BrokerAction::Serve { listen, audit_log } => {
            let mut broker = harar_proxy::broker::Broker::new(client);
            if let Some(path) = audit_log {
                broker = broker.with_audit_log_path(path);
            }
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("bind {listen}"))?;
            eprintln!("harar broker listening on {listen}");
            return Ok(harar_proxy::broker::serve(listener, broker).await?);
        }
        BrokerAction::Service { action: ServiceAction::Add { name, upstream, header, bearer, secret } } => {
            client.broker_service(&BrokerService { name, upstream, header, bearer, secret }).await?
        }
        BrokerAction::Service { action: ServiceAction::Remove { name } } => client.broker_service_remove(&name).await?,
        BrokerAction::Allow { service, to } => client.broker_allow(&BrokerGrant { service, to }).await?,
        BrokerAction::Disallow { service, to } => client.broker_disallow(&BrokerGrant { service, to }).await?,
        BrokerAction::Trust { sub } => client.broker_trust(&sub).await?,
        BrokerAction::List => client.broker_state().await?,
        BrokerAction::Placeholder { service, session } => {
            println!("{}", client.broker_placeholder(&session, &service).await?);
            return Ok(());
        }
    };
    // Placeholders are listed by hash only; skip them to keep the output short.
    print_json(&serde_json::json!({
        "services": state.services,
        "grants": state.grants,
        "brokers": state.brokers,
        "requests": state.requests.values().collect::<Vec<_>>(),
    }))
}

/// Ask for a service your session wasn't granted. Someone with admin rights
/// approves it with `harar approvals approve`.
#[derive(Debug, Args)]
pub struct Request {
    #[command(flatten)]
    socket: SocketArgs,
    /// Your session token.
    #[command(flatten)]
    token: SecretInput,
    service: String,
    #[arg(long)]
    reason: String,
}

pub async fn request(cmd: Request) -> Result<()> {
    let token = cmd.token.read("Session token")?;
    let asked = VaultClient::from_socket_path(cmd.socket.socket)
        .broker_request(&token, &cmd.service, &cmd.reason)
        .await?;
    print_json(&asked)
}

/// Requests from agents for services they weren't granted.
#[derive(Debug, Args)]
pub struct Approvals {
    #[command(flatten)]
    socket: SocketArgs,
    #[command(subcommand)]
    action: ApprovalAction,
}

#[derive(Debug, Subcommand)]
enum ApprovalAction {
    /// Pending requests.
    List,
    /// Grant a request to that session only, for --for (default 1h).
    Approve {
        id: String,
        #[arg(long = "for", value_parser = parse_duration)]
        for_seconds: Option<u64>,
    },
    Deny { id: String },
}

pub async fn approvals(cmd: Approvals) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    match cmd.action {
        ApprovalAction::List => {
            let state = client.broker_state().await?;
            let pending: Vec<_> = state.requests.values().filter(|r| r.status == RequestStatus::Pending).collect();
            print_json(&pending)
        }
        ApprovalAction::Approve { id, for_seconds } => print_json(&client.broker_decide(&id, true, for_seconds).await?),
        ApprovalAction::Deny { id } => print_json(&client.broker_decide(&id, false, None).await?),
    }
}
