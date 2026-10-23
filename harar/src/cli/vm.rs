//! `harar vm`: VM identity. On the host: register VMs and serve them over
//! vsock. Inside a VM: ask the host for tokens.

use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::{Args, Subcommand};
use harar_client::VaultClient;
use harar_client::vms::VmFor;

#[derive(Debug, Args)]
pub struct VmCmd {
    #[command(subcommand)]
    action: VmAction,
}

#[derive(Debug, Subcommand)]
enum VmAction {
    /// On the host: the VM at vsock CID runs for a session or a run you manage.
    Register {
        #[arg(long)]
        cid: u32,
        /// It becomes vm:<name>.
        #[arg(long)]
        name: String,
        #[arg(long, required_unless_present = "run", conflicts_with = "run")]
        session: Option<String>,
        #[arg(long)]
        run: Option<String>,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// On the host: the VM at CID is gone.
    Forget {
        #[arg(long)]
        cid: u32,
        #[command(flatten)]
        socket: SocketArgs,
    },
    List {
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// On the host: answer VMs on a vsock port (Linux).
    #[cfg(target_os = "linux")]
    Serve {
        #[arg(long, default_value_t = harar_client::vms::DEFAULT_PORT)]
        port: u32,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// Inside a VM: a token from the host, as this VM (Linux).
    #[cfg(target_os = "linux")]
    Token {
        #[arg(long = "aud")]
        audience: String,
        #[arg(long = "scope")]
        scopes: Vec<String>,
        #[arg(long, value_parser = crate::cli::identity::parse_duration)]
        ttl: Option<u64>,
        #[arg(long)]
        raw: bool,
        #[command(flatten)]
        host: HostAddress,
    },
}

/// Where the host's `harar vm serve` listens, seen from inside the VM.
#[derive(Debug, Args)]
pub struct HostAddress {
    /// The host's CID: 2 from inside a VM.
    #[arg(long, default_value_t = 2)]
    pub host_cid: u32,
    #[arg(long, default_value_t = harar_client::vms::DEFAULT_PORT)]
    pub vsock_port: u32,
}

pub async fn vm(cmd: VmCmd) -> Result<()> {
    match cmd.action {
        VmAction::Register { cid, name, session, run, socket } => {
            let runs_for = match (session, run) {
                (Some(sid), _) => VmFor::Session(sid),
                (None, Some(run)) => VmFor::Run(run),
                (None, None) => unreachable!("clap requires --session or --run"),
            };
            print_json(&VaultClient::from_socket_path(socket.socket).vm_register(cid, &name, &runs_for).await?)
        }
        VmAction::Forget { cid, socket } => print_json(&VaultClient::from_socket_path(socket.socket).vm_forget(cid).await?),
        VmAction::List { socket } => print_json(&VaultClient::from_socket_path(socket.socket).vms().await?),
        #[cfg(target_os = "linux")]
        VmAction::Serve { port, socket } => crate::vm::vsock::serve(port, VaultClient::from_socket_path(socket.socket)).await,
        #[cfg(target_os = "linux")]
        VmAction::Token { audience, scopes, ttl, raw, host } => {
            let ask = harar_client::oidc::TokenAsk { audience, scopes, ttl_seconds: ttl, act: None, alg: None };
            let stream = crate::vm::vsock::connect(host.host_cid, host.vsock_port).await?;
            let reply = crate::vm::ask(stream, &harar_client::vms::VmRequest::Token(ask)).await?;
            if raw {
                println!("{}", reply["token"].as_str().unwrap_or_default());
                Ok(())
            } else {
                print_json(&serde_json::json!({ "token": reply["token"], "claims": reply["claims"] }))
            }
        }
    }
}

/// Inside a run's VM: the environment's build secrets, from the host.
pub async fn secrets_from_host(env: &str, host: &HostAddress) -> Result<std::collections::BTreeMap<String, String>> {
    #[cfg(target_os = "linux")]
    {
        let stream = crate::vm::vsock::connect(host.host_cid, host.vsock_port).await?;
        let reply = crate::vm::ask(stream, &harar_client::vms::VmRequest::Secrets { env: env.to_string() }).await?;
        Ok(serde_json::from_value(reply["secrets"].clone())?)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (env, host);
        Err(anyhow::anyhow!("--from-host needs vsock, which harar supports on Linux only"))
    }
}
