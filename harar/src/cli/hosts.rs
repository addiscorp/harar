//! `harar hosts list|allow|revoke`: where a secret may go. In a per-user
//! agent's vault, kept by these commands; at a primary, a role's `send`
//! permission (`harar policy role set … --send "SECRET HOST…"`), so only
//! `list` works there.
use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::{Args, Subcommand};
use harar_client::VaultClient;

#[derive(Debug, Args)]
pub struct Hosts {
    #[command(subcommand)]
    action: HostsAction,
}

#[derive(Debug, Subcommand)]
enum HostsAction {
    /// The hosts a secret may go to.
    List {
        key: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// Let a secret go to a host (`*.example.com` for any name under it).
    Allow {
        key: String,
        host: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
    /// Stop a secret going to a host.
    Revoke {
        key: String,
        host: String,
        #[command(flatten)]
        socket: SocketArgs,
    },
}

pub async fn run(cmd: Hosts) -> Result<()> {
    match cmd.action {
        HostsAction::List { key, socket } => {
            let hosts = VaultClient::from_socket_path(socket.socket).hosts(&key).await?;
            print_json(&serde_json::json!({ "ok": true, "key": key, "hosts": hosts }))
        }
        HostsAction::Allow { key, host, socket } => {
            VaultClient::from_socket_path(socket.socket).allow_host(&key, &host).await?;
            print_json(&serde_json::json!({ "ok": true }))
        }
        HostsAction::Revoke { key, host, socket } => {
            VaultClient::from_socket_path(socket.socket).revoke_host(&key, &host).await?;
            print_json(&serde_json::json!({ "ok": true }))
        }
    }
}
