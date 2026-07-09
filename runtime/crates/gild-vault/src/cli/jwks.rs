use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use gild_vault_client::VaultClient;

#[derive(Debug, Args)]
pub struct Jwks {
    #[command(flatten)]
    socket: SocketArgs,
}

pub async fn run(cmd: Jwks) -> Result<()> {
    let jwks = VaultClient::from_socket_path(cmd.socket.socket)
        .jwks()
        .await?;
    print_json(&jwks)
}
