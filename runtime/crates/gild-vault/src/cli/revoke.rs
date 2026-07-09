use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use gild_vault_client::{RevokeTokenRequest, VaultClient};

#[derive(Debug, Args)]
pub struct Revoke {
    #[command(flatten)]
    socket: SocketArgs,
    #[arg(long)]
    jti: String,
}

pub async fn run(cmd: Revoke) -> Result<()> {
    VaultClient::from_socket_path(cmd.socket.socket)
        .revoke_token(&RevokeTokenRequest { jti: cmd.jti })
        .await?;
    print_json(&serde_json::json!({ "ok": true }))
}
