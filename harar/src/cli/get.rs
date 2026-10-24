use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use harar_client::VaultClient;

#[derive(Debug, Args)]
pub struct Get {
    #[command(flatten)]
    socket: SocketArgs,
    key: String,
}

pub async fn run(cmd: Get) -> Result<()> {
    let value = VaultClient::from_socket_path(cmd.socket.socket).get(&cmd.key).await?;
    print_json(&serde_json::json!({ "ok": true, "value": value }))
}
