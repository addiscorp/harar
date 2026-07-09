use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use gild_vault_client::VaultClient;

#[derive(Debug, Args)]
pub struct Get {
    #[command(flatten)]
    socket: SocketArgs,
    key: String,
    #[arg(long)]
    shop_id: Option<String>,
}

pub async fn run(cmd: Get) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let value = match cmd.shop_id.as_deref() {
        Some(shop_id) => client.get_for_shop(&cmd.key, shop_id).await?,
        None => client.get(&cmd.key).await?,
    };
    print_json(&serde_json::json!({ "ok": true, "value": value }))
}
