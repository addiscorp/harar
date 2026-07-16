use crate::cli::secret_input::SecretInput;
use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use harar_client::VaultClient;

#[derive(Debug, Args)]
pub struct Put {
    #[command(flatten)]
    socket: SocketArgs,
    key: String,
    #[command(flatten)]
    secret: SecretInput,
    #[arg(long)]
    shop_id: Option<String>,
}

pub async fn run(cmd: Put) -> Result<()> {
    let value = cmd.secret.read("Secret value")?;
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    match cmd.shop_id.as_deref() {
        Some(shop_id) => client.put_for_shop(&cmd.key, &value, shop_id).await?,
        None => client.put(&cmd.key, &value).await?,
    }
    print_json(&serde_json::json!({ "ok": true }))
}
