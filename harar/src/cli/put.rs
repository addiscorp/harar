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
}

pub async fn run(cmd: Put) -> Result<()> {
    let value = cmd.secret.read("Secret value")?;
    VaultClient::from_socket_path(cmd.socket.socket).put(&cmd.key, &value).await?;
    print_json(&serde_json::json!({ "ok": true }))
}
