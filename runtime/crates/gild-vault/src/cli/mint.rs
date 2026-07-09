use crate::cli::{SocketArgs, print_json};
use anyhow::{Context, Result};
use clap::Args;
use gild_vault_client::{HararTokenTemplate, MintTokenRequest, VaultClient};

#[derive(Debug, Args)]
pub struct Mint {
    #[command(flatten)]
    socket: SocketArgs,
    #[arg(long)]
    template: String,
    #[arg(long)]
    subject: String,
    #[arg(long)]
    run_id: Option<String>,
    #[arg(long)]
    ttl_seconds: u64,
}

pub async fn run(cmd: Mint) -> Result<()> {
    let template = HararTokenTemplate::parse(&cmd.template)
        .with_context(|| format!("unknown token template {}", cmd.template))?;
    let token = VaultClient::from_socket_path(cmd.socket.socket)
        .mint_token(&MintTokenRequest {
            template,
            subject: cmd.subject,
            run_id: cmd.run_id,
            ttl_seconds: cmd.ttl_seconds,
        })
        .await?;
    print_json(&token)
}
