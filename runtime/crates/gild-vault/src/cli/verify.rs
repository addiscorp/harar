use crate::cli::{SocketArgs, print_json};
use anyhow::Result;
use clap::Args;
use gild_vault_client::{VaultClient, VerifyTokenRequest};

#[derive(Debug, Args)]
pub struct Verify {
    #[command(flatten)]
    socket: SocketArgs,
    #[arg(long)]
    token: String,
    #[arg(long, alias = "aud")]
    audience: String,
    #[arg(long)]
    subject: Option<String>,
    #[arg(long)]
    run_id: Option<String>,
}

pub async fn run(cmd: Verify) -> Result<()> {
    let response = VaultClient::from_socket_path(cmd.socket.socket)
        .verify_token(&VerifyTokenRequest {
            token: cmd.token,
            audience: cmd.audience,
            subject: cmd.subject,
            run_id: cmd.run_id,
        })
        .await?;
    print_json(&response)
}
