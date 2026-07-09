use crate::cli::print_json;
use anyhow::Result;
use clap::Args;
use tana_cli_core::{SecretToken, TokenStore};

#[derive(Debug, Args)]
pub struct Login {
    #[arg(long, env = "TANA_TOKEN")]
    token: String,
}

pub async fn run(cmd: Login) -> Result<()> {
    let store = TokenStore::default_store()?;
    store.write_token(&SecretToken::new(cmd.token)?)?;
    print_json(&serde_json::json!({ "ok": true, "path": store.path() }))
}
