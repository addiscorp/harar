use crate::cli::print_json;
use crate::cli::secret_input::SecretInput;
use anyhow::Result;
use clap::Args;
use tana_cli_core::{SecretToken, TokenStore};

#[derive(Debug, Args)]
pub struct Login {
    #[command(flatten)]
    secret: SecretInput,
}

pub async fn run(cmd: Login) -> Result<()> {
    let store = TokenStore::default_store()?;
    store.write_token(&SecretToken::new(cmd.secret.read("Linkhash token")?)?)?;
    print_json(&serde_json::json!({ "ok": true, "path": store.path() }))
}
