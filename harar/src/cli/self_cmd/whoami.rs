use crate::cli::print_json;
use anyhow::Result;
use clap::Args;
use tana_cli_core::{LinkhashClient, TokenStore};

#[derive(Debug, Args)]
pub struct Whoami {
    #[arg(long, default_value = "https://git.tana.gg")]
    linkhash_url: String,
}

pub async fn run(cmd: Whoami) -> Result<()> {
    let store = TokenStore::default_store()?;
    let principal = LinkhashClient::new(cmd.linkhash_url)?.whoami_from_store(&store)?;
    print_json(&serde_json::json!({ "ok": true, "principal": principal }))
}
