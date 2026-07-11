use crate::cli::print_json;
use anyhow::Result;
use clap::Args;
use std::fs;
use tana_cli_core::TokenStore;

#[derive(Debug, Args)]
pub struct Logout {}

pub async fn run(_cmd: Logout) -> Result<()> {
    let store = TokenStore::default_store()?;
    match fs::remove_file(store.path()) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    print_json(&serde_json::json!({ "ok": true }))
}
