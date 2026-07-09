use anyhow::{Context, Result};
use clap::Args;
use std::process::Command;

#[derive(Debug, Args)]
pub struct Proxy {
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

pub async fn run(cmd: Proxy) -> Result<()> {
    let status = Command::new("gild-vault-proxy")
        .args(cmd.args)
        .status()
        .context("start gild-vault-proxy")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("gild-vault-proxy exited with {status}")
    }
}
