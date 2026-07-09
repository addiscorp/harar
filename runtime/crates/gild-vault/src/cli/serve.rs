use anyhow::{Context, Result};
use clap::Args;
use std::process::Command;

#[derive(Debug, Args)]
pub struct Serve {
    #[arg(trailing_var_arg = true)]
    args: Vec<String>,
}

pub async fn run(cmd: Serve) -> Result<()> {
    let status = Command::new("gild-vault")
        .args(cmd.args)
        .status()
        .context("start gild-vault daemon")?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("gild-vault exited with {status}")
    }
}
