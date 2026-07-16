use anyhow::Result;
use clap::Args;

#[derive(Debug, Args)]
pub struct Serve {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

pub async fn run(cmd: Serve) -> Result<()> {
    let _ = cmd.args;
    crate::run_daemon().await
}
