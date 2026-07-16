use anyhow::Result;
use clap::Args;

#[derive(Debug, Args)]
pub struct Proxy {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

pub async fn run(cmd: Proxy) -> Result<()> {
    let _ = cmd.args;
    harar_proxy::runner::run_from_env_and_args().await
}
