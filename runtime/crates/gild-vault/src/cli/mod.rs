use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

pub mod get;
pub mod jwks;
pub mod mint;
pub mod proxy;
pub mod put;
pub mod revoke;
pub mod self_cmd;
pub mod serve;
pub mod setup;
pub mod verify;

const DEFAULT_SOCKET_PATH: &str = "/run/gild-vault.sock";

#[derive(Debug, Parser)]
#[command(name = "harar", about = "Harar vault and token administration")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(serve::Serve),
    Proxy(proxy::Proxy),
    Get(get::Get),
    Put(put::Put),
    Mint(mint::Mint),
    Verify(verify::Verify),
    Revoke(revoke::Revoke),
    Jwks(jwks::Jwks),
    Setup(setup::Setup),
    #[command(name = "self")]
    SelfCmd(self_cmd::SelfCommand),
}

#[derive(Debug, Args)]
pub struct SocketArgs {
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,
}

pub async fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve(cmd) => serve::run(cmd).await,
        Command::Proxy(cmd) => proxy::run(cmd).await,
        Command::Get(cmd) => get::run(cmd).await,
        Command::Put(cmd) => put::run(cmd).await,
        Command::Mint(cmd) => mint::run(cmd).await,
        Command::Verify(cmd) => verify::run(cmd).await,
        Command::Revoke(cmd) => revoke::run(cmd).await,
        Command::Jwks(cmd) => jwks::run(cmd).await,
        Command::Setup(cmd) => setup::run(cmd).await,
        Command::SelfCmd(cmd) => self_cmd::run(cmd).await,
    }
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
