use clap::{Args, Subcommand};

pub mod login;
pub mod logout;
pub mod whoami;

#[derive(Debug, Args)]
pub struct SelfCommand {
    #[command(subcommand)]
    command: SelfSubcommand,
}

#[derive(Debug, Subcommand)]
enum SelfSubcommand {
    Login(login::Login),
    Logout(logout::Logout),
    Whoami(whoami::Whoami),
}

pub async fn run(cmd: SelfCommand) -> anyhow::Result<()> {
    match cmd.command {
        SelfSubcommand::Login(cmd) => login::run(cmd).await,
        SelfSubcommand::Logout(cmd) => logout::run(cmd).await,
        SelfSubcommand::Whoami(cmd) => whoami::run(cmd).await,
    }
}
