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
    #[arg(long, env = "HARAR_SOCKET", default_value = DEFAULT_SOCKET_PATH)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn socket_arg_defaults_to_daemon_socket_without_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("HARAR_SOCKET");
        restore_env("HARAR_SOCKET", None);

        let cli = SocketOnly::try_parse_from(["harar"]).unwrap();

        assert_eq!(cli.socket.socket, PathBuf::from(DEFAULT_SOCKET_PATH));
        restore_env("HARAR_SOCKET", previous);
    }

    #[test]
    fn socket_arg_honors_harar_socket_env_without_flag() {
        let _guard = ENV_LOCK.lock().unwrap();
        let previous = std::env::var_os("HARAR_SOCKET");
        let socket = "/tmp/harar-test.sock";
        restore_env("HARAR_SOCKET", Some(OsString::from(socket)));

        let cli = SocketOnly::try_parse_from(["harar"]).unwrap();

        assert_eq!(cli.socket.socket, PathBuf::from(socket));
        restore_env("HARAR_SOCKET", previous);
    }

    #[derive(Debug, Parser)]
    struct SocketOnly {
        #[command(flatten)]
        socket: SocketArgs,
    }

    fn restore_env(key: &str, value: Option<OsString>) {
        // SAFETY: tests in this module serialize HARAR_SOCKET mutations with
        // ENV_LOCK and restore the original value before returning.
        unsafe {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}
