use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

pub mod agent;
pub mod broker;
pub mod get;
pub mod hosts;
pub mod identity;
pub mod jwks;
pub mod key;
pub mod mint;
pub mod plugin;
pub mod proxy;
pub mod put;
pub mod revoke;
pub mod run;
pub mod runs;
pub mod secret_input;
pub mod serve;
pub mod setup;
pub mod ssh;
pub mod verify;
pub mod version;

const DEFAULT_SOCKET_PATH: &str = "/run/harar.sock";

#[derive(Debug, Parser)]
#[command(name = "harar", about = "Harar vault and token administration")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve(serve::Serve),
    Agent(agent::Agent),
    Unlock(agent::Unlock),
    Lock(agent::Lock),
    Status(agent::Status),
    Proxy(proxy::Proxy),
    Run(run::Run),
    Import(run::Import),
    Inject(run::Inject),
    Plugin(plugin::Plugin),
    Ssh(ssh::Ssh),
    Get(get::Get),
    Put(put::Put),
    Token(identity::Token),
    Workload(identity::WorkloadCmd),
    Policy(identity::PolicyCmd),
    Session(identity::SessionCmd),
    Exchange(identity::Exchange),
    Broker(broker::BrokerCmd),
    Request(broker::Request),
    Approvals(broker::Approvals),
    Env(runs::EnvCmd),
    Runs(runs::RunsCmd),
    Host(hosts::HostCmd),
    Mint(mint::Mint),
    Verify(verify::Verify),
    Revoke(revoke::Revoke),
    Jwks(jwks::Jwks),
    Key(key::Key),
    Setup(setup::Setup),
    Version(version::Version),
}

#[derive(Debug, Args)]
pub struct SocketArgs {
    #[arg(long, env = "HARAR_SOCKET", default_value_os_t = default_socket())]
    socket: PathBuf,
}

/// On macOS harar runs as the signed-in user, so commands talk to that user's
/// agent; elsewhere to the system daemon.
fn default_socket() -> PathBuf {
    if cfg!(target_os = "macos") {
        crate::agent::default_socket_path()
    } else {
        PathBuf::from(DEFAULT_SOCKET_PATH)
    }
}

pub async fn run() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Serve(cmd) => serve::run(cmd).await,
        Command::Agent(cmd) => agent::run(cmd).await,
        Command::Unlock(cmd) => agent::unlock(cmd).await,
        Command::Lock(cmd) => agent::lock(cmd).await,
        Command::Status(cmd) => agent::status(cmd).await,
        Command::Proxy(cmd) => proxy::run(cmd).await,
        Command::Run(cmd) => run::run(cmd).await,
        Command::Import(cmd) => run::import(cmd).await,
        Command::Inject(cmd) => run::inject(cmd).await,
        Command::Plugin(cmd) => plugin::run(cmd).await,
        Command::Ssh(cmd) => ssh::run(cmd).await,
        Command::Get(cmd) => get::run(cmd).await,
        Command::Put(cmd) => put::run(cmd).await,
        Command::Token(cmd) => identity::token(cmd).await,
        Command::Workload(cmd) => identity::workload(cmd).await,
        Command::Policy(cmd) => identity::policy(cmd).await,
        Command::Session(cmd) => identity::session(cmd).await,
        Command::Exchange(cmd) => identity::exchange(cmd).await,
        Command::Broker(cmd) => broker::broker(cmd).await,
        Command::Request(cmd) => broker::request(cmd).await,
        Command::Approvals(cmd) => broker::approvals(cmd).await,
        Command::Env(cmd) => runs::env(cmd).await,
        Command::Runs(cmd) => runs::runs(cmd).await,
        Command::Host(cmd) => hosts::host(cmd).await,
        Command::Mint(cmd) => mint::run(cmd).await,
        Command::Verify(cmd) => verify::run(cmd).await,
        Command::Revoke(cmd) => revoke::run(cmd).await,
        Command::Jwks(cmd) => jwks::run(cmd).await,
        Command::Key(cmd) => key::run(cmd).await,
        Command::Setup(cmd) => setup::run(cmd).await,
        Command::Version(cmd) => version::run(cmd),
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

        assert_eq!(cli.socket.socket, default_socket());
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

    #[test]
    fn credential_commands_reject_secret_values_in_argv() {
        for argv in [
            vec![
                "harar",
                "verify",
                "--token",
                "eyJhbGciOiJFZERTQSJ9.leak",
                "--audience",
                "linkhash",
            ],
            vec!["harar", "put", "DATABASE_URL", "postgres://secret@db"],
        ] {
            assert!(Cli::try_parse_from(argv).is_err());
        }
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
