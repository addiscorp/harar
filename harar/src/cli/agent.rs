use crate::agent::{self, AgentRequest, Vault, VaultConfig};
use crate::cli::print_json;
use crate::master_key::{self, KeyTier};
use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Run the per-user agent that holds your vault.
#[derive(Debug, Args)]
pub struct Agent {
    #[command(subcommand)]
    command: Option<AgentCommand>,
    #[arg(long, default_value_os_t = agent::default_socket_path())]
    socket: PathBuf,
    /// Encrypted vault file.
    #[arg(long, default_value_os_t = agent::default_state_path())]
    state: PathBuf,
    /// Master key file (see `harar key`).
    #[arg(long, default_value_os_t = master_key::default_master_key_path())]
    key: PathBuf,
    /// Lock after this many minutes without any request.
    #[arg(long, default_value_t = 30)]
    idle_lock_minutes: u64,
    /// Ask a terminal again after this many minutes without a request from it.
    #[arg(long, default_value_t = 10)]
    session_idle_minutes: u64,
}

#[derive(Debug, Subcommand)]
enum AgentCommand {
    /// Print a LaunchAgent that starts the agent at login. Install it with
    /// `harar agent plist > ~/Library/LaunchAgents/dev.harar.agent.plist`
    /// and `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/dev.harar.agent.plist`.
    Plist,
}

pub async fn run(cmd: Agent) -> Result<()> {
    if let Some(AgentCommand::Plist) = cmd.command {
        let program = std::env::current_exe().context("locate the harar binary")?;
        print!("{}", agent::launch_agent_plist(&program));
        return Ok(());
    }
    agent::disable_core_dumps()?;
    if master_key::key_tier(&cmd.key)? == KeyTier::Missing {
        return Err(anyhow!("no master key at {}; create one with `harar key init`", cmd.key.display()));
    }
    let (unlock, approve, approvals) = key_closures(master_key::MasterKeyFile::read(&cmd.key)?);
    let vault = Vault::new(
        VaultConfig {
            state_path: cmd.state,
            // SAFETY: geteuid has no preconditions.
            owner_uid: unsafe { libc::geteuid() },
            idle_lock: Duration::from_secs(cmd.idle_lock_minutes * 60),
            session_idle: Duration::from_secs(cmd.session_idle_minutes * 60),
            approvals,
        },
        unlock,
        approve,
        Instant::now(),
    );
    let listener = agent::bind(&cmd.socket)?;
    eprintln!("harar agent listening on {} (locked)", cmd.socket.display());
    agent::serve(listener, vault).await
}

/// Unlocks and approvals both open the key file as the agent read it at start,
/// never the path again: swapping the file for a plain key must not turn an
/// approval into one that never asks.
fn key_closures(key: master_key::MasterKeyFile) -> (agent::Unlock, agent::Approve, &'static str) {
    let key = std::sync::Arc::new(key);
    let unlock_key = std::sync::Arc::clone(&key);
    let unlock: agent::Unlock = Box::new(move || unlock_key.open());
    match key.tier() {
        // Opening the sealed key again asks the person, which is the approval.
        KeyTier::SecureEnclave => (unlock, Box::new(move || key.open().map(drop)), "secure-enclave"),
        KeyTier::File | KeyTier::Missing => (unlock, Box::new(|| Ok(())), "none"),
    }
}

#[derive(Debug, Args)]
pub struct AgentSocket {
    #[arg(long, default_value_os_t = agent::default_socket_path())]
    socket: PathBuf,
}

/// Unlock the agent now (asks on a Secure Enclave key).
#[derive(Debug, Args)]
pub struct Unlock {
    #[command(flatten)]
    socket: AgentSocket,
}

/// Forget the key and every approval now.
#[derive(Debug, Args)]
pub struct Lock {
    #[command(flatten)]
    socket: AgentSocket,
}

/// Show whether the agent is unlocked.
#[derive(Debug, Args)]
pub struct Status {
    #[command(flatten)]
    socket: AgentSocket,
}

pub async fn unlock(cmd: Unlock) -> Result<()> {
    send(&cmd.socket.socket, &AgentRequest::Unlock)
}

pub async fn lock(cmd: Lock) -> Result<()> {
    send(&cmd.socket.socket, &AgentRequest::Lock)
}

pub async fn status(cmd: Status) -> Result<()> {
    send(&cmd.socket.socket, &AgentRequest::Status)
}

fn send(socket: &std::path::Path, request: &AgentRequest) -> Result<()> {
    let mut stream = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("no harar agent at {}; start one with `harar agent`", socket.display()))?;
    stream.write_all(&serde_json::to_vec(request)?)?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reply = String::new();
    stream.read_to_string(&mut reply)?;
    let reply: serde_json::Value = serde_json::from_str(reply.trim()).context("decode agent reply")?;
    let failed = reply.get("ok") == Some(&serde_json::Value::Bool(false));
    print_json(&reply)?;
    if failed {
        return Err(anyhow!("{}", reply["error"].as_str().unwrap_or("agent refused the request")));
    }
    Ok(())
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn swapping_the_key_file_never_changes_what_the_agent_opens() {
        if crate::enclave::tests::test_key().is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("harar/master.key");
        let sealed = master_key::create_enclave_master_key(
            &path,
            &master_key::default_recovery_path(&path),
            "correct horse battery".to_string().into(),
            crate::enclave::Presence::NotRequired,
        )
        .unwrap();
        let (unlock, approve, approvals) = key_closures(master_key::MasterKeyFile::read(&path).unwrap());
        assert_eq!(approvals, "secure-enclave");

        // Another process of this user swaps in a plain key it made itself.
        let planted = age::x25519::Identity::generate();
        fs::remove_file(&path).unwrap();
        fs::write(&path, format!("{}\n", age::secrecy::ExposeSecret::expose_secret(&planted.to_string()))).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).unwrap();

        assert_eq!(unlock().unwrap().to_public().to_string(), sealed.to_public().to_string());
        fs::remove_file(&path).unwrap();
        approve().expect("approval opens the sealed key read at start, not the path");
        assert_eq!(unlock().unwrap().to_public().to_string(), sealed.to_public().to_string());
    }
}
