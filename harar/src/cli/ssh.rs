use crate::cli::{SocketArgs, print_json};
use crate::ssh::{KEY_PREFIX, StoredKey};
use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use harar_client::VaultClient;

/// SSH keys kept in the vault and served by `harar agent`.
#[derive(Debug, Args)]
pub struct Ssh {
    #[command(subcommand)]
    command: SshCommand,
}

#[derive(Debug, Subcommand)]
enum SshCommand {
    /// Create an Ed25519 key in the vault and print its public key.
    Keygen(Keygen),
    /// Print the public keys of every SSH key in the vault.
    List(List),
}

#[derive(Debug, Args)]
struct Keygen {
    #[command(flatten)]
    socket: SocketArgs,
    /// Name of the key (stored as `ssh/<name>`).
    name: String,
    /// Comment on the public key. Default: the name.
    #[arg(long)]
    comment: Option<String>,
}

#[derive(Debug, Args)]
struct List {
    #[command(flatten)]
    socket: SocketArgs,
}

pub async fn run(cmd: Ssh) -> Result<()> {
    match cmd.command {
        SshCommand::Keygen(cmd) => keygen(cmd).await,
        SshCommand::List(cmd) => list(cmd).await,
    }
}

async fn keygen(cmd: Keygen) -> Result<()> {
    if cmd.name.is_empty() || cmd.name.contains('/') {
        return Err(anyhow!("an SSH key name can't be empty or contain '/'"));
    }
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let vault_key = format!("{KEY_PREFIX}{}", cmd.name);
    if client.list().await?.contains(&vault_key) {
        return Err(anyhow!("{vault_key} already exists"));
    }
    let key = StoredKey::generate(cmd.comment.unwrap_or_else(|| cmd.name.clone()));
    client
        .put(&vault_key, &serde_json::to_string(&key)?)
        .await
        .with_context(|| format!("store {vault_key}"))?;
    print_json(&serde_json::json!({
        "ok": true,
        "key": vault_key,
        "public_key": key.public_line()?,
        "next": "Point SSH at the agent: `IdentityAgent \"~/Library/Application Support/harar/ssh.sock\"` in ~/.ssh/config, or SSH_AUTH_SOCK for one shell.",
    }))
}

async fn list(cmd: List) -> Result<()> {
    let client = VaultClient::from_socket_path(cmd.socket.socket);
    let mut keys = Vec::new();
    for name in client.list().await? {
        if let Some(short) = name.strip_prefix(KEY_PREFIX) {
            let key: StoredKey = serde_json::from_str(&client.get(&name).await?)
                .with_context(|| format!("{name} is not an SSH key"))?;
            keys.push(serde_json::json!({ "name": short, "public_key": key.public_line()? }));
        }
    }
    print_json(&keys)
}
