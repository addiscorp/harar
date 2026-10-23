use crate::cli::print_json;
use crate::cli::secret_input::SecretInput;
use crate::master_key::{self, KeyTier};
use anyhow::{Result, anyhow};
use clap::{Args, Subcommand};
use std::path::PathBuf;

const MIN_PASSPHRASE_CHARS: usize = 12;

/// The master key that encrypts the vault, and its recovery copy.
#[derive(Debug, Args)]
pub struct Key {
    #[command(subcommand)]
    command: KeyCommand,
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Create a master key sealed to this Mac's Secure Enclave, plus a
    /// recovery copy encrypted to a passphrase you keep offline.
    Init(Init),
    /// Show how the master key is protected and what this machine supports.
    Status(Status),
    /// Seal the master key from its recovery copy to a new Secure Enclave key.
    Recover(Recover),
}

#[derive(Debug, Args)]
struct Paths {
    /// Master key file. Default: ~/Library/Application Support/harar/master.key
    /// on macOS, /etc/harar/master.key elsewhere.
    #[arg(long)]
    path: Option<PathBuf>,
    /// Recovery copy. Default: the master key path + `.recovery.age`.
    #[arg(long)]
    recovery: Option<PathBuf>,
}

impl Paths {
    fn resolve(self) -> (PathBuf, PathBuf) {
        let path = self.path.unwrap_or_else(master_key::default_master_key_path);
        let recovery = self.recovery.unwrap_or_else(|| master_key::default_recovery_path(&path));
        (path, recovery)
    }
}

#[derive(Debug, Args)]
struct Init {
    #[command(flatten)]
    paths: Paths,
    /// Where the recovery passphrase comes from (prompted twice by default).
    #[command(flatten)]
    passphrase: SecretInput,
}

#[derive(Debug, Args)]
struct Status {
    #[command(flatten)]
    paths: Paths,
}

#[derive(Debug, Args)]
struct Recover {
    #[command(flatten)]
    paths: Paths,
    #[command(flatten)]
    passphrase: SecretInput,
}

pub async fn run(cmd: Key) -> Result<()> {
    match cmd.command {
        KeyCommand::Init(cmd) => init(cmd),
        KeyCommand::Status(cmd) => status(cmd),
        KeyCommand::Recover(cmd) => recover(cmd),
    }
}

fn status(cmd: Status) -> Result<()> {
    let (path, recovery) = cmd.paths.resolve();
    let tier = master_key::key_tier(&path)?;
    print_json(&serde_json::json!({
        "path": path,
        "tier": tier,
        "recovery_copy": recovery.exists(),
        "secure_enclave_available": secure_enclave_available(),
    }))
}

#[cfg(target_os = "macos")]
fn secure_enclave_available() -> bool {
    crate::enclave::available()
}

#[cfg(not(target_os = "macos"))]
fn secure_enclave_available() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn init(cmd: Init) -> Result<()> {
    let (path, recovery) = cmd.paths.resolve();
    if master_key::key_tier(&path)? != KeyTier::Missing {
        return Err(anyhow!("{} already exists; refusing to replace a master key", path.display()));
    }
    if !crate::enclave::available() {
        return Err(anyhow!("this Mac has no usable Secure Enclave (Apple silicon or an Intel Mac with a T2 chip is needed)"));
    }
    let passphrase = read_passphrase(cmd.passphrase, true)?;
    let identity = master_key::create_enclave_master_key(
        &path,
        &recovery,
        passphrase,
        crate::enclave::Presence::Required,
    )?;
    print_json(&serde_json::json!({
        "ok": true,
        "path": path,
        "recovery": recovery,
        "tier": KeyTier::SecureEnclave,
        "recipient": identity.to_public().to_string(),
        "next": "Move the recovery copy somewhere offline. It and its passphrase are the only way back if this Mac is lost.",
    }))
}

#[cfg(target_os = "macos")]
fn recover(cmd: Recover) -> Result<()> {
    let (path, recovery) = cmd.paths.resolve();
    let passphrase = read_passphrase(cmd.passphrase, false)?;
    let identity = master_key::recover_enclave_master_key(
        &recovery,
        passphrase,
        &path,
        crate::enclave::Presence::Required,
    )?;
    print_json(&serde_json::json!({
        "ok": true,
        "path": path,
        "tier": KeyTier::SecureEnclave,
        "recipient": identity.to_public().to_string(),
    }))
}

#[cfg(not(target_os = "macos"))]
fn init(_: Init) -> Result<()> {
    Err(anyhow!("`harar key init` needs a Mac with a Secure Enclave; on Linux create the key with `age-keygen`"))
}

#[cfg(not(target_os = "macos"))]
fn recover(_: Recover) -> Result<()> {
    Err(anyhow!("`harar key recover` needs a Mac with a Secure Enclave"))
}

#[cfg(target_os = "macos")]
fn read_passphrase(input: SecretInput, confirm: bool) -> Result<age::secrecy::SecretString> {
    let prompt = "Recovery passphrase";
    let value = if confirm { input.read_confirmed(prompt)? } else { input.read(prompt)? };
    if confirm && value.chars().count() < MIN_PASSPHRASE_CHARS {
        return Err(anyhow!("the recovery passphrase needs at least {MIN_PASSPHRASE_CHARS} characters"));
    }
    Ok(age::secrecy::SecretString::from(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        key: Key,
    }

    #[test]
    fn passphrase_is_never_an_argument() {
        assert!(Cli::try_parse_from(["harar", "init", "--passphrase", "leak"]).is_err());
        assert!(Cli::try_parse_from(["harar", "init", "--secret-stdin"]).is_ok());
        assert!(Cli::try_parse_from(["harar", "recover", "--secret-file", "/run/p"]).is_ok());
    }

    #[test]
    fn recovery_path_defaults_next_to_the_key() {
        let paths = Paths { path: Some(PathBuf::from("/x/master.key")), recovery: None };
        assert_eq!(paths.resolve().1, PathBuf::from("/x/master.key.recovery.age"));
    }
}
