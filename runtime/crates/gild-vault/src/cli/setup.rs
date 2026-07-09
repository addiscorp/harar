use crate::cli::print_json;
use anyhow::{Context, Result};
use clap::Args;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct Setup {
    #[arg(long, default_value = "/var/lib/gild-vault")]
    state_dir: PathBuf,
    #[arg(long, default_value = "/var/log")]
    log_dir: PathBuf,
}

pub async fn run(cmd: Setup) -> Result<()> {
    fs::create_dir_all(&cmd.state_dir)
        .with_context(|| format!("create {}", cmd.state_dir.display()))?;
    fs::set_permissions(&cmd.state_dir, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod 0700 {}", cmd.state_dir.display()))?;
    fs::create_dir_all(&cmd.log_dir)
        .with_context(|| format!("create {}", cmd.log_dir.display()))?;
    print_json(&serde_json::json!({
        "ok": true,
        "state_dir": cmd.state_dir,
        "log_dir": cmd.log_dir
    }))
}
