use anyhow::{Context, Result, anyhow};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DEFAULT_MASTER_KEY_PATH: &str = "/etc/gild/vault-master.key";

pub trait MasterKeySource {
    fn load(&self) -> Result<Option<age::x25519::Identity>>;
}

pub struct FileMasterKeySource {
    path: PathBuf,
}

impl FileMasterKeySource {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

impl MasterKeySource for FileMasterKeySource {
    fn load(&self) -> Result<Option<age::x25519::Identity>> {
        load_master_key_file(&self.path).map(Some)
    }
}

#[allow(dead_code)]
pub struct TpmMasterKeySource;

impl MasterKeySource for TpmMasterKeySource {
    fn load(&self) -> Result<Option<age::x25519::Identity>> {
        // TODO(tana#375 Component C): load a TPM-sealed age identity when
        // demon has Intel PTT/fTPM enabled and tss-esapi is wired in.
        Ok(None)
    }
}

#[allow(dead_code)]
pub struct YubiKeyMasterKeySource;

impl MasterKeySource for YubiKeyMasterKeySource {
    fn load(&self) -> Result<Option<age::x25519::Identity>> {
        // TODO(tana#375 Component C): load an age identity escrowed via
        // YubiKey PIV once the hardware-backed fallback tier is implemented.
        Ok(None)
    }
}

pub fn load_master_key() -> Result<age::x25519::Identity> {
    let path = std::env::var_os("GILD_VAULT_MASTER_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MASTER_KEY_PATH));
    FileMasterKeySource::new(path)
        .load()?
        .ok_or_else(|| anyhow!("master key source returned none"))
}

pub(crate) fn load_master_key_file(path: &Path) -> Result<age::x25519::Identity> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(anyhow!(
                "missing gild-vault master key at {}; run `gild vault init` before starting gild-vault",
                path.display()
            ));
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };

    let metadata = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o400 {
        return Err(anyhow!(
            "{} must be mode 0400; found {:03o}",
            path.display(),
            mode
        ));
    }

    contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .ok_or_else(|| anyhow!("{} does not contain an age x25519 identity", path.display()))?
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|err| anyhow!("parse age x25519 identity from {}: {err}", path.display()))
}
