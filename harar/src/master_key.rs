use age::secrecy::{ExposeSecret, SecretString};
use anyhow::{Context, Result, anyhow};
#[cfg(target_os = "macos")]
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::Serialize;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const DEFAULT_MASTER_KEY_PATH: &str = "/etc/harar/master.key";
#[cfg(target_os = "macos")]
const ENCLAVE_FORMAT: &str = "harar.enclave-master-key@1";
const KEY_FILE_MODE: u32 = 0o400;

/// A master key sealed to a Secure Enclave key. Only the Mac that created
/// `handle` can open `sealed`.
#[cfg(target_os = "macos")]
#[derive(Debug, Serialize, serde::Deserialize)]
struct EnclaveEnvelope {
    format: String,
    /// Enclave-encrypted key handle (base64).
    handle: String,
    /// Uncompressed P-256 public key (base64), for identification.
    public_key: String,
    /// The age identity sealed with ECIES to the enclave key (base64).
    sealed: String,
}

/// How the master key at a path is protected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyTier {
    /// Sealed to this Mac's Secure Enclave.
    SecureEnclave,
    /// A plain age identity file, protected only by file permissions.
    File,
    Missing,
}

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

/// `/etc/harar/master.key` on Linux; the user's Application Support folder on
/// macOS, where harar runs as the signed-in user.
pub fn default_master_key_path() -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/harar/master.key");
    }
    PathBuf::from(DEFAULT_MASTER_KEY_PATH)
}

pub fn default_recovery_path(master_key_path: &Path) -> PathBuf {
    let mut name = master_key_path.as_os_str().to_owned();
    name.push(".recovery.age");
    PathBuf::from(name)
}

pub fn load_master_key() -> Result<age::x25519::Identity> {
    let path = std::env::var_os("GILD_VAULT_MASTER_KEY_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(default_master_key_path);
    FileMasterKeySource::new(path)
        .load()?
        .ok_or_else(|| anyhow!("master key source returned none"))
}

pub(crate) fn load_master_key_file(path: &Path) -> Result<age::x25519::Identity> {
    MasterKeyFile::read(path)?.open()
}

/// A master key file as it was read once. Opening it again never goes back to
/// the path, so a file swapped in later is never the one opened.
pub(crate) struct MasterKeyFile {
    path: PathBuf,
    contents: String,
}

impl MasterKeyFile {
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(anyhow!(
                    "missing harar master key at {}; create one with `age-keygen -o {}` and `chmod 0400` it before starting harar",
                    path.display(),
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
        Ok(MasterKeyFile { path: path.to_path_buf(), contents })
    }

    pub(crate) fn tier(&self) -> KeyTier {
        if self.contents.trim_start().starts_with('{') { KeyTier::SecureEnclave } else { KeyTier::File }
    }

    /// Opens the key. A Secure Enclave key asks the person each time.
    pub(crate) fn open(&self) -> Result<age::x25519::Identity> {
        let path = &self.path;
        if self.tier() == KeyTier::SecureEnclave {
            return open_enclave_envelope(&self.contents, path);
        }
        self.contents
            .lines()
            .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
            .ok_or_else(|| anyhow!("{} does not contain an age x25519 identity", path.display()))?
            .trim()
            .parse::<age::x25519::Identity>()
            .map_err(|err| anyhow!("parse age x25519 identity from {}: {err}", path.display()))
    }
}

pub fn key_tier(path: &Path) -> Result<KeyTier> {
    match fs::read_to_string(path) {
        Ok(contents) if contents.trim_start().starts_with('{') => Ok(KeyTier::SecureEnclave),
        Ok(_) => Ok(KeyTier::File),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(KeyTier::Missing),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

#[cfg(target_os = "macos")]
fn open_enclave_envelope(contents: &str, path: &Path) -> Result<age::x25519::Identity> {
    let envelope: EnclaveEnvelope = serde_json::from_str(contents)
        .with_context(|| format!("parse Secure Enclave master key {}", path.display()))?;
    if envelope.format != ENCLAVE_FORMAT {
        return Err(anyhow!(
            "{} has format {:?}; this harar reads {ENCLAVE_FORMAT:?}",
            path.display(),
            envelope.format
        ));
    }
    let handle = BASE64.decode(&envelope.handle).context("decode key handle")?;
    let sealed = BASE64.decode(&envelope.sealed).context("decode sealed master key")?;
    let key = crate::enclave::EnclaveKey::from_handle(&handle)
        .with_context(|| format!("{} was sealed on a different Mac, or its enclave key is gone; restore it with `harar key recover`", path.display()))?;
    let opened = key.open(&sealed)?;
    let text = std::str::from_utf8(&opened).context("sealed master key is not text")?;
    text.trim()
        .parse::<age::x25519::Identity>()
        .map_err(|err| anyhow!("parse sealed age identity from {}: {err}", path.display()))
}

#[cfg(not(target_os = "macos"))]
fn open_enclave_envelope(_contents: &str, path: &Path) -> Result<age::x25519::Identity> {
    Err(anyhow!(
        "{} is sealed to a Mac's Secure Enclave and can only be opened on that Mac",
        path.display()
    ))
}

/// Creates a new master key sealed to a new Secure Enclave key at `path`, and
/// a recovery copy encrypted to `passphrase` at `recovery_path`. Refuses to
/// overwrite either file.
#[cfg(target_os = "macos")]
pub fn create_enclave_master_key(
    path: &Path,
    recovery_path: &Path,
    passphrase: SecretString,
    presence: crate::enclave::Presence,
) -> Result<age::x25519::Identity> {
    for existing in [path, recovery_path] {
        if existing.exists() {
            return Err(anyhow!("{} already exists; refusing to replace a master key", existing.display()));
        }
    }
    let identity = age::x25519::Identity::generate();
    write_recovery(recovery_path, &identity, passphrase)?;
    if let Err(err) = seal_to_new_enclave_key(path, &identity, presence) {
        let _ = fs::remove_file(recovery_path);
        return Err(err);
    }
    Ok(identity)
}

/// Opens the recovery copy and seals its master key to a new Secure Enclave
/// key on this Mac, at `path`.
#[cfg(target_os = "macos")]
pub fn recover_enclave_master_key(
    recovery_path: &Path,
    passphrase: SecretString,
    path: &Path,
    presence: crate::enclave::Presence,
) -> Result<age::x25519::Identity> {
    if path.exists() {
        return Err(anyhow!("{} already exists; move it away before recovering", path.display()));
    }
    let identity = open_recovery(recovery_path, passphrase)?;
    seal_to_new_enclave_key(path, &identity, presence)?;
    Ok(identity)
}

#[cfg(target_os = "macos")]
fn seal_to_new_enclave_key(
    path: &Path,
    identity: &age::x25519::Identity,
    presence: crate::enclave::Presence,
) -> Result<()> {
    let key = crate::enclave::EnclaveKey::create(presence)?;
    let secret = identity.to_string();
    let envelope = EnclaveEnvelope {
        format: ENCLAVE_FORMAT.to_string(),
        handle: BASE64.encode(key.handle()?),
        public_key: BASE64.encode(key.public_key()?),
        sealed: BASE64.encode(key.seal(secret.expose_secret().as_bytes())?),
    };
    let mut json = serde_json::to_vec_pretty(&envelope)?;
    json.push(b'\n');
    write_new_key_file(path, &json)
}

/// Creates a new master key as a plain age identity file (mode 0400) at
/// `path`, plus a recovery copy. For machines without a Secure Enclave.
pub fn create_file_master_key(
    path: &Path,
    recovery_path: &Path,
    passphrase: SecretString,
) -> Result<age::x25519::Identity> {
    for existing in [path, recovery_path] {
        if existing.exists() {
            return Err(anyhow!("{} already exists; refusing to replace a master key", existing.display()));
        }
    }
    let identity = age::x25519::Identity::generate();
    write_recovery(recovery_path, &identity, passphrase)?;
    if let Err(err) = write_identity_file(path, &identity) {
        let _ = fs::remove_file(recovery_path);
        return Err(err);
    }
    Ok(identity)
}

pub fn recover_file_master_key(
    recovery_path: &Path,
    passphrase: SecretString,
    path: &Path,
) -> Result<age::x25519::Identity> {
    if path.exists() {
        return Err(anyhow!("{} already exists; move it away before recovering", path.display()));
    }
    let identity = open_recovery(recovery_path, passphrase)?;
    write_identity_file(path, &identity)?;
    Ok(identity)
}

fn write_identity_file(path: &Path, identity: &age::x25519::Identity) -> Result<()> {
    let secret = identity.to_string();
    let mut contents = zeroize::Zeroizing::new(secret.expose_secret().as_bytes().to_vec());
    contents.push(b'\n');
    write_new_key_file(path, &contents)
}

pub fn write_recovery(
    recovery_path: &Path,
    identity: &age::x25519::Identity,
    passphrase: SecretString,
) -> Result<()> {
    let recipient = age::scrypt::Recipient::new(passphrase);
    let secret = identity.to_string();
    let encrypted = age::encrypt(&recipient, secret.expose_secret().as_bytes())
        .map_err(|err| anyhow!("encrypt recovery copy: {err}"))?;
    write_new_key_file(recovery_path, &encrypted)
}

pub fn open_recovery(recovery_path: &Path, passphrase: SecretString) -> Result<age::x25519::Identity> {
    let encrypted = fs::read(recovery_path)
        .with_context(|| format!("read recovery copy {}", recovery_path.display()))?;
    let identity = age::scrypt::Identity::new(passphrase);
    let plaintext = zeroize::Zeroizing::new(
        age::decrypt(&identity, &encrypted)
            .map_err(|err| anyhow!("open recovery copy {}: {err}", recovery_path.display()))?,
    );
    std::str::from_utf8(&plaintext)
        .context("recovery copy is not text")?
        .trim()
        .parse::<age::x25519::Identity>()
        .map_err(|err| anyhow!("parse age identity from recovery copy: {err}"))
}

fn write_new_key_file(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restrict {}", parent.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(KEY_FILE_MODE)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn passphrase(text: &str) -> SecretString {
        SecretString::from(text.to_string())
    }

    #[test]
    fn recovery_copy_opens_only_with_its_passphrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("master.key.recovery.age");
        let identity = age::x25519::Identity::generate();
        write_recovery(&path, &identity, passphrase("correct horse battery")).unwrap();

        let opened = open_recovery(&path, passphrase("correct horse battery")).unwrap();
        assert_eq!(opened.to_public().to_string(), identity.to_public().to_string());
        assert!(open_recovery(&path, passphrase("wrong horse battery")).is_err());
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
    }

    #[test]
    fn recovery_copy_never_holds_the_identity_in_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.age");
        let identity = age::x25519::Identity::generate();
        write_recovery(&path, &identity, passphrase("correct horse battery")).unwrap();

        let bytes = fs::read(&path).unwrap();
        let needle = identity.to_string();
        assert!(!bytes.windows(16).any(|w| w == &needle.expose_secret().as_bytes()[..16]));
    }

    #[test]
    fn tier_follows_the_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain.key");
        fs::write(&file, age::x25519::Identity::generate().to_string().expose_secret()).unwrap();

        assert_eq!(key_tier(&file).unwrap(), KeyTier::File);
        assert_eq!(key_tier(&dir.path().join("none")).unwrap(), KeyTier::Missing);
    }

    #[test]
    fn file_master_key_loads_and_recovers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("harar/master.key");
        let recovery = default_recovery_path(&path);
        let created = create_file_master_key(&path, &recovery, passphrase("correct horse battery")).unwrap();

        assert_eq!(key_tier(&path).unwrap(), KeyTier::File);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
        assert_eq!(
            load_master_key_file(&path).unwrap().to_public().to_string(),
            created.to_public().to_string()
        );
        assert!(create_file_master_key(&path, &recovery, passphrase("x")).is_err());

        fs::remove_file(&path).unwrap();
        let recovered = recover_file_master_key(&recovery, passphrase("correct horse battery"), &path).unwrap();
        assert_eq!(recovered.to_public().to_string(), created.to_public().to_string());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn enclave_master_key_loads_and_recovers() {
        if crate::enclave::tests::test_key().is_none() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("harar/master.key");
        let recovery = default_recovery_path(&path);
        let created = create_enclave_master_key(
            &path,
            &recovery,
            passphrase("correct horse battery"),
            crate::enclave::Presence::NotRequired,
        )
        .unwrap();

        assert_eq!(key_tier(&path).unwrap(), KeyTier::SecureEnclave);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
        let loaded = load_master_key_file(&path).unwrap();
        assert_eq!(loaded.to_public().to_string(), created.to_public().to_string());
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(!on_disk.contains("AGE-SECRET-KEY"));

        assert!(
            create_enclave_master_key(&path, &recovery, passphrase("x"), crate::enclave::Presence::NotRequired).is_err(),
            "must refuse to replace an existing master key"
        );

        // Lost enclave key: recover onto a new one from the passphrase copy.
        let moved = dir.path().join("harar/master.key.old");
        fs::rename(&path, &moved).unwrap();
        let recovered = recover_enclave_master_key(
            &recovery,
            passphrase("correct horse battery"),
            &path,
            crate::enclave::Presence::NotRequired,
        )
        .unwrap();
        assert_eq!(recovered.to_public().to_string(), created.to_public().to_string());
        assert_eq!(
            load_master_key_file(&path).unwrap().to_public().to_string(),
            created.to_public().to_string()
        );
        assert_ne!(fs::read_to_string(&path).unwrap(), fs::read_to_string(&moved).unwrap());
    }
}
