use age::secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DEFAULT_SOCKET: &str = "/run/gild-vault.sock";

#[derive(Debug, Deserialize)]
struct MintedToken {
    token: String,
    jti: String,
    exp: u64,
    aud: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct VerifyTokenResponse {
    valid: bool,
    sub: Option<String>,
    jti: Option<String>,
    exp: Option<u64>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    kty: String,
    kid: String,
    crv: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
    x: String,
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(prefix: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create test dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct VaultDaemon {
    child: Child,
    cleanup_socket: Option<PathBuf>,
}

impl Drop for VaultDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(socket) = &self.cleanup_socket {
            let _ = fs::remove_file(socket);
        }
    }
}

#[test]
fn harar_real_topology_mint_verify_revoke_jwks_over_socket() {
    let dir = TestDir::new("harar-real-topology");
    let socket = dir.path().join("gild-vault.sock");
    let _daemon = spawn_vault(dir.path(), &socket, None);
    wait_for_connectable_socket(&socket);

    let jwks: Jwks = harar_json(["jwks", "--socket", socket_str(&socket)]);
    assert_single_public_jwk(&jwks);

    let minted: MintedToken = harar_json([
        "mint",
        "--socket",
        socket_str(&socket),
        "--template",
        "service",
        "--subject",
        "service:gild",
        "--ttl-seconds",
        "30",
    ]);
    assert_eq!(minted.aud, "linkhash");
    assert_eq!(minted.scopes, vec!["service:auth"]);
    assert!(!minted.token.is_empty());
    assert!(!minted.jti.is_empty());

    let verified: VerifyTokenResponse = harar_json([
        "verify",
        "--socket",
        socket_str(&socket),
        "--token",
        &minted.token,
        "--audience",
        "linkhash",
        "--subject",
        "service:gild",
    ]);
    assert!(verified.valid, "{verified:?}");
    assert_eq!(verified.sub.as_deref(), Some("service:gild"));
    assert_eq!(verified.jti.as_deref(), Some(minted.jti.as_str()));
    assert_eq!(verified.exp, Some(minted.exp));
    assert_eq!(verified.error, None);

    let wrong_aud: VerifyTokenResponse = harar_json([
        "verify",
        "--socket",
        socket_str(&socket),
        "--token",
        &minted.token,
        "--audience",
        "deka",
    ]);
    assert!(!wrong_aud.valid, "{wrong_aud:?}");
    assert_eq!(wrong_aud.error.as_deref(), Some("wrong_audience"));

    let forged = forge_signature(&minted.token);
    let forged_verify: VerifyTokenResponse = harar_json([
        "verify",
        "--socket",
        socket_str(&socket),
        "--token",
        &forged,
        "--audience",
        "linkhash",
    ]);
    assert!(!forged_verify.valid, "{forged_verify:?}");
    assert_eq!(forged_verify.error.as_deref(), Some("bad_signature"));

    let _: serde_json::Value = harar_json([
        "revoke",
        "--socket",
        socket_str(&socket),
        "--jti",
        &minted.jti,
    ]);
    let revoked: VerifyTokenResponse = harar_json([
        "verify",
        "--socket",
        socket_str(&socket),
        "--token",
        &minted.token,
        "--audience",
        "linkhash",
    ]);
    assert!(!revoked.valid, "{revoked:?}");
    assert_eq!(revoked.error.as_deref(), Some("revoked"));

    let short_lived: MintedToken = harar_json([
        "mint",
        "--socket",
        socket_str(&socket),
        "--template",
        "service",
        "--subject",
        "service:gild-expiring",
        "--ttl-seconds",
        "1",
    ]);
    thread::sleep(Duration::from_secs(2));
    let expired: VerifyTokenResponse = harar_json([
        "verify",
        "--socket",
        socket_str(&socket),
        "--token",
        &short_lived.token,
        "--audience",
        "linkhash",
    ]);
    assert!(!expired.valid, "{expired:?}");
    assert_eq!(expired.error.as_deref(), Some("expired"));
}

#[test]
fn harar_no_socket_flag_uses_env_selected_socket_over_real_daemon() {
    let dir = TestDir::new("harar-no-socket-flag");
    let socket = dir.path().join("gild-vault.sock");
    let _daemon = spawn_vault(dir.path(), &socket, None);
    wait_for_connectable_socket(&socket);

    let socket_env = [("HARAR_SOCKET", socket_str(&socket))];
    let jwks: Jwks = harar_json_with_env(["jwks"], &socket_env);
    assert_single_public_jwk(&jwks);

    let minted: MintedToken = harar_json_with_env(
        [
            "mint",
            "--template",
            "service",
            "--subject",
            "service:gild-no-flag",
            "--ttl-seconds",
            "30",
        ],
        &socket_env,
    );

    let verified: VerifyTokenResponse = harar_json_with_env(
        [
            "verify",
            "--token",
            &minted.token,
            "--audience",
            "linkhash",
            "--subject",
            "service:gild-no-flag",
        ],
        &socket_env,
    );
    assert!(verified.valid, "{verified:?}");
    assert_eq!(verified.jti.as_deref(), Some(minted.jti.as_str()));

    let _: serde_json::Value = harar_json_with_env(["revoke", "--jti", &minted.jti], &socket_env);
}

#[test]
fn harar_default_socket_path_works_without_socket_overrides_when_available() {
    let _default_daemon = match default_socket_case() {
        DefaultSocketCase::ExistingConnectable => None,
        DefaultSocketCase::Spawned { daemon, dir } => {
            wait_for_connectable_socket(Path::new(DEFAULT_SOCKET));
            Some((daemon, dir))
        }
        DefaultSocketCase::Unavailable(reason) => {
            eprintln!("blocked: default socket path unavailable: {reason}");
            return;
        }
    };

    let jwks: Jwks = harar_json_without_socket_env(["jwks"]);
    assert_single_public_jwk(&jwks);

    let minted: MintedToken = harar_json_without_socket_env([
        "mint",
        "--template",
        "service",
        "--subject",
        "service:gild-default",
        "--ttl-seconds",
        "30",
    ]);
    let verified: VerifyTokenResponse = harar_json_without_socket_env([
        "verify",
        "--token",
        &minted.token,
        "--audience",
        "linkhash",
        "--subject",
        "service:gild-default",
    ]);

    assert!(verified.valid, "{verified:?}");
    assert_eq!(verified.jti.as_deref(), Some(minted.jti.as_str()));

    let _: serde_json::Value = harar_json_without_socket_env(["revoke", "--jti", &minted.jti]);
}

enum DefaultSocketCase {
    ExistingConnectable,
    Spawned { daemon: VaultDaemon, dir: TestDir },
    Unavailable(String),
}

fn default_socket_case() -> DefaultSocketCase {
    let path = Path::new(DEFAULT_SOCKET);
    if UnixStream::connect(path).is_ok() {
        return DefaultSocketCase::ExistingConnectable;
    }

    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            return DefaultSocketCase::Unavailable(format!(
                "{DEFAULT_SOCKET} exists but is not connectable"
            ));
        }
        Ok(_) => {
            return DefaultSocketCase::Unavailable(format!(
                "{DEFAULT_SOCKET} exists and is not a socket"
            ));
        }
        Err(err) if err.kind() != std::io::ErrorKind::NotFound => {
            return DefaultSocketCase::Unavailable(format!("stat {DEFAULT_SOCKET}: {err}"));
        }
        Err(_) => {}
    }

    let Some(parent) = path.parent() else {
        return DefaultSocketCase::Unavailable("default socket has no parent".to_string());
    };
    if !is_writable_dir(parent) {
        return DefaultSocketCase::Unavailable(format!("{} is not writable", parent.display()));
    }

    let dir = TestDir::new("harar-default-socket");
    let daemon = spawn_vault(dir.path(), path, Some(path.to_path_buf()));
    DefaultSocketCase::Spawned { daemon, dir }
}

fn spawn_vault(dir: &Path, socket: &Path, cleanup_socket: Option<PathBuf>) -> VaultDaemon {
    let master_key = dir.join("vault-master.key");
    let replication_token = dir.join("vault-replication-token");
    let state_path = dir.join("keys.age");
    let audit_log = dir.join("audit.log");
    let signing_key = dir.join("harar-signing.key");
    write_master_key(&master_key);
    fs::write(&replication_token, "test-replication-token\n").expect("write replication token");

    let mut command = Command::new(gild_vault_bin());
    if socket != Path::new(DEFAULT_SOCKET) {
        command.args(["--socket", socket_str(socket)]);
    }
    let child = command
        .args([
            "--state-path",
            path_str(&state_path),
            "--audit-log",
            path_str(&audit_log),
            "--replication-token-file",
            path_str(&replication_token),
            "--signing-key-file",
            path_str(&signing_key),
        ])
        .env("GILD_VAULT_MASTER_KEY_PATH", &master_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gild-vault daemon");

    VaultDaemon {
        child,
        cleanup_socket,
    }
}

fn write_master_key(path: &Path) {
    let identity = age::x25519::Identity::generate();
    fs::write(path, format!("{}\n", identity.to_string().expose_secret()))
        .expect("write master key");
    let mut permissions = fs::metadata(path).expect("stat master key").permissions();
    permissions.set_mode(0o400);
    fs::set_permissions(path, permissions).expect("chmod master key");
}

fn wait_for_connectable_socket(socket: &Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut last_error = None;
    while Instant::now() < deadline {
        match UnixStream::connect(socket) {
            Ok(_) => return,
            Err(err) => {
                last_error = Some(err);
                thread::sleep(Duration::from_millis(25));
            }
        }
    }
    panic!(
        "vault socket did not become connectable at {}: {:?}",
        socket.display(),
        last_error
    );
}

fn harar_json<T, I, S>(args: I) -> T
where
    T: DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    run_harar_json(args, &[], [])
}

fn harar_json_with_env<T, I, S>(args: I, envs: &[(&str, &str)]) -> T
where
    T: DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    run_harar_json(args, envs, [])
}

fn harar_json_without_socket_env<T, I, S>(args: I) -> T
where
    T: DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    run_harar_json(
        args,
        &[],
        ["HARAR_SOCKET", "VAULT_SOCKET", "GILD_VAULT_SOCKET"],
    )
}

fn run_harar_json<T, I, S, R>(args: I, envs: &[(&str, &str)], env_removals: R) -> T
where
    T: DeserializeOwned,
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
    R: IntoIterator<Item = &'static str>,
{
    let mut command = Command::new(harar_bin());
    command.args(args);
    for key in env_removals {
        command.env_remove(key);
    }
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("run harar");
    parse_success_json(output)
}

fn parse_success_json<T: DeserializeOwned>(output: Output) -> T {
    assert!(
        output.status.success(),
        "harar exited with {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "parse harar JSON: {err}\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn assert_single_public_jwk(jwks: &Jwks) {
    assert_eq!(jwks.keys.len(), 1, "{jwks:?}");
    let key = &jwks.keys[0];
    assert_eq!(key.kty, "OKP");
    assert_eq!(key.crv, "Ed25519");
    assert_eq!(key.alg, "EdDSA");
    assert_eq!(key.key_use, "sig");
    assert!(key.kid.starts_with("harar-"));
    assert!(!key.x.is_empty());
}

fn forge_signature(token: &str) -> String {
    let mut parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3, "token should have JWT shape");
    let mut signature = parts[2].as_bytes().to_vec();
    let first = signature.first_mut().expect("signature is not empty");
    *first = if *first == b'A' { b'B' } else { b'A' };
    parts[2] = std::str::from_utf8(&signature).expect("signature remains UTF-8");
    parts.join(".")
}

fn is_writable_dir(path: &Path) -> bool {
    let probe = path.join(format!(
        ".harar-write-probe-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before epoch")
            .as_nanos()
    ));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(mut file) => {
            let _ = file.write_all(b"probe");
            let _ = fs::remove_file(probe);
            true
        }
        Err(_) => false,
    }
}

fn gild_vault_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gild-vault")
}

fn harar_bin() -> &'static str {
    env!("CARGO_BIN_EXE_harar")
}

fn socket_str(path: &Path) -> &str {
    path.to_str().expect("socket path is UTF-8")
}

fn path_str(path: &Path) -> &str {
    path.to_str().expect("path is UTF-8")
}
