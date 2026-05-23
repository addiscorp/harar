use anyhow::{Context, Result, anyhow, bail};
mod attestation;

use attestation::AttestationProvider;
use serde::{Deserialize, Serialize};
use std::fs;
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

const DEFAULT_SOCKET_PATH: &str = "/run/tana-vault.sock";
const DEFAULT_CONFIG_DIR: &str = "/etc/tana-vault-agent";
const TOKEN_TTL_SECONDS: u64 = 300;
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_READ_TIMEOUT_MS: u64 = 1_000;
const MAX_SECRET_KEY_LEN: usize = 256;

#[derive(Clone)]
struct AppState {
    config: AgentConfig,
    workloads: WorkloadsConfig,
    attestation: AttestationProvider,
    client: reqwest::Client,
    connection_limit: Arc<Semaphore>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentConfig {
    #[serde(default = "default_socket_path")]
    socket_path: PathBuf,
    vault_url: Option<String>,
    #[serde(default)]
    allow_stub_secrets: bool,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_read_timeout_ms")]
    read_timeout_ms: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            socket_path: PathBuf::from(DEFAULT_SOCKET_PATH),
            vault_url: None,
            allow_stub_secrets: false,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            read_timeout_ms: DEFAULT_READ_TIMEOUT_MS,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct WorkloadsConfig {
    workloads: Vec<WorkloadRule>,
}

#[derive(Debug, Clone, Deserialize)]
struct WorkloadRule {
    identity: String,
    namespace: String,
    exe: PathBuf,
    #[serde(default)]
    cgroup_contains: Vec<String>,
    #[serde(default)]
    systemd_unit: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    exe: PathBuf,
    cgroup: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedWorkload {
    identity: String,
    namespace: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultClaims {
    sub: String,
    scope: String,
    iat: u64,
    exp: u64,
}

#[derive(Debug, Deserialize)]
struct VaultSecretResponse {
    value: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_dir = resolve_config_dir()?;
    let state = Arc::new(load_state(&config_dir).await?);
    serve(state).await
}

async fn load_state(config_dir: &Path) -> Result<AppState> {
    validate_root_owned_dir(config_dir)?;
    let config = load_agent_config(&config_dir.join("agent.toml"))?;
    let workloads = load_workloads(&config_dir.join("workloads.toml"))?;
    validate_agent_config(&config)?;
    let attestation = AttestationProvider::load(config_dir)?;

    Ok(AppState {
        connection_limit: Arc::new(Semaphore::new(config.max_connections)),
        config,
        workloads,
        attestation,
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .context("build HTTP client")?,
    })
}

async fn serve(state: Arc<AppState>) -> Result<()> {
    prepare_socket_path(&state.config.socket_path)?;
    let listener = UnixListener::bind(&state.config.socket_path)
        .with_context(|| format!("bind {}", state.config.socket_path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&state.config.socket_path, fs::Permissions::from_mode(0o666))
        .with_context(|| format!("chmod 0666 {}", state.config.socket_path.display()))?;

    eprintln!(
        "gild-vault listening on {}",
        state.config.socket_path.display()
    );

    loop {
        let (stream, _) = listener.accept().await.context("accept unix connection")?;
        let state = Arc::clone(&state);
        let permit = match Arc::clone(&state.connection_limit).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tokio::spawn(async move {
                    let _ = reject_connection(stream, 429, "too many requests").await;
                });
                continue;
            }
        };
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_connection(stream, state).await {
                eprintln!("gild-vault connection error: {err:#}");
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, state: Arc<AppState>) -> Result<()> {
    let peer = peer_process_identity(&stream)?;
    let workload = resolve_workload(&state.workloads, &peer).ok_or_else(|| {
        anyhow!(
            "no workload mapping for pid={} exe={} cgroup={:?}",
            peer.pid,
            peer.exe.display(),
            peer.cgroup
        )
    })?;

    let request = timeout(
        Duration::from_millis(state.config.read_timeout_ms),
        read_http_request(&mut stream),
    )
    .await
    .context("request header read timed out")??;
    let response = match handle_request(&state, &workload, &request).await {
        Ok(reply) => http_response(reply.status, &reply.body),
        Err(err) => {
            eprintln!("gild-vault request error: {err:#}");
            http_response(
                503,
                &serde_json::json!({ "error": "gild-vault request failed" }).to_string(),
            )
        }
    };
    stream
        .write_all(response.as_bytes())
        .await
        .context("write response")?;
    Ok(())
}

async fn handle_request(
    state: &AppState,
    workload: &ResolvedWorkload,
    request: &HttpRequest,
) -> Result<ServiceReply> {
    if request.method != "GET" {
        return Ok(ServiceReply::json(405, "method not allowed"));
    }

    let key = request
        .path
        .strip_prefix("/v1/secret/")
        .filter(|key| !key.is_empty())
        .ok_or_else(|| anyhow!("unknown route {}", request.path))?;
    validate_secret_key(key)?;

    let token = state.attestation.mint_jwt(workload, now_epoch_seconds()?)?;
    eprintln!(
        "minted vault token for sub={} scope=vault:read:{}/* key={}",
        workload.identity, workload.namespace, key
    );

    match fetch_from_vault(state, key, &token).await {
        Ok(value) => Ok(ServiceReply::json_value(
            200,
            serde_json::json!({ "value": value }),
        )),
        Err(err) if state.config.allow_stub_secrets => {
            eprintln!("vault upstream unavailable, returning configured dev stub: {err:#}");
            Ok(ServiceReply::json_value(
                200,
                serde_json::json!({ "value": format!("stub-{key}") }),
            ))
        }
        Err(err) => Err(err).context("vault secret fetch failed"),
    }
}

async fn fetch_from_vault(state: &AppState, key: &str, token: &str) -> Result<String> {
    let mut url = state
        .config
        .vault_url
        .as_deref()
        .ok_or_else(|| anyhow!("vault_url is not configured"))
        .and_then(parse_vault_url)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("vault_url cannot be a base URL"))?;
        segments.pop_if_empty();
        segments.extend(["v1", "secret", key]);
    }
    let response = state
        .client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .context("send vault request")?
        .error_for_status()
        .context("vault returned error status")?;
    let body = response
        .json::<VaultSecretResponse>()
        .await
        .context("decode vault secret response")?;
    Ok(body.value)
}

#[derive(Debug, PartialEq, Eq)]
struct ServiceReply {
    status: u16,
    body: String,
}

impl ServiceReply {
    fn json(status: u16, error: &str) -> Self {
        Self::json_value(status, serde_json::json!({ "error": error }))
    }

    fn json_value(status: u16, value: serde_json::Value) -> Self {
        Self {
            status,
            body: value.to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
}

async fn read_http_request(stream: &mut UnixStream) -> Result<HttpRequest> {
    let mut buf = vec![0; 8192];
    let mut used = 0;
    loop {
        if used == buf.len() {
            bail!("request headers too large");
        }
        let n = stream
            .read(&mut buf[used..])
            .await
            .context("read request")?;
        if n == 0 {
            bail!("client closed before request headers");
        }
        used += n;
        if buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let raw = std::str::from_utf8(&buf[..used]).context("request is not UTF-8")?;
    parse_http_request(raw)
}

fn parse_http_request(raw: &str) -> Result<HttpRequest> {
    let request_line = raw
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty HTTP request"))?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP method"))?
        .to_string();
    let path = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP path"))?
        .to_string();
    Ok(HttpRequest { method, path })
}

fn http_response(status: u16, body: &str) -> String {
    let reason = match status {
        200 => "OK",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        500 => "Internal Server Error",
        _ => "OK",
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\ncache-control: no-store\r\n\r\n{body}",
        body.len()
    )
}

fn load_agent_config(path: &Path) -> Result<AgentConfig> {
    validate_optional_root_owned_config_file(path)?;
    match fs::read_to_string(path) {
        Ok(raw) => toml::from_str(&raw).with_context(|| format!("parse {}", path.display())),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(AgentConfig::default()),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn load_workloads(path: &Path) -> Result<WorkloadsConfig> {
    validate_root_owned_config_file(path, 0o644)?;
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))
}

fn load_hs256_key(path: &Path) -> Result<Vec<u8>> {
    load_hs256_key_for_owner(path, 0, 0)
}

fn load_hs256_key_for_owner(path: &Path, uid: u32, gid: u32) -> Result<Vec<u8>> {
    let file = open_secret_file_for_owner(path, uid, gid)?;
    let metadata = file
        .metadata()
        .with_context(|| format!("fstat {}", path.display()))?;
    #[cfg(unix)]
    {
        let mode = metadata.mode() & 0o777;
        if mode != 0o600 {
            bail!("{} must have mode 0600, found {:03o}", path.display(), mode);
        }
    }
    let mut key = Vec::new();
    let mut file = file;
    use std::io::Read;
    file.read_to_end(&mut key)
        .with_context(|| format!("read {}", path.display()))?;
    if key.is_empty() {
        bail!("{} is empty", path.display());
    }
    Ok(key)
}

fn resolve_workload(
    config: &WorkloadsConfig,
    process: &ProcessIdentity,
) -> Option<ResolvedWorkload> {
    config
        .workloads
        .iter()
        .find(|rule| workload_matches(rule, process))
        .map(|rule| ResolvedWorkload {
            identity: rule.identity.clone(),
            namespace: rule.namespace.clone(),
        })
}

fn workload_matches(rule: &WorkloadRule, process: &ProcessIdentity) -> bool {
    if rule.exe != process.exe {
        return false;
    }

    if let Some(unit) = &rule.systemd_unit
        && !process.cgroup.contains(unit)
    {
        return false;
    }

    rule.cgroup_contains
        .iter()
        .all(|needle| process.cgroup.contains(needle))
}

fn now_epoch_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_secs())
}

fn peer_process_identity(stream: &UnixStream) -> Result<ProcessIdentity> {
    let pid = peer_pid(stream)?;
    let exe = fs::read_link(format!("/proc/{pid}/exe")).context("read peer /proc/PID/exe")?;
    let cgroup =
        fs::read_to_string(format!("/proc/{pid}/cgroup")).context("read peer /proc/PID/cgroup")?;
    Ok(ProcessIdentity { pid, exe, cgroup })
}

fn peer_pid(stream: &UnixStream) -> Result<u32> {
    let fd = stream.as_raw_fd();
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("getsockopt SO_PEERCRED");
    }
    u32::try_from(cred.pid).context("peer pid is negative")
}

fn prepare_socket_path(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            if metadata.file_type().is_socket() {
                fs::remove_file(path)
                    .with_context(|| format!("remove stale socket {}", path.display()))?;
                return Ok(());
            }
            bail!("{} exists and is not a socket", path.display());
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn default_socket_path() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET_PATH)
}

fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

fn default_read_timeout_ms() -> u64 {
    DEFAULT_READ_TIMEOUT_MS
}

fn resolve_config_dir() -> Result<PathBuf> {
    match std::env::var("TANA_VAULT_AGENT_CONFIG_DIR") {
        Ok(value) if cfg!(debug_assertions) => Ok(PathBuf::from(value)),
        Ok(_) => bail!("TANA_VAULT_AGENT_CONFIG_DIR is not honored in release builds"),
        Err(_) => Ok(PathBuf::from(DEFAULT_CONFIG_DIR)),
    }
}

fn validate_agent_config(config: &AgentConfig) -> Result<()> {
    if config.max_connections == 0 {
        bail!("max_connections must be greater than zero");
    }
    if config.read_timeout_ms == 0 || config.read_timeout_ms > 30_000 {
        bail!("read_timeout_ms must be between 1 and 30000");
    }
    if let Some(raw) = config.vault_url.as_deref() {
        parse_vault_url(raw)?;
    }
    Ok(())
}

fn parse_vault_url(raw: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(raw).with_context(|| format!("parse vault_url {raw:?}"))?;
    match url.scheme() {
        "https" => Ok(url),
        "http" if is_loopback_url(&url) => Ok(url),
        "http" => bail!("vault_url must use https outside loopback"),
        scheme => bail!("vault_url scheme {scheme:?} is not supported"),
    }
}

fn is_loopback_url(url: &reqwest::Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost") | Some("127.0.0.1") | Some("::1") | Some("[::1]")
    )
}

fn validate_secret_key(key: &str) -> Result<()> {
    if key.len() > MAX_SECRET_KEY_LEN {
        bail!("secret key is too long");
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        bail!("secret key contains unsupported characters");
    }
    Ok(())
}

async fn reject_connection(mut stream: UnixStream, status: u16, error: &str) -> Result<()> {
    let body = serde_json::json!({ "error": error }).to_string();
    stream
        .write_all(http_response(status, &body).as_bytes())
        .await
        .context("write rejection response")
}

fn validate_root_owned_dir(path: &Path) -> Result<()> {
    validate_secure_path_metadata(path, SecurePathKind::Directory, 0, 0, 0o755)
}

fn validate_optional_root_owned_config_file(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_root_owned_config_file(path, 0o644),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn validate_root_owned_config_file(path: &Path, max_mode: u32) -> Result<()> {
    validate_secure_path_metadata(path, SecurePathKind::RegularFile, 0, 0, max_mode)
}

fn open_secret_file_for_owner(path: &Path, uid: u32, gid: u32) -> Result<File> {
    let file = open_no_follow(path)?;
    validate_open_file_metadata(path, &file, uid, gid, 0o600, true)?;
    Ok(file)
}

#[derive(Debug, Clone, Copy)]
enum SecurePathKind {
    Directory,
    RegularFile,
}

fn validate_secure_path_metadata(
    path: &Path,
    kind: SecurePathKind,
    uid: u32,
    gid: u32,
    max_mode: u32,
) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("stat {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("{} must not be a symlink", path.display());
    }
    match kind {
        SecurePathKind::Directory if !metadata.is_dir() => {
            bail!("{} must be a directory", path.display())
        }
        SecurePathKind::RegularFile if !metadata.is_file() => {
            bail!("{} must be a regular file", path.display())
        }
        _ => {}
    }
    validate_unix_metadata(path, &metadata, uid, gid, max_mode, false)
}

fn validate_open_file_metadata(
    path: &Path,
    file: &File,
    uid: u32,
    gid: u32,
    max_mode: u32,
    reject_hardlinks: bool,
) -> Result<()> {
    let metadata = file
        .metadata()
        .with_context(|| format!("fstat {}", path.display()))?;
    if !metadata.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    validate_unix_metadata(path, &metadata, uid, gid, max_mode, reject_hardlinks)
}

fn validate_unix_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    uid: u32,
    gid: u32,
    max_mode: u32,
    reject_hardlinks: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        if metadata.uid() != uid || metadata.gid() != gid {
            bail!(
                "{} must be owned by uid {} gid {}, found uid {} gid {}",
                path.display(),
                uid,
                gid,
                metadata.uid(),
                metadata.gid()
            );
        }
        let mode = metadata.mode() & 0o777;
        if mode & !max_mode != 0 {
            bail!(
                "{} has too-permissive mode {:03o}; max allowed {:03o}",
                path.display(),
                mode,
                max_mode
            );
        }
        if reject_hardlinks && metadata.nlink() != 1 {
            bail!("{} must not have hard links", path.display());
        }
    }
    Ok(())
}

fn open_no_follow(path: &Path) -> Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options
        .open(path)
        .with_context(|| format!("open {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};

    fn test_uid_gid() -> (u32, u32) {
        #[cfg(unix)]
        {
            (unsafe { libc::geteuid() }, unsafe { libc::getegid() })
        }
        #[cfg(not(unix))]
        {
            (0, 0)
        }
    }

    fn test_state(config: AgentConfig) -> AppState {
        AppState {
            config,
            workloads: WorkloadsConfig { workloads: vec![] },
            attestation: AttestationProvider::Hs256Dev(Arc::new(b"dev-secret".to_vec())),
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(100))
                .build()
                .expect("client"),
            connection_limit: Arc::new(Semaphore::new(1)),
        }
    }

    #[test]
    fn resolves_workload_by_exe_and_cgroup() {
        let config = WorkloadsConfig {
            workloads: vec![
                WorkloadRule {
                    identity: "prod/deka.gg".to_string(),
                    namespace: "prod/deka.gg".to_string(),
                    exe: PathBuf::from("/srv/deka/bin/deka"),
                    cgroup_contains: vec!["system.slice".to_string()],
                    systemd_unit: Some("gg.tana.deka-platform.service".to_string()),
                },
                WorkloadRule {
                    identity: "prod/linkhash".to_string(),
                    namespace: "prod/linkhash".to_string(),
                    exe: PathBuf::from("/srv/linkhash/bin/server"),
                    cgroup_contains: Vec::new(),
                    systemd_unit: None,
                },
            ],
        };
        let process = ProcessIdentity {
            pid: 123,
            exe: PathBuf::from("/srv/deka/bin/deka"),
            cgroup: "0::/system.slice/gg.tana.deka-platform.service".to_string(),
        };

        let resolved = resolve_workload(&config, &process).expect("workload should resolve");

        assert_eq!(
            resolved,
            ResolvedWorkload {
                identity: "prod/deka.gg".to_string(),
                namespace: "prod/deka.gg".to_string(),
            }
        );
    }

    #[test]
    fn rejects_workload_when_unit_does_not_match() {
        let config = WorkloadsConfig {
            workloads: vec![WorkloadRule {
                identity: "prod/deka.gg".to_string(),
                namespace: "prod/deka.gg".to_string(),
                exe: PathBuf::from("/srv/deka/bin/deka"),
                cgroup_contains: Vec::new(),
                systemd_unit: Some("gg.tana.deka-platform.service".to_string()),
            }],
        };
        let process = ProcessIdentity {
            pid: 123,
            exe: PathBuf::from("/srv/deka/bin/deka"),
            cgroup: "0::/system.slice/other.service".to_string(),
        };

        assert!(resolve_workload(&config, &process).is_none());
    }

    #[test]
    fn mints_hs256_jwt_with_vault_scope() {
        let workload = ResolvedWorkload {
            identity: "prod/deka.gg".to_string(),
            namespace: "prod/deka.gg".to_string(),
        };

        let token = AttestationProvider::Hs256Dev(Arc::new(b"dev-secret".to_vec()))
            .mint_jwt(&workload, 1_779_420_000)
            .expect("mint jwt");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = false;
        let data = decode::<VaultClaims>(
            &token,
            &DecodingKey::from_secret(b"dev-secret"),
            &validation,
        )
        .expect("decode jwt");

        assert_eq!(data.claims.sub, "prod/deka.gg");
        assert_eq!(data.claims.scope, "vault:read:prod/deka.gg/*");
        assert_eq!(data.claims.iat, 1_779_420_000);
        assert_eq!(data.claims.exp, 1_779_420_000 + TOKEN_TTL_SECONDS);
    }

    #[test]
    fn requires_dev_key_mode_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("dev-key");
        fs::write(&key_path, b"secret").expect("write key");
        let (uid, gid) = test_uid_gid();
        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).expect("chmod key");

        #[cfg(unix)]
        assert!(load_hs256_key_for_owner(&key_path, uid, gid).is_err());

        #[cfg(unix)]
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod key");
        assert_eq!(
            load_hs256_key_for_owner(&key_path, uid, gid).expect("load key"),
            b"secret"
        );
    }

    #[test]
    fn rejects_symlink_dev_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("real-key");
        let link = dir.path().join("dev-key");
        fs::write(&target, b"secret").expect("write key");
        #[cfg(unix)]
        {
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod key");
            std::os::unix::fs::symlink(&target, &link).expect("symlink key");
            let (uid, gid) = test_uid_gid();

            assert!(load_hs256_key_for_owner(&link, uid, gid).is_err());
        }
    }

    #[test]
    fn rejects_hardlinked_dev_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let key_path = dir.path().join("dev-key");
        let hardlink = dir.path().join("dev-key-copy");
        fs::write(&key_path, b"secret").expect("write key");
        #[cfg(unix)]
        {
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod key");
            fs::hard_link(&key_path, &hardlink).expect("hardlink key");
            let (uid, gid) = test_uid_gid();

            assert!(load_hs256_key_for_owner(&key_path, uid, gid).is_err());
        }
    }

    #[test]
    fn validates_config_dir_ownership_and_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (uid, gid) = test_uid_gid();
        #[cfg(unix)]
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");

        assert!(
            validate_secure_path_metadata(dir.path(), SecurePathKind::Directory, uid, gid, 0o755)
                .is_ok()
        );

        #[cfg(unix)]
        {
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o775)).expect("chmod dir");
            assert!(
                validate_secure_path_metadata(
                    dir.path(),
                    SecurePathKind::Directory,
                    uid,
                    gid,
                    0o755
                )
                .is_err()
            );
        }
    }

    #[test]
    fn release_config_dir_env_override_fails_closed() {
        if !cfg!(debug_assertions) {
            unsafe {
                std::env::set_var("TANA_VAULT_AGENT_CONFIG_DIR", "/tmp/tana-vault-agent-test")
            };
            let result = resolve_config_dir();
            unsafe { std::env::remove_var("TANA_VAULT_AGENT_CONFIG_DIR") };

            assert!(result.is_err());
        }
    }

    #[test]
    fn validates_vault_url_transport() {
        assert!(parse_vault_url("https://vault.tana.gg").is_ok());
        assert!(parse_vault_url("http://localhost:9501").is_ok());
        assert!(parse_vault_url("http://127.0.0.1:9501").is_ok());
        assert!(parse_vault_url("http://vault.tana.gg").is_err());
        assert!(parse_vault_url("ftp://vault.tana.gg").is_err());
    }

    #[test]
    fn validates_secret_keys_before_upstream_dispatch() {
        assert!(validate_secret_key("STRIPE_SECRET_KEY").is_ok());
        assert!(validate_secret_key("stripe-secret.v2").is_ok());
        assert!(validate_secret_key("STRIPE?x=1").is_err());
        assert!(validate_secret_key("../STRIPE").is_err());
        assert!(validate_secret_key("STRIPE%2fSECRET").is_err());
    }

    #[tokio::test]
    async fn fails_closed_when_vault_url_missing() {
        let state = test_state(AgentConfig::default());
        let workload = ResolvedWorkload {
            identity: "prod/deka.gg".to_string(),
            namespace: "prod/deka.gg".to_string(),
        };
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/v1/secret/STRIPE_SECRET_KEY".to_string(),
        };

        assert!(handle_request(&state, &workload, &request).await.is_err());
    }

    #[tokio::test]
    async fn stub_secrets_require_explicit_dev_flag() {
        let config = AgentConfig {
            allow_stub_secrets: true,
            ..AgentConfig::default()
        };
        let state = test_state(config);
        let workload = ResolvedWorkload {
            identity: "prod/deka.gg".to_string(),
            namespace: "prod/deka.gg".to_string(),
        };
        let request = HttpRequest {
            method: "GET".to_string(),
            path: "/v1/secret/STRIPE_SECRET_KEY".to_string(),
        };

        let reply = handle_request(&state, &workload, &request)
            .await
            .expect("stub reply");

        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, r#"{"value":"stub-STRIPE_SECRET_KEY"}"#);
    }

    #[tokio::test]
    async fn read_http_request_times_out_for_slow_client() {
        let (mut client, mut server) = UnixStream::pair().expect("socket pair");
        let read = timeout(Duration::from_millis(25), read_http_request(&mut server)).await;
        client
            .write_all(b"GET /v1/secret/KEY")
            .await
            .expect("write");

        assert!(read.is_err());
    }

    #[test]
    fn semaphore_rejects_connections_over_budget() {
        let semaphore = Arc::new(Semaphore::new(1));
        let first = Arc::clone(&semaphore).try_acquire_owned().expect("permit");

        assert!(Arc::clone(&semaphore).try_acquire_owned().is_err());

        drop(first);
        assert!(Arc::clone(&semaphore).try_acquire_owned().is_ok());
    }
}
