use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

mod master_key;

const DEFAULT_SOCKET_PATH: &str = "/run/gild-vault.sock";
const DEFAULT_STATE_PATH: &str = "/var/lib/gild-vault/keys.age";
const DEFAULT_AUDIT_LOG_PATH: &str = "/var/log/gild-vault.log";
const VERSION: &str = env!("CARGO_PKG_VERSION");
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone)]
struct Config {
    socket_path: PathBuf,
    state_path: PathBuf,
    audit_log_path: PathBuf,
}

impl Config {
    fn from_env_and_args() -> Self {
        let mut config = Self {
            socket_path: env_path("GILD_VAULT_SOCKET", DEFAULT_SOCKET_PATH),
            state_path: env_path("GILD_VAULT_STATE_PATH", DEFAULT_STATE_PATH),
            audit_log_path: env_path("GILD_VAULT_AUDIT_LOG", DEFAULT_AUDIT_LOG_PATH),
        };

        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--socket" => {
                    if let Some(value) = args.next() {
                        config.socket_path = PathBuf::from(value);
                    }
                }
                "--state-path" => {
                    if let Some(value) = args.next() {
                        config.state_path = PathBuf::from(value);
                    }
                }
                "--audit-log" => {
                    if let Some(value) = args.next() {
                        config.audit_log_path = PathBuf::from(value);
                    }
                }
                _ => {}
            }
        }

        config
    }
}

#[derive(Debug)]
struct AppState {
    keys: Mutex<HashMap<String, String>>,
    started_at: Instant,
    state_path: PathBuf,
    audit_log_path: PathBuf,
    master_recipient: age::x25519::Recipient,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "lowercase")]
enum VaultRequest {
    Get {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shop_id: Option<String>,
    },
    Put {
        key: String,
        value: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shop_id: Option<String>,
    },
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shop_id: Option<String>,
    },
    Delete {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        shop_id: Option<String>,
    },
    Health,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct VaultResponse {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uptime_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_count: Option<usize>,
}

impl VaultResponse {
    fn ok() -> Self {
        Self {
            ok: true,
            value: None,
            keys: None,
            error: None,
            version: None,
            uptime_seconds: None,
            key_count: None,
        }
    }

    fn error(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            value: None,
            keys: None,
            error: Some(error.into()),
            version: None,
            uptime_seconds: None,
            key_count: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerCred {
    uid: u32,
    pid: i32,
    username: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Decision {
    Allow,
    Deny(&'static str),
}

#[derive(Debug, Serialize)]
struct AuditEvent<'a> {
    ts: u64,
    op: &'a str,
    key: Option<&'a str>,
    peer_uid: u32,
    peer_pid: i32,
    result: &'a str,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = Config::from_env_and_args();
    let master_key = master_key::load_master_key()?;
    let master_recipient = master_key.to_public();
    let keys = load_keys(&config.state_path, &master_key)?;
    let state = Arc::new(AppState {
        keys: Mutex::new(keys),
        started_at: Instant::now(),
        state_path: config.state_path.clone(),
        audit_log_path: config.audit_log_path.clone(),
        master_recipient,
    });

    serve(config, state).await
}

async fn serve(config: Config, state: Arc<AppState>) -> Result<()> {
    let listener = match systemd_listener()? {
        Some(listener) => listener,
        None => {
            prepare_socket(&config.socket_path)?;
            let listener = UnixListener::bind(&config.socket_path)
                .with_context(|| format!("bind {}", config.socket_path.display()))?;
            fs::set_permissions(&config.socket_path, fs::Permissions::from_mode(0o660))
                .with_context(|| format!("chmod 0660 {}", config.socket_path.display()))?;
            try_chgrp(&config.socket_path, "gild");
            listener
        }
    };

    eprintln!("gild-vault listening on {}", config.socket_path.display());

    loop {
        let (stream, _) = listener.accept().await.context("accept unix connection")?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, state).await {
                eprintln!("gild-vault connection error: {err:#}");
            }
        });
    }
}

fn systemd_listener() -> Result<Option<UnixListener>> {
    if std::env::var("LISTEN_FDS").as_deref() != Ok("1") {
        return Ok(None);
    }
    if let Ok(pid) = std::env::var("LISTEN_PID")
        && pid.parse::<u32>().ok() != Some(std::process::id())
    {
        return Ok(None);
    }

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(3) };
    listener
        .set_nonblocking(true)
        .context("set inherited socket nonblocking")?;
    UnixListener::from_std(listener)
        .context("adopt inherited systemd socket")
        .map(Some)
}

async fn handle_connection(mut stream: UnixStream, state: Arc<AppState>) -> Result<()> {
    let peer = peer_credentials(&stream).context("read SO_PEERCRED")?;
    let request_bytes = read_request_bytes(&mut stream).await?;
    if request_bytes.len() > MAX_REQUEST_BYTES {
        if is_http_request(&request_bytes) {
            write_http_json(
                &mut stream,
                413,
                serde_json::json!({ "error": "request too large" }),
            )
            .await?;
            return Ok(());
        }
        write_json(&mut stream, &VaultResponse::error("request_too_large")).await?;
        return Ok(());
    }

    if is_http_request(&request_bytes) {
        let response = handle_http_request(&state, &peer, &request_bytes).await;
        match response {
            Ok(reply) => write_http_json(&mut stream, reply.status, reply.body).await?,
            Err(err) => {
                eprintln!("gild-vault HTTP request error: {err:#}");
                write_http_json(
                    &mut stream,
                    400,
                    serde_json::json!({ "error": "bad request" }),
                )
                .await?;
            }
        }
        return Ok(());
    }

    let request: VaultRequest = match serde_json::from_slice(&request_bytes) {
        Ok(request) => request,
        Err(_) => {
            write_json(&mut stream, &VaultResponse::error("bad_request")).await?;
            return Ok(());
        }
    };

    let response = handle_request(&state, &peer, request).await?;
    write_json(&mut stream, &response).await?;
    Ok(())
}

async fn handle_http_request(
    state: &AppState,
    peer: &PeerCred,
    request_bytes: &[u8],
) -> Result<HttpReply> {
    let request = parse_http_request(request_bytes)?;
    if request.method != "GET" {
        return Ok(HttpReply::json(405, "method not allowed"));
    }

    let Some(key) = request
        .path
        .strip_prefix("/v1/secret/")
        .filter(|key| !key.is_empty())
    else {
        return Ok(HttpReply::json(404, "not found"));
    };

    let response = handle_request(
        state,
        peer,
        VaultRequest::Get {
            key: key.to_string(),
            shop_id: None,
        },
    )
    .await?;

    match (response.ok, response.value, response.error.as_deref()) {
        (true, Some(value), _) => Ok(HttpReply::json_value(
            200,
            serde_json::json!({ "value": value }),
        )),
        (false, _, Some("not_found")) => Ok(HttpReply::json(404, "secret not found")),
        (false, _, Some("forbidden")) => Ok(HttpReply::json(403, "forbidden")),
        (false, _, Some(error)) => Ok(HttpReply::json(500, error)),
        _ => Ok(HttpReply::json(500, "invalid response")),
    }
}

async fn handle_request(
    state: &AppState,
    peer: &PeerCred,
    request: VaultRequest,
) -> Result<VaultResponse> {
    let op = request.op_name();
    let key_for_audit = request.key().map(ToOwned::to_owned);
    let decision = authorize(peer, &request);
    if let Decision::Deny(reason) = decision {
        audit(state, op, key_for_audit.as_deref(), peer, reason)?;
        return Ok(VaultResponse::error(reason));
    }

    let response = match request {
        VaultRequest::Get { key, .. } => {
            let keys = state.keys.lock().await;
            match keys.get(&key) {
                Some(value) => VaultResponse {
                    value: Some(value.clone()),
                    ..VaultResponse::ok()
                },
                None => VaultResponse::error("not_found"),
            }
        }
        VaultRequest::Put { key, value, .. } => {
            let mut keys = state.keys.lock().await;
            keys.insert(key, value);
            persist_keys(&state.state_path, &state.master_recipient, &keys)?;
            VaultResponse::ok()
        }
        VaultRequest::List { shop_id } => {
            let keys = state.keys.lock().await;
            let mut visible = keys
                .keys()
                .filter(|key| can_read_key(peer, key, shop_id.as_deref()))
                .cloned()
                .collect::<Vec<_>>();
            visible.sort();
            VaultResponse {
                keys: Some(visible),
                ..VaultResponse::ok()
            }
        }
        VaultRequest::Delete { key, .. } => {
            let mut keys = state.keys.lock().await;
            keys.remove(&key);
            persist_keys(&state.state_path, &state.master_recipient, &keys)?;
            VaultResponse::ok()
        }
        VaultRequest::Health => {
            let keys = state.keys.lock().await;
            VaultResponse {
                version: Some(VERSION.to_string()),
                uptime_seconds: Some(state.started_at.elapsed().as_secs()),
                key_count: Some(keys.len()),
                ..VaultResponse::ok()
            }
        }
    };

    let result = if response.ok {
        "ok"
    } else {
        response.error.as_deref().unwrap_or("error")
    };
    audit(state, op, key_for_audit.as_deref(), peer, result)?;
    Ok(response)
}

async fn read_request_bytes(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut request_bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.context("read request")?;
        if read == 0 {
            break;
        }
        request_bytes.extend_from_slice(&chunk[..read]);
        if request_bytes.len() > MAX_REQUEST_BYTES {
            break;
        }
        // Bun and node:net clients do not reliably half-close Unix sockets, so
        // process complete JSON requests without waiting for EOF.
        if !is_http_request(&request_bytes)
            && serde_json::from_slice::<serde_json::Value>(&request_bytes).is_ok()
        {
            break;
        }
    }
    Ok(request_bytes)
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
}

#[derive(Debug, PartialEq, Eq)]
struct HttpReply {
    status: u16,
    body: serde_json::Value,
}

impl HttpReply {
    fn json(status: u16, error: &str) -> Self {
        Self::json_value(status, serde_json::json!({ "error": error }))
    }

    fn json_value(status: u16, body: serde_json::Value) -> Self {
        Self { status, body }
    }
}

fn is_http_request(request_bytes: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST ".as_slice(),
        b"PUT ".as_slice(),
        b"PATCH ".as_slice(),
        b"DELETE ".as_slice(),
        b"HEAD ".as_slice(),
        b"OPTIONS ".as_slice(),
        b"TRACE ".as_slice(),
    ]
    .iter()
    .any(|prefix| request_bytes.starts_with(prefix))
}

fn parse_http_request(request_bytes: &[u8]) -> Result<HttpRequest> {
    let raw = std::str::from_utf8(request_bytes).context("HTTP request is not UTF-8")?;
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

impl VaultRequest {
    fn op_name(&self) -> &'static str {
        match self {
            Self::Get { .. } => "get",
            Self::Put { .. } => "put",
            Self::List { .. } => "list",
            Self::Delete { .. } => "delete",
            Self::Health => "health",
        }
    }

    fn key(&self) -> Option<&str> {
        match self {
            Self::Get { key, .. } | Self::Put { key, .. } | Self::Delete { key, .. } => Some(key),
            Self::List { .. } | Self::Health => None,
        }
    }
}

fn authorize(peer: &PeerCred, request: &VaultRequest) -> Decision {
    match request {
        VaultRequest::Health => Decision::Allow,
        VaultRequest::Get { key, shop_id } => {
            if can_read_key(peer, key, shop_id.as_deref()) {
                Decision::Allow
            } else {
                Decision::Deny("forbidden")
            }
        }
        VaultRequest::List { .. } => Decision::Allow,
        VaultRequest::Put { key, shop_id, .. } | VaultRequest::Delete { key, shop_id } => {
            if is_admin(peer)
                || (is_shop_key(key)
                    && is_runtime(peer)
                    && runtime_shop_scope_allows(key, shop_id.as_deref()))
            {
                Decision::Allow
            } else {
                Decision::Deny("forbidden")
            }
        }
    }
}

fn can_read_key(peer: &PeerCred, key: &str, request_shop_id: Option<&str>) -> bool {
    if is_admin(peer) {
        return true;
    }

    if is_shop_key(key) && is_runtime(peer) {
        return runtime_shop_scope_allows(key, request_shop_id);
    }

    let Some(username) = peer.username.as_deref() else {
        return false;
    };
    let Some(slug) = username.strip_prefix("agent-") else {
        return false;
    };
    let prefix = format!("AGENT_{}_", slug.replace('-', "_").to_ascii_uppercase());
    key.starts_with(&prefix)
}

fn is_shop_key(key: &str) -> bool {
    key.starts_with("shops/")
}

fn runtime_shop_scope_allows(key: &str, request_shop_id: Option<&str>) -> bool {
    let Some(request_shop_id) = request_shop_id else {
        // TODO(deka#60): remove this lenient rollout path after every runtime
        // caller sends shop_id-scoped vault requests.
        return true;
    };

    key_shop_id(key).is_some_and(|key_shop_id| key_shop_id == request_shop_id)
}

fn key_shop_id(key: &str) -> Option<&str> {
    let rest = key.strip_prefix("shops/")?;
    let (shop_id, secret_name) = rest.split_once('/')?;
    if shop_id.is_empty() || secret_name.is_empty() {
        return None;
    }
    Some(shop_id)
}

fn is_runtime(peer: &PeerCred) -> bool {
    matches!(
        peer.username.as_deref(),
        Some("gild-runtime") | Some("deka") | Some("deka-platform") | Some("tana-deka-platform")
    )
}

fn is_admin(peer: &PeerCred) -> bool {
    peer.uid == 0
        || peer.uid == unsafe { libc::geteuid() }
        || peer.username.as_deref() == Some("root")
        || peer.username.as_deref() == Some("sami")
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(anyhow!(std::io::Error::last_os_error()));
    }

    Ok(PeerCred {
        uid: cred.uid,
        pid: cred.pid,
        username: username_for_uid(cred.uid),
    })
}

fn username_for_uid(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let raw_uid = fields.next()?;
        if raw_uid.parse::<u32>().ok()? == uid {
            Some(name.to_string())
        } else {
            None
        }
    })
}

fn load_keys(path: &Path, identity: &age::x25519::Identity) -> Result<HashMap<String, String>> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.is_empty() {
                return Ok(HashMap::new());
            }

            let plaintext = age::decrypt(identity, &bytes).with_context(|| {
                format!(
                    "decrypt gild-vault state at {}; refusing to boot because encrypted state could not be read",
                    path.display()
                )
            })?;
            serde_json::from_slice(&plaintext).context("decode gild-vault state")
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn persist_keys(
    path: &Path,
    recipient: &age::x25519::Recipient,
    keys: &HashMap<String, String>,
) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("state path must have a parent"));
    };
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))
        .with_context(|| format!("chmod 0750 {}", parent.display()))?;
    try_chown(parent, Some("gild-vault"), Some("gild"));

    let plaintext = serde_json::to_vec(keys).context("encode gild-vault state")?;
    let ciphertext =
        age::encrypt(recipient, &plaintext).context("encrypt gild-vault state with age")?;

    let tmp_path = path.with_extension(format!("age.tmp.{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&tmp_path)
        .with_context(|| format!("open {}", tmp_path.display()))?;
    try_chown(&tmp_path, Some("gild-vault"), None);
    file.write_all(&ciphertext)
        .context("write encrypted gild-vault state")?;
    file.sync_all().context("sync gild-vault state")?;
    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))?;
    try_chown(path, Some("gild-vault"), None);
    fs::File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("sync {}", parent.display()))?;
    Ok(())
}

fn audit(
    state: &AppState,
    op: &str,
    key: Option<&str>,
    peer: &PeerCred,
    result: &str,
) -> Result<()> {
    append_audit(
        &state.audit_log_path,
        &AuditEvent {
            ts: now_epoch_seconds()?,
            op,
            key,
            peer_uid: peer.uid,
            peer_pid: peer.pid,
            result,
        },
    )
}

fn append_audit(path: &Path, event: &AuditEvent<'_>) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o640)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    serde_json::to_writer(&mut file, event).context("encode audit event")?;
    file.write_all(b"\n").context("write audit newline")?;
    Ok(())
}

async fn write_json(stream: &mut UnixStream, response: &VaultResponse) -> Result<()> {
    let mut bytes = serde_json::to_vec(response).context("encode response")?;
    bytes.push(b'\n');
    stream.write_all(&bytes).await.context("write response")?;
    Ok(())
}

async fn write_http_json(
    stream: &mut UnixStream,
    status: u16,
    body: serde_json::Value,
) -> Result<()> {
    let body = body.to_string();
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\ncache-control: no-store\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write HTTP response")?;
    Ok(())
}

fn prepare_socket(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            fs::remove_file(path).with_context(|| format!("remove stale {}", path.display()))?;
        }
        Ok(_) => return Err(anyhow!("{} exists and is not a socket", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    }
    Ok(())
}

fn try_chgrp(path: &Path, group: &str) {
    if let Some(gid) = gid_for_group(group) {
        chown_raw(path, u32::MAX, gid);
    }
}

fn try_chown(path: &Path, user: Option<&str>, group: Option<&str>) {
    let uid = user.and_then(uid_for_user).unwrap_or(u32::MAX);
    let gid = group.and_then(gid_for_group).unwrap_or(u32::MAX);
    if uid != u32::MAX || gid != u32::MAX {
        chown_raw(path, uid, gid);
    }
}

fn chown_raw(path: &Path, uid: u32, gid: u32) {
    let bytes = path.as_os_str().as_bytes();
    let mut c_path = Vec::with_capacity(bytes.len() + 1);
    c_path.extend_from_slice(bytes);
    c_path.push(0);
    unsafe {
        libc::chown(c_path.as_ptr().cast(), uid, gid);
    }
}

fn uid_for_user(user: &str) -> Option<u32> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let raw_uid = fields.next()?;
        if name == user {
            raw_uid.parse::<u32>().ok()
        } else {
            None
        }
    })
}

fn gid_for_group(group: &str) -> Option<u32> {
    let groups = fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        let _password = fields.next()?;
        let raw_gid = fields.next()?;
        if name == group {
            raw_gid.parse::<u32>().ok()
        } else {
            None
        }
    })
}

fn env_path(name: &str, default: &str) -> PathBuf {
    std::env::var_os(name)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

fn now_epoch_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::net::UnixStream;

    fn peer(uid: u32, username: &str) -> PeerCred {
        PeerCred {
            uid,
            pid: 1234,
            username: Some(username.to_string()),
        }
    }

    fn test_state(dir: &Path) -> AppState {
        let master_key = age::x25519::Identity::generate();
        AppState {
            keys: Mutex::new(HashMap::from([
                ("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string()),
                ("AGENT_AMINA_TOKEN".to_string(), "amina-secret".to_string()),
                ("AGENT_IDRIS_TOKEN".to_string(), "idris-secret".to_string()),
            ])),
            started_at: Instant::now() - Duration::from_secs(5),
            state_path: dir.join("keys.age"),
            audit_log_path: dir.join("audit.log"),
            master_recipient: master_key.to_public(),
        }
    }

    fn ten_test_keys() -> HashMap<String, String> {
        (0..10)
            .map(|idx| (format!("KEY_{idx}"), format!("value-{idx}")))
            .collect()
    }

    #[test]
    fn encrypted_state_round_trips_ten_keys() {
        let dir = tempdir().unwrap();
        let master_key = age::x25519::Identity::generate();
        let keys = ten_test_keys();
        let path = dir.path().join("keys.age");

        persist_keys(&path, &master_key.to_public(), &keys).unwrap();
        let loaded = load_keys(&path, &master_key).unwrap();

        assert_eq!(loaded, keys);
        assert_ne!(fs::read(&path).unwrap(), serde_json::to_vec(&keys).unwrap());
    }

    #[test]
    fn empty_state_file_loads_as_empty_key_map() {
        let dir = tempdir().unwrap();
        let master_key = age::x25519::Identity::generate();
        let path = dir.path().join("keys.age");
        fs::write(&path, []).unwrap();

        let loaded = load_keys(&path, &master_key).unwrap();

        assert!(loaded.is_empty());
    }

    #[test]
    fn missing_master_key_file_has_operator_error() {
        let dir = tempdir().unwrap();
        let err = match master_key::load_master_key_file(&dir.path().join("missing.key")) {
            Ok(_) => panic!("missing master key should fail"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("gild vault init"));
    }

    #[test]
    fn wrong_master_key_refuses_to_load_existing_state() {
        let dir = tempdir().unwrap();
        let correct = age::x25519::Identity::generate();
        let wrong = age::x25519::Identity::generate();
        let path = dir.path().join("keys.age");
        let keys = HashMap::from([("ANTHROPIC_API_KEY".to_string(), "sk-test".to_string())]);
        persist_keys(&path, &correct.to_public(), &keys).unwrap();

        let err = load_keys(&path, &wrong).unwrap_err();

        assert!(err.to_string().contains("refusing to boot"));
    }

    #[test]
    fn persist_then_reload_keeps_all_keys() {
        let dir = tempdir().unwrap();
        let master_key = age::x25519::Identity::generate();
        let path = dir.path().join("state").join("keys.age");
        let keys = HashMap::from([
            ("A".to_string(), "one".to_string()),
            ("B".to_string(), "two".to_string()),
            ("C".to_string(), "three".to_string()),
        ]);

        persist_keys(&path, &master_key.to_public(), &keys).unwrap();
        let loaded = load_keys(&path, &master_key).unwrap();

        assert_eq!(loaded, keys);
        assert_eq!(
            fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o750
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn parses_request_shapes() {
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"get","key":"ANTHROPIC_API_KEY"}"#)
                .unwrap(),
            VaultRequest::Get {
                key: "ANTHROPIC_API_KEY".to_string(),
                shop_id: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(
                r#"{"op":"get","key":"shops/shop_a/SECRET","shop_id":"shop_a"}"#
            )
            .unwrap(),
            VaultRequest::Get {
                key: "shops/shop_a/SECRET".to_string(),
                shop_id: Some("shop_a".to_string()),
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"put","key":"FOO","value":"bar"}"#)
                .unwrap(),
            VaultRequest::Put {
                key: "FOO".to_string(),
                value: "bar".to_string(),
                shop_id: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(
                r#"{"op":"put","key":"shops/shop_a/SECRET","value":"bar","shop_id":"shop_a"}"#
            )
            .unwrap(),
            VaultRequest::Put {
                key: "shops/shop_a/SECRET".to_string(),
                value: "bar".to_string(),
                shop_id: Some("shop_a".to_string()),
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"list"}"#).unwrap(),
            VaultRequest::List { shop_id: None }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"list","shop_id":"shop_a"}"#).unwrap(),
            VaultRequest::List {
                shop_id: Some("shop_a".to_string())
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"delete","key":"FOO"}"#).unwrap(),
            VaultRequest::Delete {
                key: "FOO".to_string(),
                shop_id: None,
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(
                r#"{"op":"delete","key":"shops/shop_a/SECRET","shop_id":"shop_a"}"#
            )
            .unwrap(),
            VaultRequest::Delete {
                key: "shops/shop_a/SECRET".to_string(),
                shop_id: Some("shop_a".to_string()),
            }
        );
        assert_eq!(
            serde_json::from_str::<VaultRequest>(r#"{"op":"health"}"#).unwrap(),
            VaultRequest::Health
        );
    }

    #[test]
    fn serializes_response_shapes() {
        let get = VaultResponse {
            value: Some("sk-test".to_string()),
            ..VaultResponse::ok()
        };
        assert_eq!(
            serde_json::to_value(get).unwrap(),
            serde_json::json!({"ok": true, "value": "sk-test"})
        );

        assert_eq!(
            serde_json::to_value(VaultResponse::error("not_found")).unwrap(),
            serde_json::json!({"ok": false, "error": "not_found"})
        );

        let list = VaultResponse {
            keys: Some(vec!["A".to_string(), "B".to_string()]),
            ..VaultResponse::ok()
        };
        assert_eq!(
            serde_json::to_value(list).unwrap(),
            serde_json::json!({"ok": true, "keys": ["A", "B"]})
        );
    }

    #[test]
    fn policy_allows_root_and_sami_to_read_everything() {
        assert!(can_read_key(&peer(0, "root"), "ANTHROPIC_API_KEY", None));
        assert!(can_read_key(&peer(501, "sami"), "ANTHROPIC_API_KEY", None));
        assert_eq!(
            authorize(
                &peer(501, "sami"),
                &VaultRequest::Put {
                    key: "FOO".to_string(),
                    value: "bar".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn policy_limits_agent_to_matching_prefix() {
        let amina = peer(1001, "agent-amina");
        assert!(can_read_key(&amina, "AGENT_AMINA_API_KEY", None));
        assert!(!can_read_key(&amina, "AGENT_IDRIS_API_KEY", None));
        assert!(!can_read_key(&amina, "ANTHROPIC_API_KEY", None));
        assert_eq!(
            authorize(
                &amina,
                &VaultRequest::Put {
                    key: "AGENT_AMINA_API_KEY".to_string(),
                    value: "secret".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Deny("forbidden")
        );
    }

    #[test]
    fn policy_allows_runtime_to_read_shop_keys() {
        let runtime = peer(1002, "gild-runtime");
        assert!(can_read_key(
            &runtime,
            "shops/shop_alpha/STRIPE_SECRET_KEY",
            None
        ));
        assert!(!can_read_key(&runtime, "AGENT_AMINA_API_KEY", None));
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Get {
                    key: "shops/shop_alpha/STRIPE_SECRET_KEY".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn policy_scopes_runtime_read_to_request_shop_id() {
        let runtime = peer(1002, "gild-runtime");
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Get {
                    key: "shops/shop_a/SECRET".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Get {
                    key: "shops/shop_b/SECRET".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Deny("forbidden")
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Get {
                    key: "shops/shop_b/SECRET".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Allow
        );
    }

    #[tokio::test]
    async fn runtime_list_with_shop_id_only_returns_that_shop() {
        let dir = tempdir().unwrap();
        let master_key = age::x25519::Identity::generate();
        let state = AppState {
            keys: Mutex::new(HashMap::from([
                ("shops/shop_a/SECRET".to_string(), "a".to_string()),
                ("shops/shop_b/SECRET".to_string(), "b".to_string()),
                ("AGENT_AMINA_TOKEN".to_string(), "amina".to_string()),
            ])),
            started_at: Instant::now(),
            state_path: dir.path().join("keys.age"),
            audit_log_path: dir.path().join("audit.log"),
            master_recipient: master_key.to_public(),
        };

        let response = handle_request(
            &state,
            &peer(1002, "gild-runtime"),
            VaultRequest::List {
                shop_id: Some("shop_a".to_string()),
            },
        )
        .await
        .unwrap();

        assert_eq!(response.keys, Some(vec!["shops/shop_a/SECRET".to_string()]));
    }

    #[test]
    fn policy_allows_runtime_to_write_shop_keys() {
        let runtime = peer(1002, "gild-runtime");
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Put {
                    key: "shops/shop_alpha/STRIPE_SECRET_KEY".to_string(),
                    value: "sk-test".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Delete {
                    key: "shops/shop_alpha/STRIPE_SECRET_KEY".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn policy_scopes_runtime_write_to_request_shop_id() {
        let runtime = peer(1002, "gild-runtime");
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Put {
                    key: "shops/shop_a/SECRET".to_string(),
                    value: "a".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Delete {
                    key: "shops/shop_a/SECRET".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Put {
                    key: "shops/shop_b/SECRET".to_string(),
                    value: "b".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Deny("forbidden")
        );
        assert_eq!(
            authorize(
                &runtime,
                &VaultRequest::Delete {
                    key: "shops/shop_b/SECRET".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Deny("forbidden")
        );
    }

    #[test]
    fn policy_keeps_admin_write_access_with_shop_scope() {
        let admin = peer(501, "sami");
        assert_eq!(
            authorize(
                &admin,
                &VaultRequest::Put {
                    key: "shops/shop_b/SECRET".to_string(),
                    value: "b".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                &admin,
                &VaultRequest::Delete {
                    key: "shops/shop_b/SECRET".to_string(),
                    shop_id: Some("shop_a".to_string()),
                }
            ),
            Decision::Allow
        );
    }

    #[test]
    fn policy_blocks_agent_from_shop_keys() {
        let amina = peer(1001, "agent-amina");
        assert!(!can_read_key(
            &amina,
            "shops/shop_alpha/STRIPE_SECRET_KEY",
            None
        ));
        assert_eq!(
            authorize(
                &amina,
                &VaultRequest::Get {
                    key: "shops/shop_alpha/STRIPE_SECRET_KEY".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Deny("forbidden")
        );
        assert_eq!(
            authorize(
                &amina,
                &VaultRequest::Put {
                    key: "shops/shop_alpha/STRIPE_SECRET_KEY".to_string(),
                    value: "sk-test".to_string(),
                    shop_id: None,
                }
            ),
            Decision::Deny("forbidden")
        );
    }

    #[tokio::test]
    async fn handles_health_request() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let response = handle_request(&state, &peer(1001, "agent-amina"), VaultRequest::Health)
            .await
            .unwrap();

        assert!(response.ok);
        assert_eq!(response.version.as_deref(), Some("0.1.0"));
        assert_eq!(response.key_count, Some(3));
        assert!(response.uptime_seconds.unwrap() >= 5);
    }

    #[tokio::test]
    async fn http_get_missing_secret_returns_404() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let reply = handle_http_request(
            &state,
            &peer(0, "root"),
            b"GET /v1/secret/MISSING_SECRET HTTP/1.1\r\nHost: gild-vault\r\n\r\n",
        )
        .await
        .unwrap();

        assert_eq!(reply.status, 404);
        assert_eq!(
            reply.body,
            serde_json::json!({ "error": "secret not found" })
        );
    }

    #[tokio::test]
    async fn http_get_existing_secret_returns_value() {
        let dir = tempdir().unwrap();
        let state = test_state(dir.path());
        let reply = handle_http_request(
            &state,
            &peer(0, "root"),
            b"GET /v1/secret/ANTHROPIC_API_KEY HTTP/1.1\r\nHost: gild-vault\r\n\r\n",
        )
        .await
        .unwrap();

        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, serde_json::json!({ "value": "sk-test" }));
    }

    #[tokio::test]
    async fn socket_health_flow_reads_peer_credentials() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("gild-vault.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let state = Arc::new(test_state(dir.path()));

        let server = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                let peer = peer_credentials(&stream).unwrap();
                assert_eq!(peer.uid, unsafe { libc::geteuid() });
                handle_connection(stream, state).await.unwrap();
            }
        });

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(br#"{"op":"health"}"#).await.unwrap();
        client.shutdown().await.unwrap();

        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        let response: VaultResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(response.ok);
        assert_eq!(response.version.as_deref(), Some("0.1.0"));

        server.await.unwrap();
    }

    #[tokio::test]
    async fn socket_put_preserves_state_dir_permissions() {
        let dir = tempdir().unwrap();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let socket_path = dir.path().join("gild-vault.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let state = Arc::new(test_state(dir.path()));

        let server = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                handle_connection(stream, state).await.unwrap();
            }
        });

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client
            .write_all(br#"{"op":"put","key":"FOO","value":"bar"}"#)
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        let response: VaultResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(response.ok);

        server.await.unwrap();

        let mode = fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o750);
    }

    #[tokio::test]
    async fn socket_health_flow_responds_without_client_half_close() {
        let dir = tempdir().unwrap();
        let socket_path = dir.path().join("gild-vault.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let state = Arc::new(test_state(dir.path()));

        let server = tokio::spawn({
            let state = Arc::clone(&state);
            async move {
                let (stream, _) = listener.accept().await.unwrap();
                handle_connection(stream, state).await.unwrap();
            }
        });

        let mut client = UnixStream::connect(&socket_path).await.unwrap();
        client.write_all(br#"{"op":"health"}"#).await.unwrap();

        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
            .await
            .expect("daemon should respond without waiting for EOF")
            .unwrap();
        let response: VaultResponse = serde_json::from_slice(&bytes).unwrap();
        assert!(response.ok);
        assert_eq!(response.version.as_deref(), Some("0.1.0"));

        server.await.unwrap();
    }
}
