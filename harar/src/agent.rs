//! The per-user agent: one per signed-in user, holding that user's vault.
//!
//! It speaks the daemon's socket protocol for `get`, `put`, `list` and
//! `delete`, so `harar_client::VaultClient` works against it unchanged, and
//! adds `status`, `unlock` and `lock`.
//!
//! - Only the user who started the agent may talk to it (kernel-reported uid).
//! - It starts locked. The first request opens the master key, which on a
//!   Secure Enclave key needs the person at the Mac; that approval also covers
//!   the terminal session that asked.
//! - Any other terminal session needs its own approval, which asks again.
//! - After `idle_lock` without use it forgets the key and every approval, and
//!   on macOS it does the same within 15 seconds of the screen locking.

use crate::{PeerCred, VaultResponse, load_keys, peer_credentials, read_request_bytes, write_encrypted_keys};
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "lowercase")]
pub(crate) enum AgentRequest {
    Get { key: String },
    Put { key: String, value: String },
    List,
    Delete { key: String },
    Status,
    Unlock,
    Lock,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct AgentStatus {
    pub unlocked: bool,
    pub approved_sessions: usize,
    /// "secure-enclave" when approvals ask the person; "none" when the master
    /// key is a plain file and nothing can ask.
    pub approvals: String,
}

/// Opens the master key. On a Secure Enclave key this asks the person.
pub(crate) type Unlock = Box<dyn Fn() -> Result<age::x25519::Identity> + Send>;
/// Asks the person to approve a terminal session. Ok(()) means approved.
pub(crate) type Approve = Box<dyn Fn() -> Result<()> + Send>;

struct Unlocked {
    identity: age::x25519::Identity,
    keys: HashMap<String, String>,
}

pub(crate) struct VaultConfig {
    pub state_path: PathBuf,
    pub owner_uid: u32,
    /// Forget the key after this long without any request.
    pub idle_lock: Duration,
    /// Ask a terminal again after this long without a request from it.
    pub session_idle: Duration,
    /// What `status` reports approvals as ("secure-enclave" or "none").
    pub approvals: &'static str,
}

pub(crate) struct Vault {
    state_path: PathBuf,
    owner_uid: u32,
    idle_lock: Duration,
    session_idle: Duration,
    unlock: Unlock,
    approve: Approve,
    approvals: &'static str,
    unlocked: Option<Unlocked>,
    sessions: HashMap<i32, Instant>,
    last_use: Instant,
}

impl Vault {
    pub(crate) fn new(config: VaultConfig, unlock: Unlock, approve: Approve, now: Instant) -> Self {
        Self {
            state_path: config.state_path,
            owner_uid: config.owner_uid,
            idle_lock: config.idle_lock,
            session_idle: config.session_idle,
            unlock,
            approve,
            approvals: config.approvals,
            unlocked: None,
            sessions: HashMap::new(),
            last_use: now,
        }
    }

    /// Forgets the key once the agent has been idle for `idle_lock`, and
    /// approvals of sessions idle for `session_idle`.
    pub(crate) fn expire(&mut self, now: Instant) {
        if self.unlocked.is_some() && now.duration_since(self.last_use) >= self.idle_lock {
            self.lock();
        }
        let session_idle = self.session_idle;
        self.sessions
            .retain(|_, last| now.duration_since(*last) < session_idle);
    }

    pub(crate) fn lock(&mut self) {
        self.unlocked = None;
        self.sessions.clear();
    }

    pub(crate) fn status(&self) -> AgentStatus {
        AgentStatus {
            unlocked: self.unlocked.is_some(),
            approved_sessions: self.sessions.len(),
            approvals: self.approvals.to_string(),
        }
    }

    /// Unlocks if needed and makes sure `session` is approved.
    fn admit(&mut self, session: i32, now: Instant) -> Result<()> {
        if self.unlocked.is_none() {
            let identity = (self.unlock)()?;
            let keys = load_keys(&self.state_path, &identity)?;
            self.unlocked = Some(Unlocked { identity, keys });
            self.sessions.clear();
        } else if !self.sessions.contains_key(&session) {
            (self.approve)()?;
        }
        self.sessions.insert(session, now);
        self.last_use = now;
        Ok(())
    }

    /// The vault's entries, for a caller who is the owner and whose terminal
    /// is approved (asking if needed). Used by the SSH agent.
    pub(crate) fn entries_for(
        &mut self,
        peer: &PeerCred,
        session: i32,
        now: Instant,
    ) -> Result<&HashMap<String, String>> {
        if peer.uid != self.owner_uid {
            return Err(anyhow!("not_owner"));
        }
        self.expire(now);
        self.admit(session, now)?;
        Ok(&self.unlocked.as_ref().expect("admit unlocked the vault").keys)
    }

    pub(crate) fn handle(
        &mut self,
        peer: &PeerCred,
        session: i32,
        request: AgentRequest,
        now: Instant,
    ) -> AgentReply {
        if peer.uid != self.owner_uid {
            return AgentReply::Vault(Box::new(VaultResponse::error("not_owner")));
        }
        self.expire(now);
        match request {
            AgentRequest::Status => return AgentReply::Status(self.status()),
            AgentRequest::Lock => {
                self.lock();
                return AgentReply::Vault(Box::new(VaultResponse::ok()));
            }
            _ => {}
        }
        if let Err(err) = self.admit(session, now) {
            return AgentReply::Vault(Box::new(VaultResponse::error(format!("not_approved: {err:#}"))));
        }
        let unlocked = self.unlocked.as_mut().expect("admit unlocked the vault");
        let response = match request {
            AgentRequest::Unlock => VaultResponse::ok(),
            AgentRequest::Get { key } => match unlocked.keys.get(&key) {
                Some(value) => VaultResponse { value: Some(value.clone()), ..VaultResponse::ok() },
                None => VaultResponse::error("not_found"),
            },
            AgentRequest::List => {
                let mut keys: Vec<String> = unlocked.keys.keys().cloned().collect();
                keys.sort();
                VaultResponse { keys: Some(keys), ..VaultResponse::ok() }
            }
            AgentRequest::Put { key, value } => {
                let mut next = unlocked.keys.clone();
                next.insert(key, value);
                self.persist(next)
            }
            AgentRequest::Delete { key } => {
                let mut next = unlocked.keys.clone();
                if next.remove(&key).is_none() {
                    return AgentReply::Vault(Box::new(VaultResponse::error("not_found")));
                }
                self.persist(next)
            }
            AgentRequest::Status | AgentRequest::Lock => unreachable!("answered above"),
        };
        AgentReply::Vault(Box::new(response))
    }

    /// Writes first, then swaps memory, so memory never holds what disk lacks.
    fn persist(&mut self, next: HashMap<String, String>) -> VaultResponse {
        let unlocked = self.unlocked.as_mut().expect("persist runs unlocked");
        match write_encrypted_keys(&self.state_path, &unlocked.identity.to_public(), &next, None) {
            Ok(()) => {
                unlocked.keys = next;
                VaultResponse::ok()
            }
            Err(err) => VaultResponse::error(format!("persist_failed: {err:#}")),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub(crate) enum AgentReply {
    Vault(Box<VaultResponse>),
    Status(AgentStatus),
}

/// The terminal session a process belongs to. Every process started from one
/// terminal window shares the session of that window's shell.
pub(crate) fn session_of(pid: i32) -> i32 {
    // SAFETY: getsid has no memory-safety preconditions.
    let sid = unsafe { libc::getsid(pid) };
    if sid > 0 { sid } else { pid }
}

/// Default agent socket: in the user's harar folder on macOS, in
/// `$XDG_RUNTIME_DIR/harar` on Linux.
pub(crate) fn default_socket_path() -> PathBuf {
    agent_dir().join("agent.sock")
}

pub(crate) fn default_ssh_socket_path() -> PathBuf {
    agent_dir().join("ssh.sock")
}

pub(crate) fn default_state_path() -> PathBuf {
    agent_dir().join("vault.age")
}

fn agent_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join("Library/Application Support/harar");
    }
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime).join("harar");
    }
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"));
    home.join(".harar")
}

pub(crate) fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `limit` is a valid rlimit for the duration of the call.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
        return Err(anyhow!("disable core dumps: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

pub(crate) fn bind(socket_path: &Path) -> Result<UnixListener> {
    let parent = socket_path
        .parent()
        .ok_or_else(|| anyhow!("socket path {} has no parent", socket_path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
        .with_context(|| format!("restrict {}", parent.display()))?;
    if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
        return Err(anyhow!("an agent is already listening on {}", socket_path.display()));
    }
    // Nothing answers, so any file there is a stale socket from an earlier run.
    let _ = fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", socket_path.display()))?;
    Ok(listener)
}

pub(crate) async fn serve(listener: UnixListener, ssh: UnixListener, vault: Vault) -> Result<()> {
    let vault = Arc::new(Mutex::new(vault));
    tokio::spawn(crate::ssh::serve(ssh, Arc::clone(&vault)));
    let mut tick = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept agent connection")?;
                let vault = Arc::clone(&vault);
                tokio::spawn(async move {
                    if let Err(err) = handle_connection(stream, vault).await {
                        eprintln!("harar agent connection error: {err:#}");
                    }
                });
            }
            _ = tick.tick() => {
                let mut vault = vault.lock().expect("agent state lock");
                if crate::screen::is_locked() == Some(true) {
                    vault.lock();
                } else {
                    vault.expire(Instant::now());
                }
            }
        }
    }
}

async fn handle_connection(mut stream: UnixStream, vault: Arc<Mutex<Vault>>) -> Result<()> {
    let peer = peer_credentials(&stream)?;
    let bytes = read_request_bytes(&mut stream).await?;
    let reply = match serde_json::from_slice::<AgentRequest>(&bytes) {
        Err(_) => AgentReply::Vault(Box::new(VaultResponse::error("bad_request"))),
        Ok(request) => {
            let session = session_of(peer.pid);
            // Unlocking and approving can wait on the person, so keep that
            // off the async workers.
            tokio::task::spawn_blocking(move || {
                vault
                    .lock()
                    .expect("agent state lock")
                    .handle(&peer, session, request, Instant::now())
            })
            .await
            .context("agent request task")?
        }
    };
    let mut out = serde_json::to_vec(&reply).context("encode agent reply")?;
    out.push(b'\n');
    stream.write_all(&out).await.context("write agent reply")?;
    Ok(())
}

/// A LaunchAgent that starts `harar agent` at login and restarts it if it
/// exits. Printed, never installed behind the user's back.
pub(crate) fn launch_agent_plist(program: &Path) -> String {
    let program = xml_escape(&program.display().to_string());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>dev.harar.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>{program}</string>
    <string>agent</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>ProcessType</key>
  <string>Interactive</string>
</dict>
</plist>
"#
    )
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Harness {
        vault: Vault,
        unlocks: Arc<AtomicUsize>,
        approvals: Arc<AtomicUsize>,
        _dir: tempfile::TempDir,
        start: Instant,
    }

    const OWNER: u32 = 501;

    fn harness(approve_ok: bool) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let unlocks = Arc::new(AtomicUsize::new(0));
        let approvals = Arc::new(AtomicUsize::new(0));
        let (u, a) = (Arc::clone(&unlocks), Arc::clone(&approvals));
        let start = Instant::now();
        let vault = Vault::new(
            VaultConfig {
                state_path: dir.path().join("vault.age"),
                owner_uid: OWNER,
                idle_lock: Duration::from_secs(600),
                session_idle: Duration::from_secs(120),
                approvals: "secure-enclave",
            },
            Box::new(move || {
                u.fetch_add(1, Ordering::SeqCst);
                Ok(identity.clone())
            }),
            Box::new(move || {
                a.fetch_add(1, Ordering::SeqCst);
                if approve_ok { Ok(()) } else { Err(anyhow!("declined")) }
            }),
            start,
        );
        Harness { vault, unlocks, approvals, _dir: dir, start }
    }

    fn peer(uid: u32) -> PeerCred {
        PeerCred { uid, pid: 4242, username: None }
    }

    fn put(h: &mut Harness, session: i32, key: &str, value: &str, at: Duration) -> serde_json::Value {
        reply(h, session, AgentRequest::Put { key: key.into(), value: value.into() }, at)
    }

    fn reply(h: &mut Harness, session: i32, request: AgentRequest, at: Duration) -> serde_json::Value {
        let reply = h.vault.handle(&peer(OWNER), session, request, h.start + at);
        serde_json::to_value(reply).unwrap()
    }

    #[test]
    fn first_request_unlocks_and_approves_its_terminal() {
        let mut h = harness(true);
        assert_eq!(put(&mut h, 10, "dev/a", "1", Duration::ZERO)["ok"], true);
        assert_eq!(reply(&mut h, 10, AgentRequest::Get { key: "dev/a".into() }, Duration::from_secs(1))["value"], "1");

        assert_eq!(h.unlocks.load(Ordering::SeqCst), 1);
        assert_eq!(h.approvals.load(Ordering::SeqCst), 0, "unlocking counts as approving that terminal");
    }

    #[test]
    fn another_terminal_must_be_approved_once() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        for second in 1..4 {
            let r = reply(&mut h, 20, AgentRequest::Get { key: "dev/a".into() }, Duration::from_secs(second));
            assert_eq!(r["value"], "1");
        }
        assert_eq!(h.approvals.load(Ordering::SeqCst), 1);
        assert_eq!(h.unlocks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn declined_terminal_gets_nothing() {
        let mut h = harness(false);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        let r = reply(&mut h, 20, AgentRequest::Get { key: "dev/a".into() }, Duration::from_secs(1));

        assert_eq!(r["ok"], false);
        assert!(r.get("value").is_none());
        assert!(r["error"].as_str().unwrap().starts_with("not_approved"));
    }

    #[test]
    fn another_user_is_refused_before_anything_unlocks() {
        let mut h = harness(true);
        let r = serde_json::to_value(h.vault.handle(&peer(OWNER + 1), 10, AgentRequest::List, h.start)).unwrap();

        assert_eq!(r["error"], "not_owner");
        assert_eq!(h.unlocks.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn idle_agent_forgets_the_key_and_approvals() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        h.vault.expire(h.start + Duration::from_secs(601));
        assert_eq!(h.vault.status(), AgentStatus { unlocked: false, approved_sessions: 0, approvals: "secure-enclave".into() });

        let r = reply(&mut h, 10, AgentRequest::Get { key: "dev/a".into() }, Duration::from_secs(602));
        assert_eq!(r["value"], "1", "state survives on disk");
        assert_eq!(h.unlocks.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn idle_terminal_needs_approval_again() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        reply(&mut h, 20, AgentRequest::List, Duration::from_secs(1));
        // Session 10 keeps the agent busy; session 20 goes quiet past session_idle.
        reply(&mut h, 10, AgentRequest::List, Duration::from_secs(100));
        reply(&mut h, 20, AgentRequest::List, Duration::from_secs(200));

        assert_eq!(h.approvals.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn lock_forgets_everything_and_status_never_unlocks() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        assert_eq!(reply(&mut h, 10, AgentRequest::Lock, Duration::from_secs(1))["ok"], true);
        let status = reply(&mut h, 10, AgentRequest::Status, Duration::from_secs(2));

        assert_eq!(status["unlocked"], false);
        assert_eq!(h.unlocks.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn state_on_disk_is_encrypted() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/cloudflare", "cf-secret-value-123", Duration::ZERO);
        let bytes = fs::read(&h.vault.state_path).unwrap();

        assert!(!bytes.windows(19).any(|w| w == b"cf-secret-value-123"));
        assert_eq!(fs::metadata(&h.vault.state_path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn delete_removes_and_list_is_sorted() {
        let mut h = harness(true);
        put(&mut h, 10, "dev/b", "2", Duration::ZERO);
        put(&mut h, 10, "dev/a", "1", Duration::ZERO);
        assert_eq!(reply(&mut h, 10, AgentRequest::List, Duration::ZERO)["keys"], serde_json::json!(["dev/a", "dev/b"]));
        reply(&mut h, 10, AgentRequest::Delete { key: "dev/a".into() }, Duration::ZERO);
        assert_eq!(reply(&mut h, 10, AgentRequest::List, Duration::ZERO)["keys"], serde_json::json!(["dev/b"]));
        assert_eq!(reply(&mut h, 10, AgentRequest::Delete { key: "dev/a".into() }, Duration::ZERO)["error"], "not_found");
    }

    #[test]
    fn plist_runs_the_agent_at_login() {
        let plist = launch_agent_plist(Path::new("/opt/harar & co/bin/harar"));
        assert!(plist.contains("<string>/opt/harar &amp; co/bin/harar</string>\n    <string>agent</string>"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
    }
}
