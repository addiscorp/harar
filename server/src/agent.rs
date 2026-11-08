//! The per-user agent: one per signed-in user, holding that user's vault.
//!
//! It speaks the daemon's socket protocol for `get`, `put`, `list` and
//! `delete`, so `harar::VaultClient` works against it unchanged, and
//! adds `status`, `unlock` and `lock`.
//!
//! - Only the user who started the agent may talk to it (kernel-reported uid).
//! - It starts locked. The first request opens the master key, which on a
//!   Secure Enclave key needs the person at the Mac; that approval also covers
//!   the terminal session that asked.
//! - Any other terminal session needs its own approval, which asks again.
//! - After `idle_lock` without use it forgets the key and every approval, and
//!   on macOS it does the same within 15 seconds of the screen locking.

use crate::common::{PeerCred, load_keys, peer_credentials, read_request_bytes, write_encrypted_keys};
use harar::primary::PrimaryResponse as VaultResponse;
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
    /// Where `key` may go (`harar hosts allow`), as the primary answers it.
    Hosts { key: String },
    /// The value of `key`, for a request to `host` only.
    Send { key: String, host: String },
    #[serde(rename = "allow_host")]
    AllowHost { key: String, host: String },
    #[serde(rename = "revoke_host")]
    RevokeHost { key: String, host: String },
    /// `harar edge sync …` (docs/edge.md §5b).
    #[serde(rename = "sync")]
    Sync(SyncCommand),
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "sync", rename_all = "lowercase")]
pub(crate) enum SyncCommand {
    On { edge: Option<String> },
    Off,
    Status,
    Now,
    Trust { fingerprint: String },
    Approve { device: String, fingerprint: String },
    Remove { device: String },
}

/// The vault keeps for itself, out of reach of get, put, delete and list:
/// each secret's hosts.
const RESERVED_PREFIX: &str = "harar:";
const HOSTS_KEY: &str = "harar:hosts";

fn reserved(key: &str) -> bool {
    key.starts_with(RESERVED_PREFIX)
}

/// Each secret, and the host patterns it may go to. A list that doesn't read
/// is an error, never an empty list a change would write over.
fn hosts_of(keys: &HashMap<String, String>) -> Result<std::collections::BTreeMap<String, Vec<String>>, &'static str> {
    match keys.get(HOSTS_KEY) {
        None => Ok(Default::default()),
        Some(text) => serde_json::from_str(text).map_err(|_| "hosts_unreadable"),
    }
}

/// `next` without `key`'s hosts: a secret removed or replaced goes nowhere
/// until the owner says again, so a new value never inherits an old one's hosts.
fn forget_hosts(next: &mut HashMap<String, String>, key: &str) -> Result<(), &'static str> {
    let mut all = hosts_of(next)?;
    if all.remove(key).is_some() {
        next.insert(HOSTS_KEY.into(), serde_json::to_string(&all).expect("hosts serialize"));
    }
    Ok(())
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
    /// The ring this vault syncs with, when `harar edge sync on`.
    sync: Option<crate::sync::member::Member>,
    /// Wakes the sync worker: after a local change, to push it.
    wake: Option<std::sync::mpsc::Sender<()>>,
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
            sync: None,
            wake: None,
        }
    }

    pub(crate) fn set_sync(&mut self, member: Option<crate::sync::member::Member>) {
        self.sync = member;
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
        if let Some(member) = self.sync.as_mut() {
            member.forget();
        }
    }

    pub(crate) fn status(&self) -> AgentStatus {
        AgentStatus {
            unlocked: self.unlocked.is_some(),
            approved_sessions: self.sessions.len(),
            approvals: self.approvals.to_string(),
        }
    }

    /// Unlocks if needed and makes sure `session` is approved. Unlocking
    /// applies what other members wrote while the vault was locked.
    fn admit(&mut self, session: i32, now: Instant) -> Result<()> {
        if self.unlocked.is_none() {
            let identity = (self.unlock)()?;
            let keys = load_keys(&self.state_path, &identity)?;
            self.unlocked = Some(Unlocked { identity, keys });
            self.sessions.clear();
            self.sync_after("unlock");
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
        if let AgentRequest::Sync(_) = request {
            // Sync talks to the edge, so it runs outside the vault's lock
            // (handle_sync); it never comes here.
            return AgentReply::Vault(Box::new(VaultResponse::error("bad_request")));
        }
        if let Err(err) = self.admit(session, now) {
            return AgentReply::Vault(Box::new(VaultResponse::error(format!("not_approved: {err:#}"))));
        }
        let local_change = matches!(request, AgentRequest::Put { .. } | AgentRequest::Delete { .. });
        let unlocked = self.unlocked.as_mut().expect("admit unlocked the vault");
        let response = match request {
            AgentRequest::Unlock => VaultResponse::ok(),
            AgentRequest::Get { key } | AgentRequest::Put { key, .. } | AgentRequest::Delete { key } if reserved(&key) => {
                VaultResponse::error("reserved_key")
            }
            AgentRequest::Get { key } => match unlocked.keys.get(&key) {
                Some(value) => VaultResponse { value: Some(value.clone()), ..VaultResponse::ok() },
                None => VaultResponse::error("not_found"),
            },
            AgentRequest::Hosts { key } => match hosts_of(&unlocked.keys) {
                Ok(mut all) => VaultResponse { hosts: Some(all.remove(&key).unwrap_or_default()), ..VaultResponse::ok() },
                Err(reason) => VaultResponse::error(reason),
            },
            AgentRequest::Send { key, host } => {
                let allowed = harar::model::valid_host(&host)
                    && hosts_of(&unlocked.keys).is_ok_and(|all| all.get(&key).is_some_and(|hosts| hosts.iter().any(|pattern| harar::model::host_matches(pattern, &host))));
                match unlocked.keys.get(&key) {
                    _ if !allowed || reserved(&key) => VaultResponse::error("not_allowed"),
                    Some(value) => VaultResponse { value: Some(value.clone()), ..VaultResponse::ok() },
                    None => VaultResponse::error("not_found"),
                }
            }
            AgentRequest::AllowHost { key, host } => {
                if reserved(&key) || !harar::model::valid_secret_path(&key) || !harar::model::valid_host_pattern(&host) {
                    return AgentReply::Vault(Box::new(VaultResponse::error("bad_host")));
                }
                let mut all = match hosts_of(&unlocked.keys) {
                    Ok(all) => all,
                    Err(reason) => return AgentReply::Vault(Box::new(VaultResponse::error(reason))),
                };
                let hosts = all.entry(key).or_default();
                if !hosts.contains(&host) {
                    hosts.push(host);
                    hosts.sort();
                }
                let mut next = unlocked.keys.clone();
                next.insert(HOSTS_KEY.into(), serde_json::to_string(&all).expect("hosts serialize"));
                self.persist(next)
            }
            AgentRequest::RevokeHost { key, host } => {
                let mut all = match hosts_of(&unlocked.keys) {
                    Ok(all) => all,
                    Err(reason) => return AgentReply::Vault(Box::new(VaultResponse::error(reason))),
                };
                let Some(hosts) = all.get_mut(&key).filter(|hosts| hosts.contains(&host)) else {
                    return AgentReply::Vault(Box::new(VaultResponse::error("not_found")));
                };
                hosts.retain(|other| other != &host);
                if hosts.is_empty() {
                    all.remove(&key);
                }
                let mut next = unlocked.keys.clone();
                next.insert(HOSTS_KEY.into(), serde_json::to_string(&all).expect("hosts serialize"));
                self.persist(next)
            }
            AgentRequest::List => {
                let mut keys: Vec<String> = unlocked.keys.keys().filter(|key| !reserved(key)).cloned().collect();
                keys.sort();
                VaultResponse { keys: Some(keys), ..VaultResponse::ok() }
            }
            AgentRequest::Put { key, value } => {
                let mut next = unlocked.keys.clone();
                // A new value starts with nowhere to go; the same one keeps its hosts.
                if next.get(&key) != Some(&value)
                    && let Err(reason) = forget_hosts(&mut next, &key)
                {
                    return AgentReply::Vault(Box::new(VaultResponse::error(reason)));
                }
                next.insert(key, value);
                self.persist(next)
            }
            AgentRequest::Delete { key } => {
                let mut next = unlocked.keys.clone();
                if next.remove(&key).is_none() {
                    return AgentReply::Vault(Box::new(VaultResponse::error("not_found")));
                }
                if let Err(reason) = forget_hosts(&mut next, &key) {
                    return AgentReply::Vault(Box::new(VaultResponse::error(reason)));
                }
                self.persist(next)
            }
            AgentRequest::Status | AgentRequest::Lock | AgentRequest::Sync(_) => unreachable!("answered above"),
        };
        if local_change && response.ok {
            self.sync_after("change");
        }
        AgentReply::Vault(Box::new(response))
    }

    /// Runs a sync step on the unlocked vault (apply what other members
    /// wrote, record what changed here as ops), and wakes the worker to push
    /// any new ops. A failure is the sync's, never the request's: the change
    /// is in the vault already, and the next step records it.
    fn sync_after(&mut self, why: &str) {
        match self.sync_step() {
            Ok(true) => {
                if let Some(wake) = &self.wake {
                    let _ = wake.send(());
                }
            }
            Ok(false) => {}
            Err(err) => eprintln!("harar agent: sync after {why}: {err:#}"),
        }
    }

    /// One sync step on the unlocked vault. Returns whether it queued ops.
    fn sync_step(&mut self) -> Result<bool> {
        let (Some(member), Some(unlocked)) = (self.sync.as_mut(), self.unlocked.as_mut()) else {
            return Ok(false);
        };
        let queued = member.state.outbox.len();
        let mut next = unlocked.keys.clone();
        let stepped = member.step(&mut next)?;
        for path in &stepped.changed {
            // A value another member set goes nowhere until the owner says
            // here, as a value set here does.
            let _ = forget_hosts(&mut next, path);
        }
        // The ops first: a vault saved without them would never send them.
        member.save()?;
        if next != unlocked.keys {
            write_encrypted_keys(&self.state_path, &unlocked.identity.to_public(), &next)?;
            unlocked.keys = next;
        }
        Ok(member.state.outbox.len() > queued)
    }

    /// Writes first, then swaps memory, so memory never holds what disk lacks.
    fn persist(&mut self, next: HashMap<String, String>) -> VaultResponse {
        let unlocked = self.unlocked.as_mut().expect("persist runs unlocked");
        match write_encrypted_keys(&self.state_path, &unlocked.identity.to_public(), &next) {
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
    Sync(serde_json::Value),
}

/// The terminal session a process belongs to. Every process started from one
/// terminal window shares the session of that window's shell.
pub(crate) fn session_of(pid: i32) -> i32 {
    // SAFETY: getsid has no memory-safety preconditions.
    let sid = unsafe { libc::getsid(pid) };
    if sid > 0 { sid } else { pid }
}

/// Default agent socket: the client's (`harar::vault()` finds the agent there).
pub(crate) fn default_socket_path() -> PathBuf {
    harar::default_agent_socket()
}

pub(crate) fn default_ssh_socket_path() -> PathBuf {
    harar::agent_dir().join("ssh.sock")
}

/// The encrypted vault, in the state folder: it outlives a logout and a reboot.
pub(crate) fn default_state_path() -> PathBuf {
    crate::common::state_dir().join("vault.age")
}

/// Where the vault was kept before #100: beside the sockets, which on Linux is
/// `$XDG_RUNTIME_DIR/harar`, emptied at logout. On macOS it is the same file
/// as `default_state_path()`.
pub(crate) fn old_state_path() -> PathBuf {
    harar::agent_dir().join("vault.age")
}

/// Makes the vault's folder private, and moves a vault found at `old` to
/// `state` when `state` has none. Returns whether it moved one. A vault at
/// both is an error that touches neither: only the person knows which one
/// holds their secrets.
///
/// The state folder is made 0700 however it was made (`harar edge` may have
/// made it first); a folder named with --state is created 0700 when missing
/// and otherwise left as the person has it.
pub(crate) fn prepare_state(state: &Path, old: Option<&Path>) -> Result<bool> {
    if let Some(parent) = state.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        if parent == crate::common::state_dir() {
            crate::common::ensure_state_dir()?;
        } else {
            crate::common::create_private_dir(parent)?;
        }
    }
    let Some(old) = old.filter(|old| *old != state) else {
        return Ok(false);
    };
    if !file_exists(old)? {
        return Ok(false);
    }
    if file_exists(state)? {
        return Err(anyhow!(
            "there are two vaults, {} (where an older harar kept it) and {}; harar won't choose between them and has touched neither. Keep the one you want at {}, move the other one away, and start the agent again",
            old.display(),
            state.display(),
            state.display()
        ));
    }
    move_file(old, state)?;
    Ok(true)
}

fn file_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("inspect {}", path.display())),
    }
}

/// Renames `from` to `to` (0600). From a tmpfs to a disk the rename fails with
/// EXDEV, so then it copies to a temporary file beside `to`, syncs it, renames
/// it into place and syncs the folder, and only then removes `from`.
fn move_file(from: &Path, to: &Path) -> Result<()> {
    let parent = to.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
    match fs::rename(from, to) {
        Ok(()) => {}
        Err(err) if err.raw_os_error() == Some(libc::EXDEV) => return copy_across_filesystems(from, to, parent),
        Err(err) => return Err(err).with_context(|| format!("move {} to {}", from.display(), to.display())),
    }
    fs::set_permissions(to, fs::Permissions::from_mode(0o600)).with_context(|| format!("chmod 0600 {}", to.display()))?;
    sync_dir(parent)
}

fn copy_across_filesystems(from: &Path, to: &Path, parent: &Path) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let bytes = fs::read(from).with_context(|| format!("read {}", from.display()))?;
    let tmp = to.with_extension(format!("age.moving.{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let copied = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        file.write_all(&bytes).with_context(|| format!("write {}", tmp.display()))?;
        file.sync_all().with_context(|| format!("sync {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600)).with_context(|| format!("chmod 0600 {}", tmp.display()))?;
        fs::rename(&tmp, to).with_context(|| format!("rename {} to {}", tmp.display(), to.display()))?;
        sync_dir(parent)
    })();
    if copied.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    copied?;
    fs::remove_file(from).with_context(|| {
        format!("the vault is now at {}, but the old copy {} could not be removed; remove it by hand", to.display(), from.display())
    })
}

fn sync_dir(dir: &Path) -> Result<()> {
    fs::File::open(dir).and_then(|dir| dir.sync_all()).with_context(|| format!("sync {}", dir.display()))
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
    start_sync_worker(&vault);
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
        Ok(AgentRequest::Sync(command)) => {
            let session = session_of(peer.pid);
            tokio::task::spawn_blocking(move || handle_sync(&vault, &peer, session, command)).await.context("agent sync task")?
        }
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

// ------------------------------------------------------------------ sync

/// One sync at a time, from the worker or a command.
static CYCLE: Mutex<()> = Mutex::new(());

/// The worker: a sync when the agent starts and after each local change,
/// never on a timer (an edge is metered; docs/edge.md §5b).
fn start_sync_worker(vault: &Arc<Mutex<Vault>>) {
    let (wake, woken) = std::sync::mpsc::channel::<()>();
    let start = {
        let mut v = vault.lock().expect("agent state lock");
        v.wake = Some(wake.clone());
        v.sync.is_some()
    };
    let vault = Arc::clone(vault);
    std::thread::spawn(move || {
        while woken.recv().is_ok() {
            while woken.try_recv().is_ok() {}
            if let Err(err) = sync_cycle(&vault) {
                eprintln!("harar agent: sync: {err:#}");
            }
        }
    });
    if start {
        let _ = wake.send(());
    }
}

fn lock_vault(vault: &Mutex<Vault>) -> std::sync::MutexGuard<'_, Vault> {
    vault.lock().expect("agent state lock")
}

/// Pull, apply, push: a pull before every push, so a push is never refused
/// for being behind. What fails is kept (ops stay queued) and reported, and
/// is tried again at the next sync.
pub(crate) fn sync_cycle(vault: &Mutex<Vault>) -> Result<serde_json::Value> {
    use crate::sync::member::Member;
    let _one = CYCLE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let (edge, since) = {
        let v = lock_vault(vault);
        let Some(member) = v.sync.as_ref() else { return Ok(serde_json::json!({ "on": false })) };
        (member.edge.clone(), member.state.next.clone())
    };
    // The network and every signature happen outside the vault's lock.
    let device = edge.key()?;
    let pulled = Member::pull(&edge, &device, &since);
    let (unsigned, more) = {
        let mut v = lock_vault(vault);
        let Some(member) = v.sync.as_mut().filter(|m| m.edge.url == edge.url) else { return Ok(serde_json::json!({ "on": false })) };
        let pulled = match pulled {
            Ok(pulled) => pulled,
            Err(err) => {
                member.state.last_error = Some(format!("pull: {err:#}"));
                member.save()?;
                return Err(err.context("pull"));
            }
        };
        member.ingest(pulled.ops);
        if pulled.complete {
            member.rebase();
        }
        member.found_or_request()?;
        if v.unlocked.is_some() {
            v.sync_step()?;
        }
        let member = v.sync.as_mut().expect("still syncing");
        member.save()?;
        (member.unsigned(), !pulled.complete)
    };
    let signed = Member::sign(&device, unsigned)?;
    let ready = {
        let mut v = lock_vault(vault);
        let Some(member) = v.sync.as_mut().filter(|m| m.edge.url == edge.url) else { return Ok(serde_json::json!({ "on": false })) };
        member.signed(signed);
        member.save()?;
        member.ready()
    };
    let (sent, pushed) = Member::push(&edge, &device, &ready);
    let mut v = lock_vault(vault);
    if more && let Some(wake) = &v.wake {
        // There was more to pull than one sync takes: another follows.
        let _ = wake.send(());
    }
    let Some(member) = v.sync.as_mut().filter(|m| m.edge.url == edge.url) else { return Ok(serde_json::json!({ "on": false })) };
    member.sent(&ready[..sent], pushed.as_ref().err());
    member.save()?;
    pushed.context("push")?;
    Ok(serde_json::json!({ "pushed": sent, "queued": member.state.outbox.len(), "waiting": member.state.pending.len(), "more": more }))
}

/// `harar edge sync …`, for the owner, with the terminal approved as for
/// any vault request.
fn handle_sync(vault: &Mutex<Vault>, peer: &PeerCred, session: i32, command: SyncCommand) -> AgentReply {
    {
        let mut v = lock_vault(vault);
        if peer.uid != v.owner_uid {
            return AgentReply::Vault(Box::new(VaultResponse::error("not_owner")));
        }
        let now = Instant::now();
        v.expire(now);
        if let Err(err) = v.admit(session, now) {
            return AgentReply::Vault(Box::new(VaultResponse::error(format!("not_approved: {err:#}"))));
        }
    }
    match run_sync(vault, command) {
        Ok(mut answer) => {
            answer["ok"] = serde_json::Value::Bool(true);
            AgentReply::Sync(answer)
        }
        Err(err) => AgentReply::Vault(Box::new(VaultResponse::error(format!("sync: {err:#}")))),
    }
}

fn sync_status(vault: &Mutex<Vault>) -> Result<serde_json::Value> {
    let mut v = lock_vault(vault);
    let meta = v.unlocked.as_ref().map(|u| crate::sync::apply::VaultMeta::read(&u.keys));
    match v.sync.as_mut() {
        Some(member) => {
            let mut status = member.status(meta.as_ref())?;
            status["on"] = serde_json::Value::Bool(true);
            Ok(status)
        }
        None => Ok(serde_json::json!({ "on": false })),
    }
}

fn run_sync(vault: &Mutex<Vault>, command: SyncCommand) -> Result<serde_json::Value> {
    use crate::cli::edge::{AgreementKey, Paired, SyncConfig, read_edges, write_edges};
    use crate::sync::member::Member;
    use serde_json::json;
    match command {
        SyncCommand::On { edge } => {
            let paired = Paired::find_url(edge.as_deref())?;
            let mut edges = read_edges()?;
            if let Some(other) = edges.edges.iter().find(|e| e.url != paired.url && e.sync.is_some()) {
                return Err(anyhow!("this vault already syncs through {} (one ring per vault)", other.url));
            }
            let entry = edges.edges.iter_mut().find(|e| e.url == paired.url).ok_or_else(|| anyhow!("{} is no longer paired", paired.url))?;
            match entry.sync.as_mut() {
                Some(config) => config.on = true,
                None => {
                    let (_, agreement) = AgreementKey::create(&entry.url, &entry.key)?;
                    entry.sync = Some(SyncConfig { on: true, agreement });
                }
            }
            let entry = entry.clone();
            write_edges(&edges)?;
            lock_vault(vault).sync = Some(Member::load(entry)?);
            let synced = sync_cycle(vault);
            let mut status = sync_status(vault)?;
            if let Err(err) = synced {
                status["error"] = json!(format!("{err:#}"));
            }
            Ok(status)
        }
        SyncCommand::Off => {
            let mut edges = read_edges()?;
            let mut off = Vec::new();
            for entry in &mut edges.edges {
                if let Some(config) = entry.sync.as_mut().filter(|c| c.on) {
                    config.on = false;
                    off.push(entry.url.clone());
                }
            }
            write_edges(&edges)?;
            lock_vault(vault).sync = None;
            Ok(json!({ "on": false, "off": off, "note": "Nothing was deleted: the ring keys, the queued ops and the vault stay as they are. harar edge sync on picks up where this left off." }))
        }
        SyncCommand::Status => sync_status(vault),
        SyncCommand::Now => {
            let synced = sync_cycle(vault)?;
            let mut status = sync_status(vault)?;
            status["synced"] = synced;
            Ok(status)
        }
        SyncCommand::Trust { fingerprint } => {
            let trusted = {
                let mut v = lock_vault(vault);
                let member = v.sync.as_mut().ok_or_else(|| anyhow!("sync is off; harar edge sync on first"))?;
                let trusted = member.trust(&fingerprint)?;
                member.save()?;
                trusted
            };
            let synced = sync_cycle(vault);
            let mut status = sync_status(vault)?;
            status["trusted"] = trusted["trusted"].clone();
            if let Err(err) = synced {
                status["error"] = json!(format!("{err:#}"));
            }
            Ok(status)
        }
        SyncCommand::Approve { device, fingerprint } => {
            sync_cycle(vault)?;
            let approved = {
                let mut v = lock_vault(vault);
                let member = v.sync.as_mut().ok_or_else(|| anyhow!("sync is off; harar edge sync on first"))?;
                let approved = member.approve(&device, &fingerprint)?;
                member.save()?;
                approved
            };
            sync_cycle(vault)?;
            Ok(approved)
        }
        SyncCommand::Remove { device } => {
            sync_cycle(vault)?;
            let removed = {
                let mut v = lock_vault(vault);
                let member = v.sync.as_mut().ok_or_else(|| anyhow!("sync is off; harar edge sync on first"))?;
                let removed = member.remove(&device)?;
                member.save()?;
                removed
            };
            if removed.is_some() {
                sync_cycle(vault)?;
            }
            Ok(removed.unwrap_or_else(|| json!({ "removed": null, "note": format!("{device} is not a member of the ring") })))
        }
    }
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
    fn a_secret_goes_only_to_the_hosts_the_owner_allowed_and_the_list_is_out_of_reach() {
        let mut h = harness(true);
        let t = Duration::ZERO;
        put(&mut h, 10, "prod/shop/STRIPE_KEY", "sk_live_real", t);
        let ask = |h: &mut Harness, request| reply(h, 10, request, Duration::from_secs(1));
        let send = |host: &str| AgentRequest::Send { key: "prod/shop/STRIPE_KEY".into(), host: host.into() };
        assert_eq!(ask(&mut h, send("api.stripe.com"))["error"], "not_allowed", "nowhere until the owner says");
        assert_eq!(ask(&mut h, AgentRequest::AllowHost { key: "prod/shop/STRIPE_KEY".into(), host: "*.stripe.com".into() })["ok"], true);
        assert_eq!(ask(&mut h, AgentRequest::AllowHost { key: "prod/shop/STRIPE_KEY".into(), host: "10.0.0.1".into() })["error"], "bad_host");
        assert_eq!(ask(&mut h, AgentRequest::Hosts { key: "prod/shop/STRIPE_KEY".into() })["hosts"], serde_json::json!(["*.stripe.com"]));
        assert_eq!(ask(&mut h, send("api.stripe.com"))["value"], "sk_live_real");
        assert_eq!(ask(&mut h, send("stripe.com"))["error"], "not_allowed", "not the apex");
        assert_eq!(ask(&mut h, send("evil.example.com"))["error"], "not_allowed");
        // The list itself can't be read, rewritten, removed or listed.
        assert_eq!(ask(&mut h, AgentRequest::Get { key: HOSTS_KEY.into() })["error"], "reserved_key");
        assert_eq!(ask(&mut h, AgentRequest::Put { key: HOSTS_KEY.into(), value: "{}".into() })["error"], "reserved_key");
        assert_eq!(ask(&mut h, AgentRequest::Delete { key: HOSTS_KEY.into() })["error"], "reserved_key");
        assert_eq!(ask(&mut h, AgentRequest::List)["keys"], serde_json::json!(["prod/shop/STRIPE_KEY"]));
        assert_eq!(ask(&mut h, AgentRequest::RevokeHost { key: "prod/shop/STRIPE_KEY".into(), host: "*.stripe.com".into() })["ok"], true);
        assert_eq!(ask(&mut h, send("api.stripe.com"))["error"], "not_allowed");
        assert_eq!(ask(&mut h, AgentRequest::RevokeHost { key: "prod/shop/STRIPE_KEY".into(), host: "*.stripe.com".into() })["error"], "not_found");
        // A secret replaced or removed takes its hosts with it.
        ask(&mut h, AgentRequest::AllowHost { key: "prod/shop/STRIPE_KEY".into(), host: "api.stripe.com".into() });
        assert_eq!(ask(&mut h, AgentRequest::Put { key: "prod/shop/STRIPE_KEY".into(), value: "sk_live_real".into() })["ok"], true);
        assert_eq!(ask(&mut h, send("api.stripe.com"))["value"], "sk_live_real", "the same value keeps them");
        assert_eq!(ask(&mut h, AgentRequest::Put { key: "prod/shop/STRIPE_KEY".into(), value: "something else".into() })["ok"], true);
        assert_eq!(ask(&mut h, send("api.stripe.com"))["error"], "not_allowed", "a new value goes nowhere yet");
        ask(&mut h, AgentRequest::AllowHost { key: "prod/shop/STRIPE_KEY".into(), host: "api.stripe.com".into() });
        assert_eq!(ask(&mut h, AgentRequest::Delete { key: "prod/shop/STRIPE_KEY".into() })["ok"], true);
        assert_eq!(ask(&mut h, AgentRequest::Hosts { key: "prod/shop/STRIPE_KEY".into() })["hosts"], serde_json::json!([]));
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

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// An old vault (0600, as the agent wrote it) in `<dir>/run/harar`, and
    /// where the state folder would be, `<dir>/home/.local/state/harar`.
    fn old_vault(dir: &Path, bytes: &[u8]) -> (PathBuf, PathBuf) {
        let old = dir.join("run/harar/vault.age");
        fs::create_dir_all(old.parent().unwrap()).unwrap();
        fs::write(&old, bytes).unwrap();
        fs::set_permissions(&old, fs::Permissions::from_mode(0o600)).unwrap();
        (old, dir.join("home/.local/state/harar/vault.age"))
    }

    #[test]
    fn a_vault_left_in_the_runtime_folder_moves_to_the_state_folder_intact() {
        let dir = tempfile::tempdir().unwrap();
        let (old, state) = old_vault(dir.path(), b"age-encryption.org/v1 sealed bytes");

        assert!(prepare_state(&state, Some(&old)).unwrap(), "reports the move");
        assert_eq!(fs::read(&state).unwrap(), b"age-encryption.org/v1 sealed bytes");
        assert_eq!(mode(&state), 0o600);
        assert_eq!(mode(state.parent().unwrap()), 0o700, "the state folder harar made is private");
        assert!(!old.exists(), "the old copy is gone");
        assert!(!prepare_state(&state, Some(&old)).unwrap(), "nothing left to move");
    }

    #[test]
    fn two_vaults_refuse_to_start_and_neither_is_touched() {
        let dir = tempfile::tempdir().unwrap();
        let (old, state) = old_vault(dir.path(), b"the old vault");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        fs::write(&state, b"the new vault").unwrap();

        let err = format!("{:#}", prepare_state(&state, Some(&old)).unwrap_err());
        assert!(err.contains(&old.display().to_string()) && err.contains(&state.display().to_string()), "{err}");
        assert_eq!(fs::read(&old).unwrap(), b"the old vault");
        assert_eq!(fs::read(&state).unwrap(), b"the new vault");
    }

    #[test]
    fn without_an_old_vault_the_state_folder_is_made_private_and_nothing_moves() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("home/.local/state/harar/vault.age");
        assert!(!prepare_state(&state, Some(&dir.path().join("run/harar/vault.age"))).unwrap());
        assert_eq!(mode(state.parent().unwrap()), 0o700);
        assert!(!state.exists());
        // On macOS the old place is the new one: nothing to move.
        fs::write(&state, b"vault").unwrap();
        assert!(!prepare_state(&state, Some(&state)).unwrap());
        assert_eq!(fs::read(&state).unwrap(), b"vault");
    }

    #[test]
    fn the_copy_used_across_filesystems_keeps_the_bytes_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let (old, state) = old_vault(dir.path(), b"sealed");
        fs::set_permissions(&old, fs::Permissions::from_mode(0o644)).unwrap();
        crate::common::create_private_dir(state.parent().unwrap()).unwrap();

        copy_across_filesystems(&old, &state, state.parent().unwrap()).unwrap();
        assert_eq!(fs::read(&state).unwrap(), b"sealed");
        assert_eq!(mode(&state), 0o600, "0600 whatever the old file was");
        assert!(!old.exists());
        let left: Vec<_> = fs::read_dir(state.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(left, ["vault.age"], "no temporary file left");
    }

    /// For real across filesystems: /dev/shm is a tmpfs, as $XDG_RUNTIME_DIR is,
    /// and the test's temporary folder is on disk.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_vault_on_a_tmpfs_moves_to_disk() {
        use std::os::unix::fs::MetadataExt;
        let shm = tempfile::tempdir_in("/dev/shm").expect("a folder in /dev/shm, the tmpfs every Linux has");
        let disk = tempfile::tempdir().unwrap();
        assert_ne!(
            fs::metadata(shm.path()).unwrap().dev(),
            fs::metadata(disk.path()).unwrap().dev(),
            "TMPDIR must be on another filesystem than /dev/shm for this test"
        );
        let (old, _) = old_vault(shm.path(), b"sealed on tmpfs");
        let state = disk.path().join("state/harar/vault.age");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        assert_eq!(fs::rename(&old, &state).unwrap_err().raw_os_error(), Some(libc::EXDEV), "a plain rename can't cross");
        assert!(prepare_state(&state, Some(&old)).unwrap());
        assert_eq!(fs::read(&state).unwrap(), b"sealed on tmpfs");
        assert_eq!(mode(&state), 0o600);
        assert!(!old.exists());
    }
}
