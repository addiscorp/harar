//! `harar serve`: an org's primary (architecture, §1–7). It holds the org's
//! policy and secrets, issues identity tokens, and decides every request with
//! `Policy::decide`.
//!
//! Who is calling comes from the kernel: the OS user on the other end of the
//! local socket, which the policy maps to an actor. Every local caller is in
//! this machine's zone, vouched for by this machine's broker.

use crate::common::{PeerCred, load_keys, now_epoch_seconds, peer_credentials, read_request_bytes, write_encrypted_keys};
use crate::store::{envelope, postgres};
use anyhow::{Context, Result, anyhow};
use clap::Args;
use harar_client::model::{Action, Binding, Decision, Kind, Name, Org, Permission, Policy, Request, Role, Verb, Zone, ZoneKind, ZoneMatch};
use harar_client::oidc::{self, Alg, IdentityRequest};
use harar_client::approvals::{self, Approval, ApprovalRequest, ApprovalRule, ApproverDevice, DeviceKind, Widens};
use harar_client::primary::{Notice, Pending, PolicyChange, PolicyView, PrimaryRequest, PrimaryResponse, Waiting, waiting_detail};
use harar_client::recovery::{StoredCode, replace_recovery_codes, use_recovery_code};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener, UnixStream};
use tokio::sync::Mutex;

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Entries the primary keeps for itself, never readable or writable as secrets.
const RESERVED_PREFIX: &str = "harar:";
const POLICY_KEY: &str = "harar:policy";
const USERS_KEY: &str = "harar:users";
/// Approver devices (architecture, section 6).
const DEVICES_KEY: &str = "harar:devices";
/// Requests waiting for a person.
const WAITING_KEY: &str = "harar:approvals";
/// Recovery codes' hashes (architecture, §6), and recent failed tries per person.
const RECOVERY_KEY: &str = "harar:recovery";
const RECOVERY_FAILURES_KEY: &str = "harar:recovery_failures";
/// Failed recovery tries a person gets per hour; then none until it passes.
const MAX_RECOVERY_FAILURES: usize = 5;
const RECOVERY_WINDOW_SECONDS: u64 = 3600;
/// Replacing a person's recovery codes: reserved (`recovery.*`).
const RECOVERY_CLASS: &str = "recovery.codes";
/// What a person should know about their own account: kept a week, at most
/// this many per person (their oldest go first), so no one's notices push out
/// anyone else's.
const NOTICES_KEY: &str = "harar:notices";
const NOTICE_SECONDS: u64 = 7 * 24 * 3600;
const MAX_NOTICES: usize = 32;
/// How long a request waits for a person before it lapses.
const APPROVAL_SECONDS: u64 = 15 * 60;
/// At most this many requests wait at once, and this many devices are enrolled.
const MAX_WAITING: usize = 32;
const MAX_DEVICES: usize = 16;
/// At most this many requests wait for one asker, so no one fills the list.
const MAX_WAITING_PER_ASKER: usize = 4;
/// Tokens last this long unless asked for less.
const DEFAULT_TOKEN_SECONDS: u64 = 300;

/// Run an org's primary: its policy, secrets and identity tokens.
#[derive(Debug, Args)]
pub struct Serve {
    /// The local socket callers on this machine use.
    #[arg(long, default_value = "/run/harar.sock")]
    socket: PathBuf,
    /// The org this primary serves, e.g. gg.addis.
    #[arg(long)]
    org: String,
    /// This machine's name in the org, e.g. bugsy: its zone is
    /// <org>.zone.<machine> and its broker <org>.broker.<machine>.
    #[arg(long)]
    machine: String,
    /// On a new primary: the person who owns it, e.g. gg.addis.human.sami.
    #[arg(long)]
    owner: Option<String>,
    /// On a new primary: the OS user who speaks as the owner (default: the
    /// user running harar).
    #[arg(long)]
    owner_user: Option<String>,
    /// Keep secrets in Postgres, as ciphertext: a file (yours, 0600) holding
    /// the connection string, so a password never shows in `ps`. Without it,
    /// secrets stay in the state file.
    #[arg(long)]
    postgres_file: Option<PathBuf>,
    /// The encrypted state file (without --postgres), and where the store's
    /// anchor lives (with it).
    #[arg(long, default_value = "/var/lib/harar/keys.age")]
    state_path: PathBuf,
    /// Move an existing state file into Postgres on this start.
    #[arg(long)]
    import_state: bool,
    /// Start although Postgres has seen writes and this host has no anchor.
    #[arg(long)]
    accept_unanchored: bool,
    #[arg(long, default_value = "/var/log/harar.log")]
    audit_log: PathBuf,
    /// The master key every stored secret is encrypted to (0400, yours).
    #[arg(long, default_value_os_t = crate::master_key::default_master_key_path())]
    master_key_file: PathBuf,
    #[arg(long, default_value = "/var/lib/harar/harar-signing.key")]
    signing_key_file: PathBuf,
    /// Default: next to the signing key.
    #[arg(long)]
    es256_key_file: Option<PathBuf>,
    /// The issuer URL tokens name.
    #[arg(long, default_value = "https://account.addis.gg")]
    issuer: String,
    /// A TCP address serving only the discovery document and JWKS.
    #[arg(long)]
    public_listen: Option<String>,
}

/// Where the keys live.
enum Storage {
    File { path: PathBuf, recipient: age::x25519::Recipient },
    Postgres { pg: Box<postgres::PgStore>, org: String, saved: Mutex<HashMap<String, String>> },
}

pub(crate) struct Primary {
    org: Org,
    zone: Name,
    broker: Name,
    keys: Mutex<HashMap<String, String>>,
    storage: Storage,
    issuer: oidc::Issuer,
    audit_log: PathBuf,
    /// Whether an OS user exists on this machine. Only users that do may be
    /// mapped, so the lockout guard never counts a typo as an owner.
    user_exists: fn(&str) -> bool,
    /// Audit lines for unknown callers, per uid and minute, so one local user
    /// can't fill the audit log.
    unknown_lines: std::sync::Mutex<HashMap<u32, (u64, u32)>>,
}

/// Audit lines kept per unknown uid per minute; past this, one line says the
/// rest were left out.
const UNKNOWN_LINES_PER_MINUTE: u32 = 5;

/// What answering a request comes to: a reply, or a new key map to save
/// (and, once it is saved, what to answer).
enum Outcome {
    Reply(Box<PrimaryResponse>),
    Commit(HashMap<String, String>),
    CommitWith(HashMap<String, String>, Box<PrimaryResponse>),
}

/// A request waiting for a person, with what it would do and the approvals so
/// far (each verified when it arrived, at most one per device).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Stored {
    request: ApprovalRequest,
    waiting: Waiting,
    approvals: Vec<Approval>,
}

fn load_devices(keys: &HashMap<String, String>) -> Vec<ApproverDevice> {
    keys.get(DEVICES_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default()
}

fn store_devices(keys: &mut HashMap<String, String>, devices: &[ApproverDevice]) {
    keys.insert(DEVICES_KEY.into(), serde_json::to_string(devices).expect("devices serialize"));
}

/// The requests still waiting: lapsed ones are dropped as they are read.
fn load_waiting(keys: &HashMap<String, String>, now: u64) -> Vec<Stored> {
    let all: Vec<Stored> = keys.get(WAITING_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default();
    all.into_iter().filter(|stored| stored.request.expires_at > now).collect()
}

fn store_waiting(keys: &mut HashMap<String, String>, waiting: &[Stored]) {
    keys.insert(WAITING_KEY.into(), serde_json::to_string(waiting).expect("approvals serialize"));
}

/// A device as `actor` would have it enrolled: always the caller's own (whom
/// it approves as comes from who is asking, never from what the request
/// says), a Mac key that asks first (a passkey's enrollment needs its own
/// ceremony, which the approval page will run), within the cap, and not a key
/// already enrolled. The primary sets its id, owner and times.
fn new_device(actor: &Name, device: ApproverDevice, devices: &[ApproverDevice]) -> Result<ApproverDevice, &'static str> {
    if actor.kind() != Kind::Human || device.kind != DeviceKind::Mac || !device.user_verification || !approvals::valid_device_key(&device) {
        return Err("bad_device");
    }
    if devices.iter().filter(|other| !other.revoked).count() >= MAX_DEVICES {
        return Err("too_many_devices");
    }
    if devices.iter().any(|other| !other.revoked && other.public_key.x == device.public_key.x && other.public_key.y == device.public_key.y) {
        return Err("key_enrolled");
    }
    Ok(ApproverDevice {
        id: approvals::approval_id(),
        human: actor.clone(),
        enrolled_at: now_epoch_seconds(),
        credential_id: None,
        backup_eligible: false,
        sign_count: 0,
        reserved_after: 0,
        revoked: false,
        ..device
    })
}

fn load_notices(keys: &HashMap<String, String>, now: u64) -> Vec<Notice> {
    let mut notices: Vec<Notice> = keys.get(NOTICES_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default();
    notices.retain(|notice| now < notice.at + NOTICE_SECONDS);
    notices
}

/// Tells `human`, the next time they look (`harar approvals`): no one can
/// take it back, and it goes only after a week.
fn notify(keys: &mut HashMap<String, String>, human: &Name, text: String) {
    let now = now_epoch_seconds();
    let mut notices = load_notices(keys, now);
    notices.push(Notice { human: human.clone(), at: now, text });
    let mine = notices.iter().filter(|notice| notice.human == *human).count();
    let mut over = mine.saturating_sub(MAX_NOTICES);
    notices.retain(|notice| {
        let drop = over > 0 && notice.human == *human;
        over -= usize::from(drop);
        !drop
    });
    keys.insert(NOTICES_KEY.into(), serde_json::to_string(&notices).expect("notices serialize"));
}

fn load_recovery(keys: &HashMap<String, String>) -> Vec<StoredCode> {
    keys.get(RECOVERY_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default()
}

fn store_recovery(keys: &mut HashMap<String, String>, codes: &[StoredCode]) {
    keys.insert(RECOVERY_KEY.into(), serde_json::to_string(codes).expect("recovery codes serialize"));
}

/// Each person's failed recovery tries in the last hour.
fn load_failures(keys: &HashMap<String, String>, now: u64) -> BTreeMap<String, Vec<u64>> {
    let mut all: BTreeMap<String, Vec<u64>> = keys.get(RECOVERY_FAILURES_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default();
    for tries in all.values_mut() {
        tries.retain(|at| now < at + RECOVERY_WINDOW_SECONDS);
    }
    all.retain(|_, tries| !tries.is_empty());
    all
}

fn store_failures(keys: &mut HashMap<String, String>, failures: &BTreeMap<String, Vec<u64>>) {
    keys.insert(RECOVERY_FAILURES_KEY.into(), serde_json::to_string(failures).expect("failures serialize"));
}

/// The same change waiting twice: the same policy change, the same key to
/// enroll, or new codes for the same person.
fn same_change(a: &Waiting, b: &Waiting) -> bool {
    match (a, b) {
        (Waiting::Policy { change: a }, Waiting::Policy { change: b }) => a == b,
        (Waiting::Device { device: a }, Waiting::Device { device: b }) => a.public_key.x == b.public_key.x && a.public_key.y == b.public_key.y,
        (Waiting::RecoveryCodes { human: a }, Waiting::RecoveryCodes { human: b }) => a == b,
        _ => false,
    }
}

/// One line for the person deciding: who asks, from where, for exactly what.
fn describe(request: &ApprovalRequest, waiting: &Waiting) -> String {
    let who = request.act_for.as_ref().unwrap_or(&request.actor);
    let what = match waiting {
        Waiting::Policy { change } => format!("change the policy: {}", serde_json::to_string(change).unwrap_or_default()),
        Waiting::Device { device } => {
            format!("enroll the {:?} key {} as an approver device for {}", device.kind, approvals::device_fingerprint(device), device.human)
        }
        Waiting::RecoveryCodes { human } => format!("replace the recovery codes of {human} (the old ones stop working)"),
    };
    let zone = request.zone.as_ref().map(Name::to_string).unwrap_or_default();
    format!("[{} on {}] {who}, at {zone}, asks to {what}", request.class, request.primary)
}

/// The store's master key comes from the vault's own master key, so whatever
/// protects that (Secure Enclave, TPM, a 0400 file) protects this too.
fn store_master_key(identity: &age::x25519::Identity) -> envelope::MasterKey {
    use age::secrecy::ExposeSecret;
    let secret = identity.to_string();
    envelope::MasterKey::from_secret(format!("age:{}", identity.to_public()), secret.expose_secret().as_bytes())
}

fn reserved(key: &str) -> bool {
    key.starts_with(RESERVED_PREFIX)
}

fn load_policy(keys: &HashMap<String, String>) -> Result<(Policy, BTreeMap<String, Name>)> {
    let policy = keys.get(POLICY_KEY).ok_or_else(|| anyhow!("no policy"))?;
    let policy: Policy = serde_json::from_str(policy).context("the stored policy doesn't load")?;
    let users = match keys.get(USERS_KEY) {
        Some(users) => serde_json::from_str(users).context("the stored user map doesn't load")?,
        None => BTreeMap::new(),
    };
    Ok((policy, users))
}

fn store_policy(keys: &mut HashMap<String, String>, policy: &Policy, users: &BTreeMap<String, Name>) {
    keys.insert(POLICY_KEY.into(), serde_json::to_string(policy).expect("policies serialize"));
    keys.insert(USERS_KEY.into(), serde_json::to_string(users).expect("user maps serialize"));
}

/// Approving that makes a change give someone approver rights.
const GRANT_APPROVAL_CLASS: &str = "approvals.grant";
/// Enrolling another approver device for someone who has one.
const DEVICE_APPROVAL_CLASS: &str = "approvals.device";

/// Who may approve what, as comparable lines: every binding to a role with
/// an approve permission, and every OS user whose actor such a binding
/// covers. A change that adds a line gives someone approver rights.
fn approver_reach(policy: &Policy, users: &BTreeMap<String, Name>) -> BTreeSet<String> {
    let mut reach = BTreeSet::new();
    for binding in &policy.bindings {
        let Some(role) = policy.roles.iter().find(|role| role.name == binding.role) else { continue };
        for permission in role.allows.iter().filter(|permission| permission.verb == Verb::Approve) {
            let zone = serde_json::to_string(&binding.zone).unwrap_or_default();
            reach.insert(format!("{} in {zone} approves {}", binding.actor, permission.resource));
            for (user, actor) in users.iter().filter(|(_, actor)| binding.actor.matches(actor)) {
                reach.insert(format!("OS user {user} as {actor} in {zone} approves {}", permission.resource));
            }
        }
    }
    reach
}

/// A new primary's first policy: its own machine zone, an owner role that may
/// do and approve everything, the owner bound to it in this zone, and the OS
/// user who speaks as the owner. Approver devices take over approving later.
fn first_policy(org: &Org, zone: &Name, broker: &Name, owner: &Name, owner_user: &str, now: u64) -> Result<(Policy, BTreeMap<String, Name>)> {
    if owner.kind() != Kind::Human || owner.org() != org {
        return Err(anyhow!("--owner must be a human of {org}, like {org}.human.you"));
    }
    let mut policy = Policy::new(org.clone());
    policy
        .add_zone(Zone {
            name: zone.clone(),
            kind: ZoneKind::Machine,
            parent: None,
            broker: Some(broker.clone()),
            profile: None,
            created_at: now,
            expires_at: None,
            revoked: false,
        })
        .map_err(|err| anyhow!("this machine's zone: {}", err.as_str()))?;
    let role = Name::new(org, Kind::Role, "owner")?;
    let all = |verb| Permission { verb, resource: "*".into(), scopes: Vec::new() };
    policy.roles.push(Role {
        name: role.clone(),
        allows: vec![
            all(Verb::Read),
            all(Verb::Write),
            Permission { verb: Verb::Token, resource: "*".into(), scopes: vec!["*".into()] },
            all(Verb::Approve),
        ],
    });
    policy.bindings.push(Binding { actor: owner.to_string().parse()?, zone: ZoneMatch::Name(zone.to_string().parse()?), role });
    Ok((policy, BTreeMap::from([(owner_user.to_string(), owner.clone())])))
}

impl Primary {
    fn caller(&self, keys: &HashMap<String, String>, peer: &PeerCred) -> Result<(Policy, BTreeMap<String, Name>, Name), &'static str> {
        let (policy, users) = load_policy(keys).map_err(|_| "policy_unreadable")?;
        let actor = peer.username.as_deref().and_then(|user| users.get(user)).cloned().ok_or("unknown_caller")?;
        Ok((policy, users, actor))
    }

    /// Every decision the primary makes: its own entries are never secrets,
    /// then the policy decides, in this machine's zone, via its broker.
    fn check(&self, policy: &Policy, actor: &Name, action: &Action) -> Result<Name, &'static str> {
        if let Action::Read { path } | Action::Write { path } | Action::Send { path, .. } = action
            && reserved(path)
        {
            return Err("reserved_key");
        }
        match policy.decide(&Request { actor, zone: &self.zone, via: Some(&self.broker), action, session: None }, now_epoch_seconds()) {
            Decision::Allow { by_role } => Ok(by_role),
            Decision::Deny(reason) => Err(reason.as_str()),
        }
    }

    /// Saves the whole key map: to Postgres (what changed, all or nothing),
    /// or to the encrypted state file. Callers save the new map first and
    /// only then make it the live one, so a failed save changes nothing.
    async fn save(&self, keys: &HashMap<String, String>) -> Result<()> {
        match &self.storage {
            Storage::File { path, recipient } => write_encrypted_keys(path, recipient, keys),
            Storage::Postgres { pg, org, saved } => {
                let mut saved = saved.lock().await;
                let mut changes: Vec<postgres::Change<'_>> = keys
                    .iter()
                    .filter(|(key, value)| saved.get(*key) != Some(*value))
                    .map(|(key, value)| postgres::Change { path: key, value: Some(value.as_bytes()) })
                    .collect();
                changes.extend(saved.keys().filter(|key| !keys.contains_key(*key)).map(|key| postgres::Change { path: key, value: None }));
                if changes.is_empty() {
                    return Ok(());
                }
                pg.write(org, &changes, &format!("{org}.service.harar"), None).await.map_err(|err| anyhow!("save: {err}"))?;
                drop(changes);
                *saved = keys.clone();
                Ok(())
            }
        }
    }

    fn audit(&self, peer: &PeerCred, actor: Option<&Name>, op: &str, subject: Option<&str>, result: &str) -> Result<()> {
        let line = serde_json::json!({
            "at": now_epoch_seconds(),
            "uid": peer.uid,
            "pid": peer.pid,
            "actor": actor.map(Name::to_string),
            "zone": self.zone.to_string(),
            "op": op,
            "subject": subject,
            "result": result,
        });
        OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.audit_log)
            .and_then(|mut file| writeln!(file, "{line}"))
            .with_context(|| format!("audit {}", self.audit_log.display()))
    }

    pub(crate) async fn handle(&self, peer: &PeerCred, request: PrimaryRequest) -> PrimaryResponse {
        let op = op_name(&request);
        let mut keys = self.keys.lock().await;
        let (policy, users, actor) = match self.caller(&keys, peer) {
            Ok(caller) => caller,
            Err(reason) => {
                if let Some(result) = self.unknown_line(peer.uid, reason)
                    && let Err(err) = self.audit(peer, None, op, None, result)
                {
                    eprintln!("harar: {err:#}");
                }
                return PrimaryResponse::error(reason);
            }
        };
        let (subject, outcome) = self.answer(&keys, policy, users, &actor, request);
        let committed = !matches!(outcome, Outcome::Reply(_));
        let response = match outcome {
            Outcome::Reply(response) => *response,
            // A change is written to the audit log before it is made, and
            // not made if it can't be.
            Outcome::Commit(next) | Outcome::CommitWith(next, _) if self.audit(peer, Some(&actor), op, subject.as_deref(), "pending").is_err() => {
                drop(next);
                eprintln!("harar: the audit log can't be written; refusing the change");
                return PrimaryResponse::error("audit_failed");
            }
            Outcome::Commit(next) => self.commit(&mut keys, next).await,
            Outcome::CommitWith(next, answer) => {
                let saved = self.commit(&mut keys, next).await;
                if saved.ok { *answer } else { saved }
            }
        };
        let result = if response.ok { "ok" } else { response.error.as_deref().unwrap_or("error") };
        if let Err(err) = self.audit(peer, Some(&actor), op, subject.as_deref(), result) {
            eprintln!("harar: {err:#}");
            // A change is already made (and logged as pending); nothing else
            // is handed out unrecorded: no secret, no token, no policy.
            if response.ok && !committed {
                return PrimaryResponse::error("audit_failed");
            }
        }
        response
    }

    /// What to write for an unknown caller: the reason for the first few per
    /// uid each minute, one note that the rest are left out, then nothing.
    fn unknown_line(&self, uid: u32, reason: &'static str) -> Option<&'static str> {
        let minute = now_epoch_seconds() / 60;
        let mut lines = self.unknown_lines.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        lines.retain(|_, (at, _)| *at == minute);
        let (_, count) = lines.entry(uid).or_insert((minute, 0));
        *count += 1;
        match *count {
            n if n <= UNKNOWN_LINES_PER_MINUTE => Some(reason),
            n if n == UNKNOWN_LINES_PER_MINUTE + 1 => Some("more_unknown_calls_this_minute_not_logged"),
            _ => None,
        }
    }

    fn answer(&self, keys: &HashMap<String, String>, policy: Policy, users: BTreeMap<String, Name>, actor: &Name, request: PrimaryRequest) -> (Option<String>, Outcome) {
        let reply = |response| Outcome::Reply(Box::new(response));
        let refuse = |reason: &str| Outcome::Reply(Box::new(PrimaryResponse::error(reason)));
        match request {
            PrimaryRequest::Health => (None, reply(PrimaryResponse { version: Some(VERSION.into()), ..PrimaryResponse::ok() })),
            PrimaryRequest::Get { key } => {
                if let Err(reason) = self.check(&policy, actor, &Action::Read { path: key.clone() }) {
                    return (Some(key), refuse(reason));
                }
                let response = match keys.get(&key) {
                    Some(value) => PrimaryResponse { value: Some(value.clone()), ..PrimaryResponse::ok() },
                    None => PrimaryResponse::error("not_found"),
                };
                (Some(key), reply(response))
            }
            PrimaryRequest::Put { key, value } => {
                if let Err(reason) = self.check(&policy, actor, &Action::Write { path: key.clone() }) {
                    return (Some(key), refuse(reason));
                }
                let mut next = keys.clone();
                next.insert(key.clone(), value);
                (Some(key), Outcome::Commit(next))
            }
            PrimaryRequest::Hosts { key } => {
                if reserved(&key) {
                    return (Some(key), refuse("reserved_key"));
                }
                let hosts = policy.send_hosts(actor, &self.zone, Some(&self.broker), &key, now_epoch_seconds());
                (Some(key), reply(PrimaryResponse { hosts: Some(hosts), ..PrimaryResponse::ok() }))
            }
            PrimaryRequest::Send { key, host } => {
                // The record says where it went, not just that it was read.
                let subject = Some(format!("{key} to {host}"));
                if let Err(reason) = self.check(&policy, actor, &Action::Send { path: key.clone(), host }) {
                    return (subject, refuse(reason));
                }
                let response = match keys.get(&key) {
                    Some(value) => PrimaryResponse { value: Some(value.clone()), ..PrimaryResponse::ok() },
                    None => PrimaryResponse::error("not_found"),
                };
                (subject, reply(response))
            }
            // Where a secret goes is policy here: a role's `send` permission,
            // changed (and approved) like any other.
            PrimaryRequest::AllowHost { key, .. } | PrimaryRequest::RevokeHost { key, .. } => (Some(key), refuse("hosts_are_policy")),
            PrimaryRequest::Delete { key } => {
                if let Err(reason) = self.check(&policy, actor, &Action::Write { path: key.clone() }) {
                    return (Some(key), refuse(reason));
                }
                if !keys.contains_key(&key) {
                    return (Some(key), refuse("not_found"));
                }
                let mut next = keys.clone();
                next.remove(&key);
                (Some(key), Outcome::Commit(next))
            }
            PrimaryRequest::List => {
                let mut readable: Vec<String> = keys.keys().filter(|key| self.check(&policy, actor, &Action::Read { path: (*key).clone() }).is_ok()).cloned().collect();
                readable.sort();
                (None, reply(PrimaryResponse { keys: Some(readable), ..PrimaryResponse::ok() }))
            }
            PrimaryRequest::Token(ask) => {
                let subject = Some(ask.audience.clone());
                if ask.act.is_some() {
                    return (subject, refuse("act_not_supported"));
                }
                let action = Action::Token { audience: ask.audience.clone(), scopes: ask.scopes.clone() };
                if let Err(reason) = self.check(&policy, actor, &action) {
                    return (subject, refuse(reason));
                }
                let mut extra = BTreeMap::new();
                extra.insert("org".into(), serde_json::Value::String(self.org.to_string()));
                extra.insert("zone".into(), serde_json::Value::String(self.zone.to_string()));
                extra.insert("via".into(), serde_json::Value::String(self.broker.to_string()));
                let identity = IdentityRequest {
                    sub: actor.to_string(),
                    aud: ask.audience,
                    scopes: ask.scopes,
                    ttl_seconds: ask.ttl_seconds.unwrap_or(DEFAULT_TOKEN_SECONDS),
                    act: None,
                    extra,
                };
                let response = match self.issuer.issue(&identity, ask.alg.unwrap_or(Alg::ES256), now_epoch_seconds()) {
                    Ok((token, claims)) => PrimaryResponse { token: Some(token), claims: Some(claims), ..PrimaryResponse::ok() },
                    Err(err) => PrimaryResponse::error(format!("token_refused: {err}")),
                };
                (subject, reply(response))
            }
            PrimaryRequest::PolicyShow => {
                if let Err(reason) = self.check(&policy, actor, &Action::Approve { class: "policy.show".into() }) {
                    return (None, refuse(reason));
                }
                let view = PolicyView { policy, users, zone: self.zone.clone(), broker: self.broker.clone() };
                (None, reply(PrimaryResponse { policy: Some(view), ..PrimaryResponse::ok() }))
            }
            PrimaryRequest::Decide { actor: asked, action } => {
                if let Err(reason) = self.check(&policy, actor, &Action::Approve { class: "policy.show".into() }) {
                    return (None, refuse(reason));
                }
                let decision = match self.check(&policy, asked.as_ref().unwrap_or(actor), &action) {
                    Ok(by_role) => format!("allow by {by_role}"),
                    Err(reason) => reason.to_string(),
                };
                (None, reply(PrimaryResponse { decision: Some(decision), ..PrimaryResponse::ok() }))
            }
            PrimaryRequest::PolicyChange { change } => {
                let class = if change.narrows() { "policy.narrow" } else { "policy.widen" };
                let subject = Some(format!("{class} {}", serde_json::to_string(&change).unwrap_or_default()));
                let (next_policy, next_users, grants) = match self.proposed(keys, &policy, &users, actor, &change) {
                    Ok(proposed) => proposed,
                    Err(reason) => return (subject, refuse(reason)),
                };
                let mut next = keys.clone();
                // Taking away applies at once. Once anyone has an approver
                // device, a widening waits for a person to approve it with one:
                // being logged in as an OS user is no longer enough.
                if !change.narrows() && load_devices(keys).iter().any(|device| !device.revoked) {
                    let class = if grants { GRANT_APPROVAL_CLASS } else { class };
                    return match self.wait(&mut next, actor, class, grants, Waiting::Policy { change }) {
                        Ok(pending) => (subject, Outcome::CommitWith(next, Box::new(PrimaryResponse { pending: Some(pending), ..PrimaryResponse::ok() }))),
                        Err(reason) => (subject, refuse(reason)),
                    };
                }
                store_policy(&mut next, &next_policy, &next_users);
                (subject, Outcome::Commit(next))
            }
            PrimaryRequest::Approvals => {
                if let Err(reason) = self.check(&policy, actor, &Action::Approve { class: "policy.show".into() }) {
                    return (None, refuse(reason));
                }
                let pending = load_waiting(keys, now_epoch_seconds())
                    .into_iter()
                    .map(|stored| Pending { description: describe(&stored.request, &stored.waiting), request: stored.request, waiting: stored.waiting })
                    .collect();
                let notices = load_notices(keys, now_epoch_seconds()).into_iter().filter(|notice| notice.human == *actor).collect();
                let left = load_recovery(keys).iter().filter(|code| code.human == *actor).count();
                (
                    None,
                    reply(PrimaryResponse {
                        approvals: Some(pending),
                        devices: Some(load_devices(keys)),
                        notices: Some(notices),
                        recovery_codes_left: Some(left),
                        ..PrimaryResponse::ok()
                    }),
                )
            }
            PrimaryRequest::Submit { approval } => self.submit(keys, &policy, &users, approval),
            PrimaryRequest::AddDevice { device } => {
                let subject = Some(format!("{:?} key {} for {actor}", device.kind, approvals::device_fingerprint(&device)));
                let mut devices = load_devices(keys);
                let live = devices.iter().filter(|other| !other.revoked).count();
                let device = match new_device(actor, device, &devices) {
                    Ok(device) => device,
                    Err(reason) => return (subject, refuse(reason)),
                };
                let mut next = keys.clone();
                // Approvals start with one device, enrolled at once, of someone
                // who can approve a widening. After that every device, a
                // person's first included, is approved with a device that is
                // already there: an OS account alone never makes an approver.
                if live > 0 {
                    // A device is for approving: only someone who may approve
                    // device enrollments asks for one, so no one else can fill
                    // the waiting list with requests.
                    if self.check(&policy, actor, &Action::Approve { class: DEVICE_APPROVAL_CLASS.into() }).is_err() {
                        return (subject, refuse("not_an_approver"));
                    }
                    return match self.wait(&mut next, actor, DEVICE_APPROVAL_CLASS, true, Waiting::Device { device }) {
                        Ok(pending) => (subject, Outcome::CommitWith(next, Box::new(PrimaryResponse { pending: Some(pending), ..PrimaryResponse::ok() }))),
                        Err(reason) => (subject, refuse(reason)),
                    };
                }
                let id = device.id.clone();
                devices.push(device);
                if !self.devices_can_widen(&policy, &devices) {
                    return (subject, refuse("not_an_approver"));
                }
                store_devices(&mut next, &devices);
                // The first device's owner gets their recovery codes, once:
                // the way back in if it is lost.
                let mut stored = load_recovery(keys);
                let codes = replace_recovery_codes(&mut stored, actor);
                store_recovery(&mut next, &stored);
                (
                    subject,
                    Outcome::CommitWith(
                        next,
                        Box::new(PrimaryResponse { value: Some(id), devices: Some(devices), recovery_codes: Some(codes), ..PrimaryResponse::ok() }),
                    ),
                )
            }
            PrimaryRequest::Recover { code, device } => {
                let what = format!("{:?} key {} for {actor}, with a recovery code", device.kind, approvals::device_fingerprint(&device));
                let subject = Some(what.clone());
                let now = now_epoch_seconds();
                let mut next = keys.clone();
                // Tries are counted per person before the code is looked at,
                // so guessing costs the same whether or not it is close.
                let mut failures = load_failures(keys, now);
                if failures.get(&actor.to_string()).is_some_and(|tries| tries.len() >= MAX_RECOVERY_FAILURES) {
                    return (subject, refuse("too_many_attempts"));
                }
                let mut devices = load_devices(keys);
                let device = match new_device(actor, device, &devices) {
                    Ok(device) => device.enrolled_by_recovery(now),
                    Err(reason) => return (subject, refuse(reason)),
                };
                let mut stored = load_recovery(keys);
                if !use_recovery_code(&mut stored, actor, &code) {
                    failures.entry(actor.to_string()).or_default().push(now);
                    store_failures(&mut next, &failures);
                    // The failed try is kept, and the caller hears no more than no.
                    return (subject, Outcome::CommitWith(next, Box::new(PrimaryResponse::error("bad_code"))));
                }
                // The code is used up in the same write that enrolls the device.
                store_recovery(&mut next, &stored);
                failures.remove(&actor.to_string());
                store_failures(&mut next, &failures);
                let id = device.id.clone();
                let others: Vec<ApproverDevice> = devices.iter().filter(|other| !other.revoked && other.human == *actor).cloned().collect();
                devices.push(device);
                store_devices(&mut next, &devices);
                let left = stored.iter().filter(|code| code.human == *actor).count();
                // Who should be told: every other device of theirs, named in the record.
                let told: Vec<&str> = others.iter().map(|other| other.id.as_str()).collect();
                let subject = Some(format!("{what}: {id}; {left} codes left; their other devices: [{}]", told.join(", ")));
                // Told where only time removes it, so whoever used the code
                // can't hide it from the owner.
                notify(
                    &mut next,
                    actor,
                    format!(
                        "a new device {id} was enrolled with one of your recovery codes ({left} left); if it wasn't you, revoke it (harar device remove {id}) and get new codes (harar recovery-codes)"
                    ),
                );
                (subject, Outcome::CommitWith(next, Box::new(PrimaryResponse { value: Some(id), devices: Some(others), ..PrimaryResponse::ok() })))
            }
            PrimaryRequest::NewRecoveryCodes => {
                let subject = Some(format!("new recovery codes for {actor}"));
                if actor.kind() != Kind::Human {
                    return (subject, refuse("not_a_human"));
                }
                // Only someone with a device of their own can approve it, so
                // no one else holds the one place it waits in.
                if !load_devices(keys).iter().any(|device| !device.revoked && device.human == *actor) {
                    return (subject, refuse("no_device"));
                }
                let mut next = keys.clone();
                match self.wait(&mut next, actor, RECOVERY_CLASS, false, Waiting::RecoveryCodes { human: actor.clone() }) {
                    Ok(pending) => (subject, Outcome::CommitWith(next, Box::new(PrimaryResponse { pending: Some(pending), ..PrimaryResponse::ok() }))),
                    Err(reason) => (subject, refuse(reason)),
                }
            }
            PrimaryRequest::RemoveDevice { id } => {
                let subject = Some(format!("{id} of {actor}"));
                let mut devices = load_devices(keys);
                let now = now_epoch_seconds();
                // While a device recovered with a code waits out its day, the
                // person's other devices stay: a stolen code can't strip the
                // owner's devices. The recovered one can always go.
                let cooling = devices.iter().any(|device| !device.revoked && device.human == *actor && now < device.reserved_after);
                let Some(device) = devices.iter_mut().find(|device| device.id == id && device.human == *actor && !device.revoked) else {
                    return (subject, refuse("no_such_device"));
                };
                if cooling && now >= device.reserved_after {
                    return (subject, refuse("recovery_cooldown"));
                }
                device.revoked = true;
                if !self.devices_can_widen(&policy, &devices) {
                    return (subject, refuse("would_lock_out"));
                }
                let mut next = keys.clone();
                store_devices(&mut next, &devices);
                (subject, Outcome::Commit(next))
            }
        }
    }

    /// The policy after `change`, as a restart would load it, if `actor` may
    /// make it: the class it needs, approver rights it hands out (a stronger
    /// class), and never a policy nobody could change again. Checked when the
    /// change is asked for and again, against the policy then, when it is approved.
    fn proposed(
        &self,
        keys: &HashMap<String, String>,
        policy: &Policy,
        users: &BTreeMap<String, Name>,
        actor: &Name,
        change: &PolicyChange,
    ) -> Result<(Policy, BTreeMap<String, Name>, bool), &'static str> {
        let class = if change.narrows() { "policy.narrow" } else { "policy.widen" };
        self.check(policy, actor, &Action::Approve { class: class.into() })?;
        let before = approver_reach(policy, users);
        let mut next_policy = policy.clone();
        let mut next_users = users.clone();
        self.apply(&mut next_policy, &mut next_users, change.clone())?;
        // Load it back the way a restart would, so a change that leaves a
        // policy that can't load is refused now.
        let next_policy: Policy =
            serde_json::to_string(&next_policy).ok().and_then(|text| serde_json::from_str(&text).ok()).ok_or("policy_invalid")?;
        // Giving anyone approver rights they didn't have is its own, stronger
        // class (architecture, section 6).
        let grants = !approver_reach(&next_policy, &next_users).is_subset(&before);
        if grants {
            self.check(policy, actor, &Action::Approve { class: GRANT_APPROVAL_CLASS.into() })?;
        }
        if !self.someone_can_change_policy(&next_policy, &next_users) {
            return Err("would_lock_out");
        }
        // Once there are approver devices, one must still be able to approve a widening.
        let devices = load_devices(keys);
        if devices.iter().any(|device| !device.revoked) && !self.devices_can_widen(&next_policy, &devices) {
            return Err("would_lock_out");
        }
        Ok((next_policy, next_users, grants))
    }

    /// Whether a device that isn't revoked belongs to someone who may approve a widening.
    fn devices_can_widen(&self, policy: &Policy, devices: &[ApproverDevice]) -> bool {
        let widen = Action::Approve { class: "policy.widen".into() };
        devices.iter().any(|device| !device.revoked && self.check(policy, &device.human, &widen).is_ok())
    }

    /// Who decides here, as the approval rules see it: its issuer, the site
    /// its passkeys belong to, one device per approval to start.
    fn rp(&self) -> approvals::Primary {
        let issuer = self.issuer.url().to_string();
        let rp_id = issuer.trim_start_matches("https://").split(['/', ':']).next().unwrap_or_default().to_string();
        approvals::Primary { issuer, rp_id, reserved_devices: 1 }
    }

    /// Any human of this org may approve, one device each; the policy then
    /// decides whether this human may approve this class (`submit`).
    fn rules(&self) -> Vec<ApprovalRule> {
        let humans = format!("{}.human.*", self.org).parse().expect("a human pattern for the org");
        ["policy.*", "approvals.*", "recovery.*"]
            .into_iter()
            .map(|class| ApprovalRule { class: class.into(), approvers: Clone::clone(&humans), devices: 1 })
            .collect()
    }

    /// Records a request for a person: the machine's broker asks on behalf of
    /// the OS user's actor (so that actor's own device can approve it), for
    /// exactly `waiting`, for `APPROVAL_SECONDS`.
    fn wait(&self, keys: &mut HashMap<String, String>, actor: &Name, class: &str, grants: bool, waiting: Waiting) -> Result<Pending, &'static str> {
        let now = now_epoch_seconds();
        let mut all = load_waiting(keys, now);
        if all.len() >= MAX_WAITING {
            return Err("too_many_waiting");
        }
        if all.iter().filter(|stored| stored.request.act_for.as_ref() == Some(actor)).count() >= MAX_WAITING_PER_ASKER {
            return Err("too_many_waiting");
        }
        if all.iter().any(|stored| same_change(&stored.waiting, &waiting)) {
            return Err("already_waiting");
        }
        let request = ApprovalRequest {
            id: approvals::approval_id(),
            primary: self.issuer.url().to_string(),
            org: self.org.clone(),
            class: class.into(),
            actor: self.broker.clone(),
            act_for: Some(actor.clone()),
            chain: Vec::new(),
            zone: Some(self.zone.clone()),
            action: Action::Approve { class: class.into() },
            // What the change reaches isn't bounded here, so only a person
            // ever approves it, never a coordinator.
            affects: Widens::Unbounded,
            grants_approval: grants,
            created_at: now,
            expires_at: now + APPROVAL_SECONDS,
            detail: Some(waiting_detail(&waiting)),
        };
        all.push(Stored { request: request.clone(), waiting: waiting.clone(), approvals: Vec::new() });
        store_waiting(keys, &all);
        Ok(Pending { description: describe(&request, &waiting), request, waiting })
    }

    /// A person's decision. The proof is checked before anything is kept;
    /// only a human the policy lets approve the class counts; an approved
    /// change is checked again against the policy as it is now, and a request
    /// is acted on once.
    fn submit(&self, keys: &HashMap<String, String>, policy: &Policy, users: &BTreeMap<String, Name>, approval: Approval) -> (Option<String>, Outcome) {
        let refuse = |reason: &str| Outcome::Reply(Box::new(PrimaryResponse::error(reason)));
        let subject = Some(approval.request_id.clone());
        let now = now_epoch_seconds();
        let mut all = load_waiting(keys, now);
        let Some(index) = all.iter().position(|stored| stored.request.id == approval.request_id) else {
            return (subject, refuse("no_such_request"));
        };
        let mut devices = load_devices(keys);
        let rp = self.rp();
        let device = match approvals::verify_approval(&all[index].request, &approval, &devices, &rp) {
            Ok((device, _)) => device.clone(),
            Err(err) => return (subject, refuse(err.as_str())),
        };
        let class = all[index].request.class.clone();
        match &all[index].waiting {
            // A person's recovery codes are theirs alone: only their own
            // device approves a new set, whatever the policy says (and, the
            // class being reserved, never one still in its day after a recovery).
            Waiting::RecoveryCodes { human } => {
                if *human != device.human {
                    return (subject, refuse("not_yours"));
                }
            }
            _ => {
                if self.check(policy, &device.human, &Action::Approve { class }).is_err() {
                    return (subject, refuse("not_an_approver"));
                }
            }
        }
        // From here the audit line names who decided, with which device.
        let who = format!("{} by {} ({})", approval.request_id, device.id, device.human);
        let entry = &mut all[index];
        entry.approvals.retain(|other| other.device_id != approval.device_id);
        entry.approvals.push(approval);
        let decided = match approvals::decide(&entry.request, &entry.approvals, &devices, &self.rules(), &rp, now) {
            Ok(decided) => decided,
            Err(err) => return (subject, refuse(err.as_str())),
        };
        for (id, count) in decided.sign_counts {
            if let Some(device) = devices.iter_mut().find(|device| device.id == id) {
                device.sign_count = count;
            }
        }
        let mut next = keys.clone();
        let mut codes = None;
        let decision = match decided.outcome {
            approvals::Outcome::Pending { have, need } => format!("pending {have}/{need}"),
            approvals::Outcome::Denied => {
                all.remove(index);
                "denied".to_string()
            }
            approvals::Outcome::Approved => {
                let stored = all.remove(index);
                let asker = stored.request.act_for.clone().unwrap_or(stored.request.actor.clone());
                match stored.waiting {
                    Waiting::Policy { change } => match self.proposed(keys, policy, users, &asker, &change) {
                        Ok((next_policy, next_users, _)) => store_policy(&mut next, &next_policy, &next_users),
                        // Approved, but no longer possible: it is used up, and says why.
                        Err(reason) => {
                            store_waiting(&mut next, &all);
                            store_devices(&mut next, &devices);
                            return (Some(format!("{who}: approved_but_{reason}")), Outcome::CommitWith(next, Box::new(PrimaryResponse::error(format!("approved_but_{reason}")))));
                        }
                    },
                    Waiting::Device { mut device } => {
                        // The cap and the key, again, as they are now.
                        let live = devices.iter().filter(|other| !other.revoked).count();
                        let enrolled = devices.iter().any(|other| !other.revoked && other.public_key.x == device.public_key.x && other.public_key.y == device.public_key.y);
                        if live >= MAX_DEVICES || enrolled {
                            store_waiting(&mut next, &all);
                            store_devices(&mut next, &devices);
                            let reason = if enrolled { "key_enrolled" } else { "too_many_devices" };
                            return (Some(format!("{who}: approved_but_{reason}")), Outcome::CommitWith(next, Box::new(PrimaryResponse::error(format!("approved_but_{reason}")))));
                        }
                        device.enrolled_at = now;
                        // A person's first device: their way back in, if it is lost,
                        // is a set of codes only they see, so they ask for it themselves.
                        if !load_recovery(keys).iter().any(|code| code.human == device.human) {
                            notify(&mut next, &device.human, "you have no recovery codes yet: harar recovery-codes, approved on this device".into());
                        }
                        devices.push(device);
                    }
                    Waiting::RecoveryCodes { human } => {
                        let mut stored = load_recovery(keys);
                        codes = Some(replace_recovery_codes(&mut stored, &human));
                        store_recovery(&mut next, &stored);
                        notify(&mut next, &human, format!("your recovery codes were replaced, approved with {}; the old ones no longer work", device.id));
                    }
                }
                "approved".to_string()
            }
        };
        store_waiting(&mut next, &all);
        store_devices(&mut next, &devices);
        (Some(format!("{who}: {decision}")), Outcome::CommitWith(next, Box::new(PrimaryResponse { decision: Some(decision), recovery_codes: codes, ..PrimaryResponse::ok() })))
    }

    fn apply(&self, policy: &mut Policy, users: &mut BTreeMap<String, Name>, change: PolicyChange) -> Result<(), &'static str> {
        let own = |name: &Name, kind: Kind| name.kind() == kind && name.org() == &self.org;
        match change {
            PolicyChange::SetRole { role } => {
                if !own(&role.name, Kind::Role) {
                    return Err("bad_name");
                }
                policy.roles.retain(|existing| existing.name != role.name);
                policy.roles.push(role);
            }
            PolicyChange::RemoveRole { name } => {
                let before = policy.roles.len();
                policy.roles.retain(|role| role.name != name);
                if policy.roles.len() == before {
                    return Err("not_found");
                }
            }
            PolicyChange::Bind { binding } => {
                if policy.bindings.contains(&binding) {
                    return Err("already_bound");
                }
                policy.bindings.push(binding);
            }
            PolicyChange::Unbind { binding } => {
                let before = policy.bindings.len();
                policy.bindings.retain(|existing| existing != &binding);
                if policy.bindings.len() == before {
                    return Err("not_found");
                }
            }
            PolicyChange::SetProfile { profile } => {
                if !own(&profile.name, Kind::Profile) {
                    return Err("bad_name");
                }
                policy.profiles.retain(|existing| existing.name != profile.name);
                policy.profiles.push(profile);
            }
            PolicyChange::RemoveProfile { name } => {
                let before = policy.profiles.len();
                policy.profiles.retain(|profile| profile.name != name);
                if policy.profiles.len() == before {
                    return Err("not_found");
                }
            }
            PolicyChange::AddZone { zone } => {
                policy.add_zone(zone).map_err(|err| err.as_str())?;
            }
            // Revoking the primary's own zone is refused as a lockout:
            // nothing in a revoked zone can change policy again.
            PolicyChange::RevokeZone { name } => {
                if !policy.revoke_zone(&name) {
                    return Err("not_found");
                }
            }
            PolicyChange::MapUser { user, actor } => {
                if user.is_empty() || !actor.kind().is_actor() || actor.org() != &self.org || actor.kind() == Kind::User {
                    return Err("bad_name");
                }
                if !(self.user_exists)(&user) {
                    return Err("unknown_os_user");
                }
                users.insert(user, actor);
            }
            PolicyChange::UnmapUser { user } => {
                if users.remove(&user).is_none() {
                    return Err("not_found");
                }
            }
        }
        Ok(())
    }

    /// Whether some mapped OS user could still widen policy: no change may
    /// leave nobody able to change it again.
    fn someone_can_change_policy(&self, policy: &Policy, users: &BTreeMap<String, Name>) -> bool {
        let widen = Action::Approve { class: "policy.widen".into() };
        users.iter().any(|(user, actor)| (self.user_exists)(user) && self.check(policy, actor, &widen).is_ok())
    }

    async fn commit(&self, keys: &mut HashMap<String, String>, next: HashMap<String, String>) -> PrimaryResponse {
        match self.save(&next).await {
            Ok(()) => {
                *keys = next;
                PrimaryResponse::ok()
            }
            Err(err) => {
                eprintln!("harar: {err:#}");
                PrimaryResponse::error("save_failed")
            }
        }
    }
}

fn op_name(request: &PrimaryRequest) -> &'static str {
    match request {
        PrimaryRequest::Get { .. } => "get",
        PrimaryRequest::Hosts { .. } => "hosts",
        PrimaryRequest::Send { .. } => "send",
        PrimaryRequest::AllowHost { .. } => "allow_host",
        PrimaryRequest::RevokeHost { .. } => "revoke_host",
        PrimaryRequest::Put { .. } => "put",
        PrimaryRequest::Delete { .. } => "delete",
        PrimaryRequest::List => "list",
        PrimaryRequest::Token(_) => "token",
        PrimaryRequest::Health => "health",
        PrimaryRequest::PolicyShow => "policy_show",
        PrimaryRequest::PolicyChange { .. } => "policy_change",
        PrimaryRequest::Decide { .. } => "decide",
        PrimaryRequest::Approvals => "approvals",
        PrimaryRequest::Submit { .. } => "submit",
        PrimaryRequest::AddDevice { .. } => "add_device",
        PrimaryRequest::RemoveDevice { .. } => "remove_device",
        PrimaryRequest::Recover { .. } => "recover",
        PrimaryRequest::NewRecoveryCodes => "new_recovery_codes",
    }
}

/// Opens Postgres and returns what it holds. An existing state file moves in
/// only when asked, only into an empty store, all at once, and is then
/// renamed so it is never read again.
async fn open_postgres(
    pg: postgres::PgStore,
    org: &str,
    state_path: &Path,
    identity: &age::x25519::Identity,
    import_state: bool,
) -> Result<(Storage, HashMap<String, String>)> {
    let mut held = HashMap::new();
    for (path, value) in pg.load_all(org).await.map_err(|err| anyhow!("load secrets: {err}"))? {
        held.insert(path.clone(), String::from_utf8(value.to_vec()).map_err(|_| anyhow!("{path} is not text"))?);
    }
    let imported = state_path.with_extension("age.imported");
    if !state_path.exists() {
        return Ok((Storage::Postgres { pg: Box::new(pg), org: org.into(), saved: Mutex::new(held.clone()) }, held));
    }
    if !held.is_empty() {
        if load_keys(state_path, identity)? == held && !imported.exists() {
            fs::rename(state_path, &imported).with_context(|| format!("rename {} to {}", state_path.display(), imported.display()))?;
            eprintln!("harar: finished an earlier import; renamed the file to {}", imported.display());
            return Ok((Storage::Postgres { pg: Box::new(pg), org: org.into(), saved: Mutex::new(held.clone()) }, held));
        }
        return Err(anyhow!(
            "both {} and Postgres hold secrets for {org}; harar won't guess which is right. Move the file aside once you've checked.",
            state_path.display()
        ));
    }
    if !import_state {
        return Err(anyhow!("{} holds secrets and Postgres holds none for {org}; start once with --import-state to move them in", state_path.display()));
    }
    if imported.exists() {
        return Err(anyhow!("{} already exists; move it aside before importing again", imported.display()));
    }
    let file_keys = load_keys(state_path, identity)?;
    if let Some(bad) = file_keys.keys().find(|key| !harar_client::model::valid_secret_path(key)) {
        return Err(anyhow!("{bad:?} isn't a secret path; rename it in the file vault first. Nothing was imported."));
    }
    let changes: Vec<postgres::Change<'_>> = file_keys.iter().map(|(key, value)| postgres::Change { path: key, value: Some(value.as_bytes()) }).collect();
    pg.write(org, &changes, &format!("{org}.service.harar"), None).await.map_err(|err| anyhow!("import: {err}; nothing was imported"))?;
    drop(changes);
    fs::rename(state_path, &imported).with_context(|| format!("rename {} to {}", state_path.display(), imported.display()))?;
    eprintln!("harar: imported {} entries into Postgres and renamed the file to {}; delete it once you've checked", file_keys.len(), imported.display());
    Ok((Storage::Postgres { pg: Box::new(pg), org: org.into(), saved: Mutex::new(file_keys.clone()) }, file_keys))
}

/// Builds the primary from its config: the master key, the store, the
/// issuer's keys, and the policy (made on first start from --owner).
async fn open(config: &Serve) -> Result<Primary> {
    let org: Org = config.org.parse().map_err(|err| anyhow!("--org {}: {err}", config.org))?;
    let zone = Name::new(&org, Kind::Zone, &config.machine).map_err(|err| anyhow!("--machine {}: {err}", config.machine))?;
    let broker = Name::new(&org, Kind::Broker, &config.machine)?;
    let state_dir = config.state_path.parent().ok_or_else(|| anyhow!("the state path has no parent folder"))?;
    ensure_private_dir(state_dir, "state")?;
    let identity = crate::master_key::load_master_key(&config.master_key_file)?;
    let (storage, mut keys) = match &config.postgres_file {
        None => {
            let keys = load_keys(&config.state_path, &identity)?;
            (Storage::File { path: config.state_path.clone(), recipient: identity.to_public() }, keys)
        }
        Some(file) => {
            let url = read_private_file(file, "Postgres connection file")?;
            let url = url.trim();
            let options = postgres::Options {
                anchor: Some(config.state_path.with_file_name("store.anchor")),
                accept_unanchored: config.accept_unanchored,
                exit_when_lost: true,
            };
            let pg = postgres::PgStore::connect(url, "harar_primary", store_master_key(&identity), options)
                .await
                .map_err(|err| anyhow!("open the secret store: {err}"))?;
            pg.hold_as_primary().await.map_err(|err| anyhow!("open the secret store: {err}"))?;
            open_postgres(pg, org.as_str(), &config.state_path, &identity, config.import_state).await?
        }
    };
    let signing = load_or_create_key(&config.signing_key_file, "signing key", harar_client::generate_signing_key, |key| key.to_bytes().to_vec(), |bytes| {
        let bytes: [u8; 32] = bytes.try_into().map_err(|_| anyhow!("not 32 bytes"))?;
        Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
    })?;
    let es256_path = config.es256_key_file.clone().unwrap_or_else(|| config.signing_key_file.with_file_name("harar-es256.key"));
    let es256 = load_or_create_key(&es256_path, "ES256 key", oidc::generate_es256_key, |key| oidc::es256_key_bytes(key).to_vec(), |bytes| {
        oidc::es256_key_from_bytes(bytes).map_err(|err| anyhow!("{err}"))
    })?;
    check_audit_log(&config.audit_log)?;
    let primary = Primary {
        org: org.clone(),
        zone: zone.clone(),
        broker: broker.clone(),
        keys: Mutex::new(HashMap::new()),
        storage,
        issuer: oidc::Issuer::new(config.issuer.clone(), es256, signing),
        audit_log: config.audit_log.clone(),
        user_exists: crate::common::user_exists,
        unknown_lines: Default::default(),
    };
    match keys.get(POLICY_KEY) {
        Some(_) => {
            let (policy, _) = load_policy(&keys)?;
            if policy.org != org {
                return Err(anyhow!("this primary's policy is for {}, not {org}", policy.org));
            }
            if policy.zone(&zone).is_none() {
                return Err(anyhow!("this primary's policy has no zone {zone}; was --machine changed?"));
            }
        }
        None => {
            let owner = config.owner.as_deref().ok_or_else(|| anyhow!("a new primary needs --owner, the person who owns it (e.g. {org}.human.you)"))?;
            let owner: Name = owner.parse().map_err(|err| anyhow!("--owner {owner}: {err}"))?;
            let owner_user = match &config.owner_user {
                Some(user) => user.clone(),
                // SAFETY: geteuid has no preconditions.
                None => crate::common::username_for_uid(unsafe { libc::geteuid() }).ok_or_else(|| anyhow!("can't tell who is running harar; pass --owner-user"))?,
            };
            if !(primary.user_exists)(&owner_user) {
                return Err(anyhow!("--owner-user {owner_user} is not a user on this machine"));
            }
            let (policy, users) = first_policy(&org, &zone, &broker, &owner, &owner_user, now_epoch_seconds())?;
            let mut next = keys.clone();
            store_policy(&mut next, &policy, &users);
            primary.save(&next).await.context("save the first policy")?;
            keys = next;
            eprintln!("harar: a new primary for {org}: {owner} owns it, as the OS user {owner_user}");
        }
    }
    *primary.keys.lock().await = keys;
    Ok(primary)
}

fn ensure_private_dir(path: &Path, kind: &str) -> Result<()> {
    let existed = path.exists();
    fs::create_dir_all(path).with_context(|| format!("create the {kind} folder {}", path.display()))?;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {}", path.display()))?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(anyhow!("refusing a {kind} folder this user doesn't own: {}", path.display()));
    }
    if existed && metadata.permissions().mode() & 0o022 != 0 {
        return Err(anyhow!("refusing a {kind} folder others can write: {}", path.display()));
    }
    if !existed {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A file only this user can read: their own, with no group or other bits.
/// The checks are made on the file that was opened, never on a symlink.
fn read_private_file(path: &Path, kind: &str) -> Result<String> {
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).with_context(|| format!("open the {kind} {}", path.display()))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(anyhow!("refusing a {kind} others can read, or this user doesn't own: {}", path.display()));
    }
    let mut text = String::new();
    std::io::Read::read_to_string(&mut file, &mut text).with_context(|| format!("read the {kind} {}", path.display()))?;
    Ok(text)
}

/// The audit log is this user's and private, or the primary doesn't start.
fn check_audit_log(path: &Path) -> Result<()> {
    let file = OpenOptions::new().create(true).append(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(path).with_context(|| format!("open the audit log {}", path.display()))?;
    let metadata = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(anyhow!("refusing an audit log others can read, or this user doesn't own: {}", path.display()));
    }
    Ok(())
}

/// Loads a key file (this user's, 0600), or makes one.
fn load_or_create_key<K>(
    path: &Path,
    kind: &str,
    generate: impl FnOnce() -> K,
    encode: impl FnOnce(&K) -> Vec<u8>,
    decode: impl FnOnce(&[u8]) -> Result<K>,
) -> Result<K> {
    let parent = path.parent().ok_or_else(|| anyhow!("the {kind} path has no parent folder"))?;
    ensure_private_dir(parent, kind)?;
    let check = || -> Result<()> {
        let metadata = fs::symlink_metadata(path)?;
        // SAFETY: geteuid has no preconditions.
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(anyhow!("refusing an unsafe {kind} at {}", path.display()));
        }
        Ok(())
    };
    match fs::read(path) {
        Ok(bytes) => {
            check()?;
            decode(&bytes).with_context(|| format!("decode the {kind} at {}", path.display()))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let key = generate();
            let mut file = OpenOptions::new().create_new(true).write(true).mode(0o600).open(path).with_context(|| format!("create {}", path.display()))?;
            file.write_all(&encode(&key)).and_then(|()| file.sync_all()).with_context(|| format!("write {}", path.display()))?;
            check()?;
            Ok(key)
        }
        Err(err) => Err(err).with_context(|| format!("read {}", path.display())),
    }
}

fn bind_socket(path: &Path) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    match fs::symlink_metadata(path) {
        // Only a socket nothing answers on is stale; one that is busy or
        // unreadable may still be a live primary's.
        Ok(metadata) if metadata.file_type().is_socket() => match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => return Err(anyhow!("another harar is serving on {}", path.display())),
            Err(err) if err.kind() == std::io::ErrorKind::ConnectionRefused => {
                fs::remove_file(path).with_context(|| format!("remove the stale {}", path.display()))?
            }
            Err(err) => return Err(anyhow!("can't tell whether {} is in use ({err}); remove it if no harar is running", path.display())),
        },
        Ok(_) => return Err(anyhow!("{} exists and is not a socket", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err).with_context(|| format!("stat {}", path.display())),
    }
    let listener = UnixListener::bind(path).with_context(|| format!("bind {}", path.display()))?;
    // Anyone on this machine may connect; the kernel says who they are, and
    // OS users the policy doesn't map get nothing.
    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).with_context(|| format!("chmod {}", path.display()))?;
    Ok(listener)
}

pub async fn run(config: Serve) -> Result<()> {
    crate::agent::disable_core_dumps()?;
    let state_dir = config.state_path.parent().ok_or_else(|| anyhow!("the state path has no parent folder"))?;
    ensure_private_dir(state_dir, "state")?;
    // Held until the process exits: one primary per state folder.
    let _lock = crate::common::lock_exclusive(&state_dir.join("primary.lock")).context("another harar primary is using this state folder")?;
    let primary = Arc::new(open(&config).await?);
    let listener = bind_socket(&config.socket)?;
    eprintln!("harar primary for {} in {} on {}", primary.org, primary.zone, config.socket.display());
    if let Some(address) = &config.public_listen {
        let public = TcpListener::bind(address).await.with_context(|| format!("bind the public listener {address}"))?;
        eprintln!("harar serving discovery and JWKS on {address} as {}", primary.issuer.url());
        tokio::spawn(serve_public(public, Arc::clone(&primary), PUBLIC_LIMITS));
    }
    let slots = Arc::new(tokio::sync::Semaphore::new(LOCAL_LIMITS.connections));
    let per_uid = Arc::new(PerUid::default());
    loop {
        let slot = Arc::clone(&slots).acquire_owned().await.expect("the semaphore is never closed");
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) => {
                eprintln!("harar: accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let primary = Arc::clone(&primary);
        let per_uid = Arc::clone(&per_uid);
        tokio::spawn(async move {
            let _slot = slot;
            if let Err(err) = connection(stream, &primary, &per_uid, LOCAL_LIMITS.exchange).await {
                eprintln!("harar connection error: {err:#}");
            }
        });
    }
}

/// Limits for the local socket, which any OS user on this machine can open.
/// A request arrives at once, so a second is plenty to send it.
const LOCAL_LIMITS: Limits = Limits { connections: 64, exchange: Duration::from_secs(1) };
/// Connections one OS user may hold open at once, so no one user can take
/// every slot.
const CONNECTIONS_PER_UID: usize = 8;

/// Open connections per OS user.
#[derive(Default)]
struct PerUid(std::sync::Mutex<HashMap<u32, usize>>);

/// One of a user's connection slots, given back when dropped.
struct UidSlot<'a> {
    per_uid: &'a PerUid,
    uid: u32,
}

impl PerUid {
    fn take(&self, uid: u32) -> Option<UidSlot<'_>> {
        let mut open = self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = open.entry(uid).or_insert(0);
        if *count >= CONNECTIONS_PER_UID {
            return None;
        }
        *count += 1;
        Some(UidSlot { per_uid: self, uid })
    }
}

impl Drop for UidSlot<'_> {
    fn drop(&mut self) {
        let mut open = self.per_uid.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(count) = open.get_mut(&self.uid) {
            *count -= 1;
            if *count == 0 {
                open.remove(&self.uid);
            }
        }
    }
}

/// Reading the request and writing the reply each get `limit`; deciding and
/// saving in between are never cut off halfway.
async fn connection(mut stream: UnixStream, primary: &Primary, per_uid: &PerUid, limit: Duration) -> Result<()> {
    let peer = peer_credentials(&stream).context("read the caller's credentials")?;
    // Over the limit, the caller hears why; nothing is logged, so a flood
    // can't fill the journal either.
    let Some(_uid_slot) = per_uid.take(peer.uid) else {
        let reply = serde_json::to_vec(&PrimaryResponse::error("too_many_connections"))?;
        let _ = tokio::time::timeout(limit, stream.write_all(&reply)).await;
        return Ok(());
    };
    let bytes = tokio::time::timeout(limit, read_request_bytes(&mut stream)).await.map_err(|_| anyhow!("the caller sent nothing in time"))??;
    let response = match serde_json::from_slice::<PrimaryRequest>(&bytes) {
        Ok(request) => primary.handle(&peer, request).await,
        Err(_) => PrimaryResponse::error("bad_request"),
    };
    let reply = serde_json::to_vec(&response)?;
    tokio::time::timeout(limit, stream.write_all(&reply)).await.map_err(|_| anyhow!("the caller read nothing in time"))?.context("write the response")
}

// The public listener: discovery and JWKS only, for anyone on the network.

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    path: String,
}

/// Limits for a listener others can reach.
#[derive(Clone, Copy)]
struct Limits {
    /// Connections served at once. Past this, accepting waits, so a flood
    /// queues in the kernel instead of using up this process's file handles.
    connections: usize,
    /// The whole exchange, reading and writing, must finish in this time.
    exchange: Duration,
}

const PUBLIC_LIMITS: Limits = Limits { connections: 256, exchange: Duration::from_secs(10) };

fn public_reply(primary: &Primary, request: &HttpRequest) -> Option<(u16, serde_json::Value)> {
    let body = match request.path.as_str() {
        oidc::DISCOVERY_PATH => primary.issuer.discovery(),
        oidc::JWKS_PATH => serde_json::to_value(primary.issuer.jwks()).ok()?,
        _ => return None,
    };
    Some((200, body))
}

async fn serve_public(listener: TcpListener, primary: Arc<Primary>, limits: Limits) {
    let slots = Arc::new(tokio::sync::Semaphore::new(limits.connections));
    loop {
        let slot = Arc::clone(&slots).acquire_owned().await.expect("the semaphore is never closed");
        let mut stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                eprintln!("harar public listener: accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let primary = Arc::clone(&primary);
        tokio::spawn(async move {
            let _slot = slot;
            let exchange = async {
                let (status, body) = match read_http_head(&mut stream).await.and_then(|head| parse_http_request(&head)) {
                    Ok(request) if request.method == "GET" => public_reply(&primary, &request).unwrap_or((404, serde_json::json!({ "error": "not found" }))),
                    Ok(_) => (405, serde_json::json!({ "error": "method not allowed" })),
                    Err(_) => (400, serde_json::json!({ "error": "bad request" })),
                };
                write_http_json(&mut stream, status, body).await
            };
            // A timeout just drops the connection.
            if let Ok(Err(err)) = tokio::time::timeout(limits.exchange, exchange).await {
                eprintln!("harar public listener error: {err:#}");
            }
        });
    }
}

/// Reads up to the blank line ending an HTTP request's headers. Browsers and
/// curl keep the connection open, so EOF can't be the signal.
async fn read_http_head(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut head = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        if head.len() > crate::common::MAX_REQUEST_BYTES {
            return Err(anyhow!("HTTP request head too large"));
        }
        let read = stream.read(&mut chunk).await.context("read request")?;
        if read == 0 {
            return Ok(head);
        }
        // Only the new bytes, plus three before them, can complete the end.
        let from = head.len().saturating_sub(3);
        head.extend_from_slice(&chunk[..read]);
        if head[from..].windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

fn parse_http_request(bytes: &[u8]) -> Result<HttpRequest> {
    let text = std::str::from_utf8(bytes).context("HTTP request is not UTF-8")?;
    let line = text.lines().next().ok_or_else(|| anyhow!("empty HTTP request"))?;
    let mut parts = line.split_whitespace();
    let method = parts.next().ok_or_else(|| anyhow!("no method"))?.to_string();
    let path = parts.next().ok_or_else(|| anyhow!("no path"))?.to_string();
    Ok(HttpRequest { method, path })
}

async fn write_http_json(stream: &mut (impl AsyncWrite + Unpin), status: u16, body: serde_json::Value) -> Result<()> {
    let body = body.to_string();
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\ncache-control: no-store\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes()).await.context("write the HTTP response")
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod approval_tests;
