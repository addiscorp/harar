//! The agent's vault as a member of a ring (docs/edge.md §5b): its sync
//! state on disk, how it founds a ring, asks to join one, approves and
//! removes members, and turns ops into vault changes and back.
//!
//! The state file (`sync/<edge>.json` in the state folder, 0600) holds only
//! what the edge holds too, plus the ring keys wrapped to this member's
//! key-agreement key: ops are ciphertext, and a secret's path or value is
//! never in it. What the vault knows about sync is inside the vault
//! (`apply::VaultMeta`).

use super::apply::{Incoming, VaultMeta};
use super::crypto::{b64, ecies_seal, fingerprint, gcm_seal, public_key, random_iv, random_key, ring_mac, seal_value, unb64};
use super::ledger::{self, Author, Rejected, RingKey, Roster};
use super::op::{self, Kind, MemberBody, Op, Rank, RekeyBody, RemoveBody, Served, ValueBody};
use crate::cli::edge::{AgreementKey, DeviceKey, Paired};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// At most this many ops, and about this many bytes, in one PUT /v1/sync
/// (the edge takes 100 ops and a 64 KiB body).
const PUSH_OPS: usize = 100;
const PUSH_BYTES: usize = 56 * 1024;
/// The edge's limit on an op's `sealed` (docs/edge.md §5a).
const MAX_SEALED: usize = 48 * 1024;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct State {
    pub edge: String,
    pub device: String,
    /// Ring keys, each wrapped (ECIES) to this member's key-agreement key.
    #[serde(default)]
    pub ring: Vec<RingEntry>,
    /// Whether this member has asked to join (and is waiting for approval).
    #[serde(default)]
    pub requested: bool,
    /// The pull cursor: each author's last verified seq.
    #[serde(default)]
    pub next: BTreeMap<String, u64>,
    #[serde(default)]
    pub authors: BTreeMap<String, Author>,
    /// Every verified member.add, member.remove and rekey.
    #[serde(default)]
    pub member_ops: Vec<Served>,
    /// Verified secret ops not applied yet (the vault was locked, or their
    /// author isn't known to be a member yet).
    #[serde(default)]
    pub pending: Vec<Served>,
    #[serde(default)]
    pub rejected: Vec<Rejected>,
    /// This member's ops not yet on the edge, in seq order.
    #[serde(default)]
    pub outbox: Vec<Op>,
    /// The newest op this member wrote: its seq, hash and time.
    #[serde(default)]
    pub tip: Tip,
    /// The last push or pull that failed, and why (no secret is ever in it).
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Tip {
    pub seq: u64,
    pub hash: String,
    pub at: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RingEntry {
    pub epoch: u32,
    pub wrapped: String,
    pub rank: Option<Rank>,
}

pub(crate) fn state_path(url: &str) -> Result<PathBuf> {
    Ok(crate::common::ensure_state_subdir("sync")?.join(format!("{}.json", &super::crypto::hex(Sha256::digest(url.as_bytes()))[..16])))
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("the clock is after 1970").as_millis() as u64
}

/// The agent's membership of one edge's ring.
pub(crate) struct Member {
    pub edge: Paired,
    pub state: State,
    path: PathBuf,
    agree_pub: Vec<u8>,
    sign_pub: Vec<u8>,
    /// The ring keys, opened: only while the vault is unlocked.
    keys: Option<Vec<RingKey>>,
}

/// What one step did to the vault.
#[derive(Debug, Default)]
pub(crate) struct Stepped {
    /// Paths whose value another member's op changed.
    pub changed: BTreeSet<String>,
}

impl Member {
    /// The member for `edge` (which has sync set up), from its state file.
    pub(crate) fn load(edge: Paired) -> Result<Member> {
        let path = state_path(&edge.url)?;
        Self::load_at(edge, path)
    }

    pub(crate) fn load_at(edge: Paired, path: PathBuf) -> Result<Member> {
        let config = edge.sync.clone().ok_or_else(|| anyhow!("{} has no sync set up; run harar edge sync on", edge.url))?;
        let state = match fs::read_to_string(&path) {
            Ok(text) => serde_json::from_str(&text).with_context(|| format!("read {}", path.display()))?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => State { edge: edge.url.clone(), device: edge.device.clone(), ..State::default() },
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        };
        if state.edge != edge.url || state.device != edge.device {
            bail!("{} is the sync state of another edge or device", path.display());
        }
        let agree_pub = AgreementKey::load(&config.agreement)?.public_key()?;
        let sign_pub = edge.key()?.public_key()?;
        Ok(Member { edge, state, path, agree_pub, sign_pub, keys: None })
    }

    pub(crate) fn me(&self) -> &str {
        &self.edge.device
    }

    pub(crate) fn save(&self) -> Result<()> {
        let part = self.path.with_extension("json.part");
        let mut out = OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&part).with_context(|| format!("open {}", part.display()))?;
        out.write_all(&serde_json::to_vec(&self.state)?)?;
        out.sync_all()?;
        fs::rename(&part, &self.path).with_context(|| format!("write {}", self.path.display()))?;
        Ok(())
    }

    /// Forgets the opened ring keys (the vault locked).
    pub(crate) fn forget(&mut self) {
        self.keys = None;
    }

    fn agreement(&self) -> Result<AgreementKey> {
        AgreementKey::load(&self.edge.sync.as_ref().expect("a member has sync set up").agreement)
    }

    // ------------------------------------------------------------ ingest

    /// Takes pulled ops: each author's chain and signatures are verified, the
    /// ring's ops kept, and secret ops queued until they can be applied.
    pub(crate) fn ingest(&mut self, ops: Vec<Served>) {
        let me = self.edge.device.clone();
        let mut rejected = Vec::new();
        let good = ledger::verify_chains(&mut self.state.authors, &me, ops, &mut rejected);
        for r in rejected {
            if !self.state.rejected.iter().any(|x| x.author == r.author && x.seq == r.seq) {
                self.state.rejected.push(r);
            }
        }
        for op in good {
            let at = self.state.next.entry(op.author.clone()).or_insert(0);
            *at = (*at).max(op.seq);
            // Our own chain continues from the newest of ours the edge has,
            // even if this state file was lost: never a fork.
            if op.author == me && op.seq > self.state.tip.seq {
                self.state.tip = Tip { seq: op.seq, hash: op.hash.clone(), at: op.at };
            }
            if !op.kind.is_value() {
                if !self.state.member_ops.iter().any(|o| o.hash == op.hash) {
                    self.state.member_ops.push(op);
                }
            } else if op.author != me {
                self.state.pending.push(op);
            }
        }
    }

    // ------------------------------------------------------------ keys

    /// Opens the ring keys this member holds (asking the enclave once while
    /// the vault stays unlocked), plus any a grant to it or a rekey gives.
    fn open_keys(&mut self) -> Result<()> {
        let agreement = self.agreement()?;
        let unwrap = |sealed: &[u8]| agreement.open(sealed);
        let mut keys = match self.keys.take() {
            Some(keys) => keys,
            None => {
                let mut keys = Vec::new();
                for entry in &self.state.ring {
                    let raw = unwrap(&unb64(&entry.wrapped)?).context("open this member's ring key")?;
                    let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| anyhow!("a ring key is 32 bytes"))?;
                    keys.push(RingKey { epoch: entry.epoch, key: Zeroizing::new(key), rank: entry.rank.clone() });
                }
                keys
            }
        };
        let mut changed = false;
        if keys.is_empty() {
            for (epoch, wrapped) in ledger::grants_to(self.me(), &self.state.member_ops) {
                if let Ok(raw) = unb64(&wrapped).and_then(|w| unwrap(&w))
                    && let Ok(key) = <[u8; 32]>::try_from(raw.as_slice())
                    && !keys.iter().any(|k: &RingKey| *k.key == key)
                {
                    keys.push(RingKey { epoch, key: Zeroizing::new(key), rank: None });
                    changed = true;
                }
            }
        }
        changed |= ledger::reach_keys(self.me(), &self.state.member_ops, &mut keys, &unwrap);
        // A grant counts only from a member; keys from one that doesn't are dropped.
        if changed {
            let roster = ledger::roster(&self.state.member_ops, &keys);
            if !roster.counts(self.me(), self.state.tip.seq + 1) {
                keys.clear();
            }
            self.keep_keys(&keys)?;
        }
        self.keys = Some(keys);
        Ok(())
    }

    /// Writes `keys` to the state, each wrapped to this member's own key.
    fn keep_keys(&mut self, keys: &[RingKey]) -> Result<()> {
        let mine = public_key(&self.agree_pub)?;
        self.state.ring = keys.iter().map(|k| RingEntry { epoch: k.epoch, wrapped: b64(ecies_seal(&mine, &*k.key)), rank: k.rank.clone() }).collect();
        if !keys.is_empty() {
            self.state.requested = false;
        }
        Ok(())
    }

    pub(crate) fn roster(&mut self) -> Result<Roster> {
        self.open_keys()?;
        Ok(ledger::roster(&self.state.member_ops, self.keys.as_deref().unwrap_or_default()))
    }

    fn current(&self, roster: &Roster) -> Option<&RingKey> {
        ledger::current(self.keys.as_deref().unwrap_or_default(), &self.state.member_ops, roster)
    }

    // ------------------------------------------------------------ writing ops

    /// Signs this member's next op and queues it.
    fn write(&mut self, device: &DeviceKey, kind: Kind, key: String, version: u64, sealed: String, wrapped_key: String) -> Result<Op> {
        let at = now_ms().max(self.state.tip.at);
        let me = self.edge.device.clone();
        let op = Op::sign(&me, self.state.tip.seq + 1, &self.state.tip.hash, kind, &key, version, sealed, wrapped_key, at, &|m| device.sign(m))?;
        let hash = op.hash();
        self.state.tip = Tip { seq: op.seq, hash: hash.clone(), at };
        self.state.authors.entry(me).or_insert(Author { sign_pub: b64(&self.sign_pub), seq: 0, hash: String::new() });
        if !kind.is_value() {
            self.state.member_ops.push(Served::from(&op));
        }
        self.state.outbox.push(op.clone());
        Ok(op)
    }

    fn own_body(&self, epoch: u32) -> MemberBody {
        MemberBody { device: self.edge.device.clone(), name: self.edge.name.clone(), sign_pub: b64(&self.sign_pub), agree_pub: b64(&self.agree_pub), epoch }
    }

    /// Founds the ring when the edge has no ring yet, or asks to join the one
    /// it has. Needs no unlocked vault.
    pub(crate) fn found_or_request(&mut self) -> Result<Option<&'static str>> {
        if !self.state.ring.is_empty() {
            return Ok(None);
        }
        // Only an edge where nobody has written anything gets a new ring.
        let others = self.state.authors.keys().any(|a| *a != self.edge.device) || !self.state.rejected.is_empty();
        let device = self.edge.key()?;
        if !others && self.state.member_ops.is_empty() {
            let ring = random_key();
            let mine = public_key(&self.agree_pub)?;
            let body = self.own_body(0);
            let key = ring_mac(&ring, &op::add_mac_text(self.me(), 0));
            self.write(&device, Kind::MemberAdd, key, 0, op::plain_body(&body), b64(ecies_seal(&mine, &*ring)))?;
            let keys = vec![RingKey { epoch: 0, key: ring, rank: None }];
            self.keep_keys(&keys)?;
            self.keys = Some(keys);
            return Ok(Some("founded"));
        }
        if self.state.requested {
            return Ok(None);
        }
        let body = self.own_body(0);
        self.write(&device, Kind::MemberAdd, op::request_key(self.me()), 0, op::plain_body(&body), String::new())?;
        self.state.requested = true;
        Ok(Some("requested"))
    }

    /// Adds `device`, which asked to join: the ring key, wrapped to the
    /// key-agreement key in its request, in a member.add.
    pub(crate) fn approve(&mut self, device: &str) -> Result<Value> {
        let roster = self.roster()?;
        if roster.members.contains_key(device) {
            bail!("{device} is already a member");
        }
        let Some(request) = roster.requests.get(device).cloned() else {
            bail!("{device} hasn't asked to join; run harar edge sync on there first (then harar edge sync now here)");
        };
        if self.state.authors.get(device).map(|a| &a.sign_pub) != Some(&request.sign_pub) {
            bail!("{device}'s request names a signing key that isn't its own");
        }
        let current = self.current(&roster).ok_or_else(|| anyhow!("this machine isn't a member of the ring, so it can't add one"))?;
        let (epoch, ring) = (current.epoch, current.key.clone());
        let recipient = public_key(&unb64(&request.agree_pub)?)?;
        let body = MemberBody { epoch, ..request.clone() };
        let key = ring_mac(&ring, &op::add_mac_text(device, epoch));
        let signer = self.edge.key()?;
        self.write(&signer, Kind::MemberAdd, key, u64::from(epoch), op::plain_body(&body), b64(ecies_seal(&recipient, &*ring)))?;
        Ok(json!({ "approved": device, "name": request.name, "fingerprint": fingerprint(&unb64(&request.agree_pub)?) }))
    }

    /// Removes `device` from the ring, then rekeys: a new ring key, wrapped
    /// to every member that remains, used for every write from now on.
    /// Returns None when it isn't a member.
    pub(crate) fn remove(&mut self, device: &str) -> Result<Option<Value>> {
        let roster = self.roster()?;
        if device == self.me() || !roster.active().any(|(id, _)| id == device) {
            return Ok(None);
        }
        let current = self.current(&roster).ok_or_else(|| anyhow!("this machine isn't a member of the ring, so it can't remove one"))?;
        let (epoch, old) = (current.epoch, current.key.clone());
        let after = self.state.authors.get(device).map_or(0, |a| a.seq);
        let signer = self.edge.key()?;
        let removed = RemoveBody { device: device.to_owned(), after };
        self.write(&signer, Kind::MemberRemove, ring_mac(&old, &op::remove_mac_text(device, after)), u64::from(epoch), op::plain_body(&removed), String::new())?;
        let new = random_key();
        let next = epoch + 1;
        let mut wraps = BTreeMap::new();
        for (id, member) in roster.active().filter(|(id, _)| *id != device) {
            wraps.insert(id.clone(), b64(ecies_seal(&public_key(&unb64(&member.agree_pub)?)?, &*new)));
        }
        let body = RekeyBody { epoch: next, wraps };
        let back = b64(gcm_seal(&new, &*old, op::rekey_ad(next).as_bytes(), random_iv()));
        let rekey = self.write(&signer, Kind::Rekey, ring_mac(&old, &op::rekey_mac_text(next)), u64::from(next), op::plain_body(&body), back)?;
        let mut keys = self.keys.take().unwrap_or_default();
        keys.push(RingKey { epoch: next, key: new, rank: Some(Served::from(&rekey).rank()) });
        self.keep_keys(&keys)?;
        self.keys = Some(keys);
        Ok(Some(json!({ "removed": device, "after": after, "epoch": next })))
    }

    // ------------------------------------------------------------ the vault

    /// With the vault open: applies what other members wrote (last write
    /// wins), then turns what changed here into ops. `keys` is the vault.
    pub(crate) fn step(&mut self, keys: &mut HashMap<String, String>) -> Result<Stepped> {
        let roster = self.roster()?;
        if self.keys.as_ref().is_none_or(Vec::is_empty) || !roster.counts(self.me(), self.state.tip.seq + 1) {
            return Ok(Stepped::default());
        }
        let mut meta = VaultMeta::read(keys);
        let incoming = self.open_pending(&roster);
        // What isn't synced yet and differs from what the ring holds becomes
        // this member's write, concurrent with the ring's, so last write wins
        // between them and the loser is kept. The same value is just adopted.
        let mut ring_view = keys.clone();
        let mut dry = meta.clone();
        dry.apply(&mut ring_view, incoming.iter().map(|(_, i)| i.clone()).collect());
        let unsynced: Vec<String> = keys.keys().filter(|p| !p.starts_with("harar:") && !meta.paths.contains_key(*p)).cloned().collect();
        let adopt: BTreeSet<String> = unsynced.into_iter().filter(|p| dry.paths.contains_key(p) && ring_view.get(p) == keys.get(p)).collect();
        let mut first = keys.clone();
        first.retain(|p, _| !adopt.contains(p));
        self.record_changes(&mut meta, &first, &roster)?;

        let applied: BTreeSet<String> = incoming.iter().map(|(h, _)| h.clone()).collect();
        let changed = meta.apply(keys, incoming.into_iter().map(|(_, i)| i).collect());
        self.state.pending.retain(|op| !applied.contains(&op.hash));
        self.record_changes(&mut meta, keys, &roster)?;
        meta.write(keys);
        Ok(Stepped { changed })
    }

    fn record_changes(&mut self, meta: &mut VaultMeta, keys: &HashMap<String, String>, roster: &Roster) -> Result<()> {
        let changes = meta.changes(keys);
        if changes.is_empty() {
            return Ok(());
        }
        let current = self.current(roster).ok_or_else(|| anyhow!("no ring key to write with"))?;
        let ring = current.key.clone();
        let signer = self.edge.key()?;
        for change in changes {
            let key = ring_mac(&ring, &change.path);
            let body = ValueBody { path: change.path.clone(), value: change.value.clone(), base: change.base.clone() };
            let plain = Zeroizing::new(serde_json::to_vec(&body)?);
            let (sealed, wrapped) = seal_value(&ring, &key, change.version, &plain, None);
            if sealed.len() > MAX_SEALED {
                // The edge would refuse the whole push; this one stays here.
                eprintln!("harar agent: a secret of {} bytes is too large to sync (at most about {} KiB); it stays on this machine only", plain.len(), MAX_SEALED * 3 / 4 / 1024);
                continue;
            }
            let op = self.write(&signer, change.kind, key, change.version, sealed, wrapped)?;
            meta.record_own(&change, &op.hash(), Served::from(&op).rank());
        }
        Ok(())
    }

    /// The pending secret ops that can be applied now, opened: (hash, op).
    /// An op whose author is no longer a member at its seq is rejected; one
    /// whose author isn't known to be a member yet waits.
    fn open_pending(&mut self, roster: &Roster) -> Vec<(String, Incoming)> {
        let keys = self.keys.as_deref().unwrap_or_default();
        let mut out = Vec::new();
        let mut drop = Vec::new();
        for op in &self.state.pending {
            if !roster.counts(&op.author, op.seq) {
                if roster.members.contains_key(&op.author) {
                    drop.push((op.hash.clone(), Rejected { author: op.author.clone(), seq: op.seq, reason: "its author was removed before it".into() }));
                }
                continue;
            }
            let Some((sealed, wrapped)) = op.ciphertext() else {
                // Compacted: a later op on its key superseded it.
                drop.push((op.hash.clone(), Rejected { author: op.author.clone(), seq: op.seq, reason: String::new() }));
                continue;
            };
            let opened = keys.iter().rev().find_map(|k| {
                let plain = super::crypto::open_value(&k.key, &op.key, op.version, sealed, wrapped).ok()?;
                let body: ValueBody = serde_json::from_slice(&plain).ok()?;
                (ring_mac(&k.key, &body.path) == op.key).then_some(body)
            });
            match opened {
                Some(body) if (op.kind == Kind::Delete) == body.value.is_none() && !body.path.starts_with("harar:") && !body.path.is_empty() => {
                    out.push((op.hash.clone(), Incoming { hash: op.hash.clone(), base: body.base, rank: op.rank(), version: op.version, path: body.path, value: body.value }));
                }
                Some(_) => drop.push((op.hash.clone(), Rejected { author: op.author.clone(), seq: op.seq, reason: "what it holds doesn't match its kind".into() })),
                None => {}
            }
        }
        for (hash, rejected) in drop {
            self.state.pending.retain(|op| op.hash != hash);
            if !rejected.reason.is_empty() {
                self.state.rejected.push(rejected);
            }
        }
        out
    }

    // ------------------------------------------------------------ the edge

    /// Every op after the cursor, all pages.
    pub(crate) fn pull(edge: &Paired, device: &DeviceKey, since: &BTreeMap<String, u64>) -> Result<Vec<Served>> {
        let mut since = since.clone();
        let mut ops = Vec::new();
        loop {
            let page = edge.call_with(device, "POST", "/v1/sync", Some(&json!({ "since": since })))?;
            let got: Vec<Served> = serde_json::from_value(page["ops"].clone()).context("the edge's ops")?;
            ops.extend(got);
            since = serde_json::from_value(page["next"].clone()).context("the edge's next")?;
            if page["more"] != Value::Bool(true) {
                return Ok(ops);
            }
        }
    }

    /// Sends `outbox` in batches the edge takes: how many were sent, and the
    /// error that stopped the rest (they stay queued).
    pub(crate) fn push(edge: &Paired, device: &DeviceKey, outbox: &[Op]) -> (usize, Result<()>) {
        let mut sent = 0;
        while sent < outbox.len() {
            let mut end = sent;
            let mut bytes = 0;
            while end < outbox.len() && end - sent < PUSH_OPS {
                let size = serde_json::to_vec(&outbox[end]).map_or(0, |b| b.len());
                if end > sent && bytes + size > PUSH_BYTES {
                    break;
                }
                bytes += size;
                end += 1;
            }
            if let Err(err) = edge.call_with(device, "PUT", "/v1/sync", Some(&json!({ "ops": &outbox[sent..end] }))) {
                return (sent, Err(err));
            }
            sent = end;
        }
        (sent, Ok(()))
    }

    /// Takes the ops a push sent out of the outbox.
    pub(crate) fn sent(&mut self, ops: &[Op]) {
        let hashes: BTreeSet<String> = ops.iter().map(Op::hash).collect();
        self.state.outbox.retain(|op| !hashes.contains(&op.hash()));
    }

    // ------------------------------------------------------------ status

    /// What `harar edge sync status` shows. Paths appear only in conflicts,
    /// which come from the unlocked vault; values never.
    pub(crate) fn status(&mut self, meta: Option<&VaultMeta>) -> Result<Value> {
        let roster = self.roster()?;
        let role = if roster.counts(self.me(), self.state.tip.seq + 1) && self.keys.as_ref().is_some_and(|k| !k.is_empty()) {
            "member"
        } else if roster.members.contains_key(self.me()) {
            "removed"
        } else if self.state.requested {
            "requested"
        } else {
            "not a member"
        };
        let members: Vec<Value> = roster
            .members
            .iter()
            .map(|(id, m)| json!({ "device": id, "name": m.name, "fingerprint": fingerprint(&unb64(&m.agree_pub).unwrap_or_default()), "removed_after": m.after }))
            .collect();
        let requests: Vec<Value> = roster
            .requests
            .iter()
            .map(|(id, r)| json!({ "device": id, "name": r.name, "fingerprint": fingerprint(&unb64(&r.agree_pub).unwrap_or_default()) }))
            .collect();
        let epoch = self.current(&roster).map(|k| k.epoch);
        Ok(json!({
            "edge": self.edge.url,
            "device": self.edge.device,
            "fingerprint": fingerprint(&self.agree_pub),
            "role": role,
            "founder": roster.founder,
            "epoch": epoch,
            "members": members,
            "requests": requests,
            "queued": self.state.outbox.len(),
            "waiting": self.state.pending.len(),
            "rejected": self.state.rejected,
            "conflicts": meta.map(|m| json!(m.conflicts)).unwrap_or(json!("unlock the vault to see them")),
            "last_error": self.state.last_error,
        }))
    }
}
