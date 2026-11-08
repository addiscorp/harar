//! The agent's vault as a member of a ring (docs/edge.md §5b): its sync
//! state on disk, how it founds a ring, asks to join one, pins it, and (as
//! the ring's authority) adds, removes and hands over; and how it turns ops
//! into vault changes and back.
//!
//! The state file (`sync/<edge>.json` in the state folder, 0600) holds only
//! what the edge holds too, plus the ring keys wrapped to this member's
//! key-agreement key: ops are ciphertext, and a secret's path or value is
//! never in it. What the vault knows about sync is inside the vault
//! (`apply::VaultMeta`).
//!
//! Ops are written unsigned, under the agent's lock, and signed outside it
//! (an op's hash doesn't cover its signature), so a Secure Enclave signature
//! never holds the vault. Who is a member comes from the membership log,
//! which needs no ring key, so nothing here opens one while the vault is
//! locked.

use super::apply::{Change, Conflict, Incoming, Lost, Side, VaultMeta};
use super::crypto::{
    b64, device_fingerprint, gcm_seal, member_mac, name_mac, normal_fingerprint, public_key, random_iv, random_key, ring_fingerprint, seal_value, sha256_hex,
    unb64, unwrapped_ring, wrap_key, wrap_ring,
};
use super::ledger::{self, Author, Fork, Log, Rejected, RingKey, ring_id};
use super::op::{self, Entry, EntryType, Kind, MemberKeys, Op, Rank, Removed, Request, RequestType, Served, ValueBody};
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
/// One sync pulls at most this many pages; the rest waits for the next.
const PULL_PAGES: usize = 20;
/// Ops held per author that isn't a member; past it the author is parked.
const PER_AUTHOR: usize = if cfg!(test) { 20 } else { 2000 };
/// Waiting ops held per member; past it its cursor waits until they apply.
const PER_MEMBER: usize = if cfg!(test) { 200 } else { 20_000 };
/// Devices that aren't members whose ops are held at all.
const NONMEMBER_AUTHORS: usize = 50;
/// The ciphertext held waiting, across every author.
const HELD_BYTES: usize = 64 * 1024 * 1024;
/// Refusals kept per author.
const REJECTED_PER_AUTHOR: usize = 20;
/// Changes remembered, so one recorded again after a crash isn't a new op.
const OWN_CHANGES: usize = 512;
/// How far ahead of now an op's `at` may be (the edge's own limit).
const AHEAD_MS: u64 = 300_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct State {
    pub edge: String,
    pub device: String,
    /// Ring keys, each wrapped (ECIES) to this member's key-agreement key.
    #[serde(default)]
    pub ring: Vec<RingEntry>,
    /// The ring this member pinned (`harar edge sync trust`), or founded.
    #[serde(default)]
    pub trusted: Option<String>,
    #[serde(default)]
    pub founded: bool,
    /// The ring this member gave its own up for, when the person pinned it.
    #[serde(default)]
    pub fell_back: Option<String>,
    #[serde(default)]
    pub requested: bool,
    /// The pull cursor: each author's last linked seq.
    #[serde(default)]
    pub next: BTreeMap<String, u64>,
    #[serde(default)]
    pub authors: BTreeMap<String, Author>,
    /// Every linked member.add and rekey op: the log, requests, and other
    /// rings' founders.
    #[serde(default)]
    pub member_ops: Vec<Served>,
    /// Linked secret ops not applied yet.
    #[serde(default)]
    pub pending: Vec<Served>,
    /// Authors that aren't members and hit PER_AUTHOR: their cursors stay
    /// put and pulls skip them until the log makes them members.
    #[serde(default)]
    pub parked: BTreeSet<String>,
    /// Each (author, secret key)'s highest-ranked op that counted.
    #[serde(default)]
    pub key_tips: BTreeMap<String, Rank>,
    #[serde(default)]
    pub rejected: Vec<Rejected>,
    #[serde(default)]
    pub forks: Vec<Fork>,
    /// Forged ops refused (their authors' chains pulled again).
    #[serde(default)]
    pub forged: Vec<Rejected>,
    /// This member's ops not yet on the edge, in seq order; unsigned until
    /// the sync that sends them.
    #[serde(default)]
    pub outbox: Vec<Op>,
    /// The newest op this member wrote: its seq, hash and time.
    #[serde(default)]
    pub tip: Tip,
    /// The highest seq this member ever wrote: it never writes at or below.
    #[serde(default)]
    pub high_seq: u64,
    /// The highest seq the edge has acknowledged taking from this member.
    #[serde(default)]
    pub acked_seq: u64,
    /// Changes already written as ops: (tag, op hash, rank).
    #[serde(default)]
    pub own_changes: Vec<(String, String, Rank)>,
    /// Ops re-sequenced or re-dated: old hash to (new hash, new seq, new at),
    /// until the vault's record of them is updated.
    #[serde(default)]
    pub renamed: BTreeMap<String, (String, u64, u64)>,
    /// The discovery cursor the edge handed back: everyone not followed in
    /// `since` comes through it.
    #[serde(default)]
    pub discover: String,
    /// The edge showed ops of this device past the highest it knew it wrote:
    /// this state was restored from an older copy. Nothing is signed until a
    /// full pull has made the edge's view the base.
    #[serde(default)]
    pub restored: bool,
    /// `reset-edge-view` was run: the next full pull's view of this device's
    /// chain is the base, acknowledged seq included. Nothing is signed until.
    #[serde(default)]
    pub adopt_edge: bool,
    /// Changed with every step, and kept in the vault too (`VaultMeta`).
    #[serde(default)]
    pub mark: u64,
    /// The mark before: a vault that holds it is one step behind (the agent
    /// stopped between saving this state and saving the vault), which the
    /// ops still held here cover (`applied` lets them go only after).
    #[serde(default)]
    pub prev_mark: u64,
    /// Devices that aren't members, beyond the NONMEMBER_AUTHORS held: only
    /// counted.
    #[serde(default)]
    pub unheld_authors: u64,
    /// Waiting ops let go because no epoch's key opens them.
    #[serde(default)]
    pub unopenable: u64,
    #[serde(default)]
    pub rebased: u64,
    /// What's wrong with this member's chain on the edge, if anything.
    #[serde(default)]
    pub chain_error: Option<String>,
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
}

pub(crate) fn state_path(url: &str) -> Result<PathBuf> {
    Ok(crate::common::ensure_state_subdir("sync")?.join(format!("{}.json", &super::crypto::hex(Sha256::digest(url.as_bytes()))[..16])))
}

/// A random nonzero-ish mark for the vault and the state to share.
fn rand_mark() -> u64 {
    use p256::elliptic_curve::rand_core::{OsRng, RngCore};
    OsRng.next_u64()
}

/// The epoch after `epoch`, or an error at the last one.
pub(crate) fn next_epoch(epoch: u32) -> Result<u32> {
    epoch.checked_add(1).ok_or_else(|| anyhow!("the ring is at its last epoch; it can't be rekeyed"))
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
    /// Whether the last pull reached the end: a joiner's first step waits
    /// for one, and so does every membership change.
    pub pull_complete: bool,
    /// The log, followed once per change to the ring ops held.
    log_cache: std::cell::RefCell<Option<(LogKey, Log)>>,
}

/// What the cached log was followed from.
type LogKey = (usize, String, Option<String>);

/// What one step did to the vault.
#[derive(Debug, Default)]
pub(crate) struct Stepped {
    /// Paths whose value another member's op changed.
    pub changed: BTreeSet<String>,
    /// The waiting ops it applied: let them go (`applied`) once the vault
    /// is saved.
    pub applied: BTreeSet<String>,
}

/// A pull: the ops, whether it reached the end, and the discovery cursor.
pub(crate) struct Pulled {
    pub ops: Vec<Served>,
    pub complete: bool,
    pub discover: String,
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
        Ok(Member { edge, state, path, agree_pub, sign_pub, keys: None, pull_complete: false, log_cache: Default::default() })
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

    /// This device's fingerprint: what the authority checks before approving.
    pub(crate) fn fingerprint(&self) -> String {
        device_fingerprint(&self.sign_pub, &self.agree_pub)
    }

    pub(crate) fn own_keys(&self) -> MemberKeys {
        MemberKeys { device: self.edge.device.clone(), name: self.edge.name.clone(), sign_pub: b64(&self.sign_pub), agree_pub: b64(&self.agree_pub) }
    }

    /// The membership log, as this member follows it. Needs no ring key;
    /// followed again only when the ring ops held change.
    pub(crate) fn log(&self) -> Log {
        let key: LogKey = (
            self.state.member_ops.len(),
            self.state.member_ops.iter().map(|o| o.hash.as_str()).collect::<Vec<_>>().join(""),
            self.state.trusted.clone(),
        );
        let key = (key.0, super::crypto::sha256_hex(&key.1), key.2);
        if let Some((k, log)) = self.log_cache.borrow().as_ref()
            && *k == key
        {
            return log.clone();
        }
        let log = ledger::follow(&self.state.member_ops, self.state.trusted.as_deref(), self.me());
        *self.log_cache.borrow_mut() = Some((key, log.clone()));
        log
    }

    // ------------------------------------------------------------ ingest

    /// What to send as `since`: this device and the log's members (removed
    /// ones while their chain hasn't reached its cut). Everyone else comes
    /// through the discovery cursor, so `since` never grows with them.
    pub(crate) fn since(&self) -> BTreeMap<String, u64> {
        let log = self.log();
        let mut since = BTreeMap::new();
        let mut follow = |a: &str| {
            since.insert(a.to_owned(), self.state.next.get(a).copied().unwrap_or(0));
        };
        follow(self.me());
        for m in log.members.values() {
            match log.cut_of(&m.keys.device) {
                Some((after, _)) if self.state.next.get(&m.keys.device).copied().unwrap_or(0) >= after => {}
                _ => follow(&m.keys.device),
            }
        }
        since
    }

    /// Takes pulled ops: each author's chain is linked, the ring's ops kept,
    /// and secret ops queued until they can be applied. What an author can
    /// make this member hold is bounded: a removed one's ops past its cut are
    /// let go as they come; a member's waiting ops stop at PER_MEMBER (its
    /// cursor waits); at most NONMEMBER_AUTHORS devices that aren't members
    /// are held at all, PER_AUTHOR ops each (then parked); and the waiting
    /// ciphertext stops at HELD_BYTES. Nothing past a cursor is ever taken
    /// and then let go: what isn't taken is pulled again.
    pub(crate) fn ingest(&mut self, ops: Vec<Served>) {
        let me = self.edge.device.clone();
        let log = self.log();
        let mut held: BTreeMap<String, usize> = BTreeMap::new();
        for op in self.state.pending.iter().chain(self.state.member_ops.iter()) {
            *held.entry(op.author.clone()).or_default() += 1;
        }
        let mut nonmembers: BTreeSet<String> = held.keys().filter(|a| **a != me && !log.members.contains_key(*a)).cloned().collect();
        let mut bytes: usize = self.state.pending.iter().map(|o| o.sealed.as_ref().map_or(0, String::len)).sum();
        let mut stopped: BTreeSet<String> = BTreeSet::new();
        let mut taken = Vec::new();
        let own_key = b64(&self.sign_pub);
        for op in ops {
            if stopped.contains(&op.author) {
                continue;
            }
            if op.author == me {
                if !ledger::signed_by(&op, &own_key) {
                    // Not ours, whatever it says: the edge made it.
                    self.reject(Rejected { author: op.author.clone(), seq: op.seq, reason: "forged: an op in this device's name it never signed".into() });
                    stopped.insert(op.author.clone());
                    continue;
                }
                if op.seq > self.state.high_seq || self.state.outbox.iter().any(|o| o.seq == op.seq && o.hash() != op.hash) {
                    // The edge has ops of ours we didn't know we wrote (past
                    // our newest, or at a seq we queued another op at): this
                    // state was restored. Nothing is signed until a full pull
                    // makes the edge's view the base (`rebase`).
                    self.state.restored = true;
                }
                taken.push(op);
                continue;
            }
            if let Some((after, _)) = log.cut_of(&op.author)
                && op.seq > after
            {
                self.reject(Rejected { author: op.author.clone(), seq: op.seq, reason: format!("written after its author was removed (its last op that counts is {after}): dropped") });
                stopped.insert(op.author.clone());
                continue;
            }
            let n = held.entry(op.author.clone()).or_default();
            let size = op.sealed.as_ref().map_or(0, String::len);
            if log.members.contains_key(&op.author) {
                if op.kind.is_value() && (*n >= PER_MEMBER || bytes + size > HELD_BYTES) {
                    stopped.insert(op.author.clone());
                    continue;
                }
            } else {
                if self.state.parked.contains(&op.author) || *n >= PER_AUTHOR || bytes + size > HELD_BYTES {
                    self.state.parked.insert(op.author.clone());
                    stopped.insert(op.author.clone());
                    continue;
                }
                if !nonmembers.contains(&op.author) {
                    if nonmembers.len() >= NONMEMBER_AUTHORS {
                        self.state.unheld_authors += 1;
                        stopped.insert(op.author.clone());
                        continue;
                    }
                    nonmembers.insert(op.author.clone());
                }
            }
            *n += 1;
            bytes += size;
            taken.push(op);
        }
        let linked = ledger::link_chains(&mut self.state.authors, &me, taken);
        for r in linked.rejected {
            self.reject(r);
        }
        // A fork only on proof: the second op verifies under the key the log
        // gives its author (the first was linked and verified already).
        // Anything else is bogus: refused, and the author goes on.
        for op in linked.conflicts {
            let proven = log.members.get(&op.author).is_some_and(|m| ledger::signed_by(&op, &m.keys.sign_pub));
            if !proven {
                self.reject(Rejected { author: op.author.clone(), seq: op.seq, reason: "forged: a second op at a seq held, not signed by its author".into() });
                continue;
            }
            let known = self.state.authors.get(&op.author).and_then(|a| a.recent.get(&op.seq).cloned()).unwrap_or_default();
            if let Some(a) = self.state.authors.get_mut(&op.author) {
                a.fork_at = Some(a.fork_at.map_or(op.seq, |f| f.min(op.seq)));
            }
            if !self.state.forks.iter().any(|f| f.author == op.author && f.seq == op.seq) {
                self.state.forks.push(Fork { author: op.author.clone(), seq: op.seq, hashes: [known, op.hash.clone()], evidence: op });
            }
        }
        for op in linked.good {
            let at = self.state.next.entry(op.author.clone()).or_insert(0);
            *at = (*at).max(op.seq);
            if op.author == me {
                // Already on the edge: never send it again.
                self.state.outbox.retain(|o| o.hash() != op.hash);
                self.state.acked_seq = self.state.acked_seq.max(op.seq);
            }
            if !op.kind.is_value() {
                if !self.state.member_ops.iter().any(|o| o.hash == op.hash) {
                    self.state.member_ops.push(op);
                }
            } else if op.author != me {
                self.state.pending.push(op);
            }
        }
        self.settle_log();
        // A removal that came in this batch cuts what the batch brought too.
        let log = self.log();
        let mut dropped: BTreeSet<String> = BTreeSet::new();
        let mut cut = Vec::new();
        self.state.pending.retain(|op| match log.cut_of(&op.author) {
            Some((after, _)) if op.seq > after => {
                if dropped.insert(op.author.clone()) {
                    cut.push(Rejected { author: op.author.clone(), seq: op.seq, reason: format!("written after its author was removed (its last op that counts is {after}): dropped") });
                }
                false
            }
            _ => true,
        });
        for r in cut {
            self.reject(r);
        }
    }

    fn reject(&mut self, r: Rejected) {
        if self.state.rejected.iter().any(|x| x.author == r.author && x.seq == r.seq) {
            return;
        }
        self.state.rejected.push(r);
        let author = self.state.rejected.last().expect("pushed").author.clone();
        while self.state.rejected.iter().filter(|x| x.author == author).count() > REJECTED_PER_AUTHOR {
            let i = self.state.rejected.iter().position(|x| x.author == author).expect("over");
            self.state.rejected.remove(i);
        }
    }

    /// After the log changed: members are unparked, and a member's op that
    /// doesn't verify with the key the log gives it is refused as forged and
    /// its chain goes back to before it, to be pulled again.
    fn settle_log(&mut self) {
        let log = self.log();
        self.state.parked.retain(|a| !log.members.contains_key(a));
        let mut forged = log.forged.clone();
        // Every op a member wrote is signed by the key the log gives it; one
        // that isn't (a first op the edge forged for it, say) is refused.
        for op in self.state.member_ops.iter().chain(self.state.pending.iter()) {
            if let Some(m) = log.members.get(&op.author)
                && op.author != self.edge.device
                && !ledger::signed_by(op, &m.keys.sign_pub)
            {
                forged.push(Rejected { author: op.author.clone(), seq: op.seq, reason: "forged: not signed by the key the log gives its author".into() });
            }
        }
        // The earliest forged op per author: its chain goes back to before it.
        let mut first: BTreeMap<String, Rejected> = BTreeMap::new();
        for f in forged {
            if first.get(&f.author).is_none_or(|x| f.seq < x.seq) {
                first.insert(f.author.clone(), f);
            }
        }
        for f in first.into_values() {
            self.forged(f);
        }
    }

    /// Refuses `f`'s op as forged: its author's chain, held ops and cursor go
    /// back to before it, so the next pull asks for it again.
    fn forged(&mut self, f: Rejected) {
        let Some(prev) = self.state.member_ops.iter().chain(self.state.pending.iter()).find(|o| o.author == f.author && o.seq == f.seq).map(|o| o.prev.clone()) else { return };
        self.state.member_ops.retain(|o| o.author != f.author || o.seq < f.seq);
        self.state.pending.retain(|o| o.author != f.author || o.seq < f.seq);
        if let Some(a) = self.state.authors.get_mut(&f.author) {
            a.back_to(f.seq, &prev);
        }
        self.state.next.insert(f.author.clone(), f.seq.saturating_sub(1));
        if !self.state.forged.iter().any(|x| x.author == f.author && x.seq == f.seq) {
            self.state.forged.push(f);
        }
        if self.state.forged.len() > 100 {
            self.state.forged.remove(0);
        }
    }

    /// After a full pull: checks this member's chain on the edge.
    /// - The edge showed ops of this device past the highest it knew (this
    ///   state was restored): the edge's view becomes the base, and the
    ///   queued ops follow its newest. Only then is anything signed again.
    /// - The edge shows fewer of this device's ops than it acknowledged: it
    ///   is withholding them; refused, nothing re-signed (an edge restored
    ///   from a backup needs `reset_edge_view`).
    ///
    /// A seq is never reused otherwise.
    pub(crate) fn rebase(&mut self) {
        let (seq, hash) = self.edge_tip();
        if self.state.adopt_edge {
            self.state.acked_seq = seq;
            self.state.high_seq = seq;
            self.state.tip = Tip { seq, hash: hash.clone(), at: self.state.tip.at };
            self.resequence(seq, hash);
            self.state.adopt_edge = false;
            self.state.restored = false;
            self.state.chain_error = None;
            return;
        }
        if self.state.restored {
            self.state.high_seq = self.state.high_seq.max(seq);
            self.state.acked_seq = self.state.acked_seq.max(seq);
            self.state.tip = Tip { seq, hash: hash.clone(), at: self.state.tip.at };
            self.resequence(seq, hash);
            self.state.restored = false;
            self.state.chain_error = None;
            return;
        }
        if seq < self.state.acked_seq {
            self.state.chain_error = Some(format!("the edge is withholding this device's ops: it took up to {}, and shows {seq}; if the edge was restored from a backup, run harar edge sync reset-edge-view", self.state.acked_seq));
            return;
        }
        if self.state.chain_error.as_deref().is_some_and(|e| e.starts_with("the edge is withholding")) {
            self.state.chain_error = None;
        }
    }

    /// The edge's newest op of this device: its seq and hash.
    fn edge_tip(&self) -> (u64, String) {
        self.state.authors.get(self.me()).map(|a| (a.seq, a.hash.clone())).unwrap_or((0, String::new()))
    }

    /// Writes the queued ops again after `seq`/`hash`, unsigned; the vault
    /// learns their new hashes.
    fn resequence(&mut self, seq: u64, hash: String) {
        if self.state.outbox.first().is_none_or(|first| first.seq == seq + 1 && first.prev == hash) {
            return;
        }
        let mut prev = (seq, hash);
        self.rewrite_outbox(|op| {
            op.seq = prev.0 + 1;
            op.prev = prev.1.clone();
            prev = (op.seq, op.hash());
        });
    }

    /// Rewrites each queued op with `f` (which may change its seq, prev or
    /// at; each op's prev is kept chained), clears its signature, and tells
    /// the vault and the ring ops held about the new hashes.
    fn rewrite_outbox(&mut self, mut f: impl FnMut(&mut Op)) {
        let mut moved = Vec::new();
        let mut prev: Option<String> = None;
        for op in &mut self.state.outbox {
            let old = op.hash();
            if let Some(p) = &prev {
                op.prev = p.clone();
            }
            f(op);
            op.sig = String::new();
            let new = op.hash();
            prev = Some(new.clone());
            if new != old {
                moved.push((old, new, op.clone()));
            }
        }
        for (old, new, op) in moved {
            if let Some(m) = self.state.member_ops.iter_mut().find(|o| o.hash == old) {
                *m = Served::from(&op);
            }
            for (_, h, r) in &mut self.state.own_changes {
                if *h == old {
                    *h = new.clone();
                    r.seq = op.seq;
                    r.at = op.at;
                }
            }
            for v in self.state.renamed.values_mut() {
                if v.0 == old {
                    *v = (new.clone(), op.seq, op.at);
                }
            }
            self.state.renamed.insert(old, (new, op.seq, op.at));
            self.state.rebased += 1;
        }
        if let Some(last) = self.state.outbox.last() {
            self.state.high_seq = self.state.high_seq.max(last.seq);
            self.state.tip = Tip { seq: last.seq, hash: last.hash(), at: self.state.tip.at.max(last.at) };
        }
    }

    /// Whether the queued ops follow the edge's newest op of this device.
    fn outbox_follows_edge(&self) -> bool {
        let (seq, hash) = self.edge_tip();
        self.state.outbox.first().is_none_or(|first| first.seq == seq + 1 && first.prev == hash) || self.state.outbox.first().is_some_and(|f| f.seq > seq + 1)
    }

    /// Membership changes are refused unless this member has a full, clean
    /// view: the last pull reached the end, the edge's view of its chain is
    /// sound, and nothing waits on a restore. A restored device must complete
    /// a full sync before it acts.
    fn may_change_membership(&self) -> Result<()> {
        if !self.pull_complete {
            bail!("this machine hasn't completed a full sync since it started; run harar edge sync now first");
        }
        if self.state.restored || self.state.adopt_edge {
            bail!("this machine's view of its own chain is being taken again from the edge; run harar edge sync now first");
        }
        if let Some(err) = &self.state.chain_error {
            bail!("this machine's chain on the edge isn't sound ({err}); fix that first");
        }
        if !self.outbox_follows_edge() {
            bail!("this machine's queued ops don't follow its chain on the edge yet; run harar edge sync now first");
        }
        if let Some(n) = self.log().fork {
            // Two entries at one place, both the authority's: membership
            // stays as it was before them, everywhere alike, and values go
            // on under the heads before the fork.
            bail!("the membership log forks at entry {n} (status.log): membership is frozen there");
        }
        Ok(())
    }

    /// After the edge's database was restored from a backup (it shows fewer
    /// of this device's ops than it once took): after a full pull, takes the
    /// edge's view as the base. Explicit, and logged: members that saw the
    /// ops the edge lost may see this device fork.
    pub(crate) fn reset_edge_view(&mut self) -> Result<Value> {
        let me = self.edge.device.clone();
        let was = self.state.acked_seq;
        eprintln!("harar agent: reset-edge-view on {}: this device's chain (acknowledged up to {was}) is taken again from the edge at the next full pull", self.edge.url);
        // What this device knows of its own chain goes; the next full pull
        // brings the edge's, and `rebase` makes it the base.
        self.state.authors.remove(&me);
        self.state.next.remove(&me);
        self.state.adopt_edge = true;
        self.state.chain_error = None;
        Ok(json!({ "reset": true, "was": was }))
    }

    // ------------------------------------------------------------ keys

    /// Opens the ring keys this member holds (asking the enclave once while
    /// the vault stays unlocked), plus any the log gives it.
    fn open_keys(&mut self, log: &Log) -> Result<()> {
        let agreement = self.agreement()?;
        let me = self.edge.device.clone();
        let unwrap = |sealed: &[u8]| agreement.open(sealed);
        let mut keys = match self.keys.take() {
            Some(keys) => keys,
            None => {
                let mut keys = Vec::new();
                for entry in &self.state.ring {
                    let plain = unwrap(&unb64(&entry.wrapped)?).context("open this member's ring key")?;
                    let key = unwrapped_ring(&plain, entry.epoch, &me).ok_or_else(|| anyhow!("this member's ring key file is not for this device"))?;
                    keys.push(RingKey { epoch: entry.epoch, key });
                }
                keys
            }
        };
        if ledger::reach_keys(&me, log, &mut keys, &unwrap) {
            self.keep_keys(&keys)?;
        }
        self.keys = Some(keys);
        Ok(())
    }

    /// Writes `keys` to the state, each wrapped to this member's own key.
    fn keep_keys(&mut self, keys: &[RingKey]) -> Result<()> {
        let mine = public_key(&self.agree_pub)?;
        let me = self.edge.device.clone();
        self.state.ring = keys.iter().map(|k| RingEntry { epoch: k.epoch, wrapped: b64(wrap_ring(&mine, k.epoch, &me, &k.key)) }).collect();
        if !keys.is_empty() {
            self.state.requested = false;
        }
        Ok(())
    }

    /// The log, with the ring keys opened.
    pub(crate) fn opened(&mut self) -> Result<Log> {
        let log = self.log();
        self.open_keys(&log)?;
        Ok(log)
    }

    /// The key new writes use: the log's current epoch's, if held.
    fn current(&self, log: &Log) -> Option<(u32, Key)> {
        let (epoch, id) = log.epoch()?;
        self.keys.as_deref()?.iter().find(|k| k.epoch == epoch && ring_id(&k.key, epoch) == id).map(|k| (epoch, k.key.clone()))
    }

    /// The ring's fingerprint, when this member founded or pinned one.
    #[cfg(test)]
    pub(crate) fn ring_fingerprint(&self) -> Option<String> {
        self.state.trusted.clone()
    }

    // ------------------------------------------------------------ writing ops

    /// This member's next op, unsigned, queued. `at` is never before
    /// `min_at` nor this member's last op, and never more than 5 minutes
    /// past now.
    pub(crate) fn write(&mut self, kind: Kind, key: String, version: u64, sealed: String, wrapped_key: String, min_at: u64) -> Op {
        let now = now_ms();
        let at = now.max(self.state.tip.at).max(min_at).min(now + AHEAD_MS);
        self.write_at(kind, key, version, sealed, wrapped_key, at)
    }

    /// The same, at exactly `at` (a joiner's own older values: 0, the lowest).
    fn write_at(&mut self, kind: Kind, key: String, version: u64, sealed: String, wrapped_key: String, at: u64) -> Op {
        let me = self.edge.device.clone();
        let seq = self.state.tip.seq.max(self.state.high_seq) + 1;
        let op = Op { author: me.clone(), seq, prev: self.state.tip.hash.clone(), kind, key, version, sealed, wrapped_key, at, sig: String::new() };
        let hash = op.hash();
        self.state.tip = Tip { seq: op.seq, hash, at: self.state.tip.at.max(at) };
        self.state.high_seq = seq;
        if !kind.is_value() {
            self.state.member_ops.push(Served::from(&op));
        }
        self.state.outbox.push(op.clone());
        op
    }

    /// The queued ops not signed yet. None while this state may be a restored
    /// one: nothing is signed until a full pull has made the edge's view the
    /// base, so no seq is ever signed twice.
    pub(crate) fn unsigned(&self) -> Vec<Op> {
        if self.state.restored || self.state.adopt_edge {
            return Vec::new();
        }
        self.state.outbox.iter().filter(|o| o.sig.is_empty()).cloned().collect()
    }

    /// Signs `ops` with the device key (outside the agent's lock).
    pub(crate) fn sign(device: &DeviceKey, ops: Vec<Op>) -> Result<Vec<Op>> {
        ops.into_iter()
            .map(|mut op| {
                op.sig = b64(device.sign(op.canonical().as_bytes())?);
                Ok(op)
            })
            .collect()
    }

    /// Puts signatures on the queued ops they belong to (by hash, which the
    /// signature doesn't change).
    pub(crate) fn signed(&mut self, ops: Vec<Op>) {
        let by_hash: HashMap<String, String> = ops.into_iter().map(|o| (o.hash(), o.sig)).collect();
        for op in &mut self.state.outbox {
            if let Some(sig) = by_hash.get(&op.hash()) {
                op.sig = sig.clone();
            }
        }
        for m in &mut self.state.member_ops {
            if let Some(sig) = by_hash.get(&m.hash) {
                m.sig = sig.clone();
            }
        }
    }

    /// The queued ops ready to send: signed, from the first on. None while
    /// the edge is withholding this member's ops.
    pub(crate) fn ready(&self) -> Vec<Op> {
        if self.state.chain_error.is_some() {
            return Vec::new();
        }
        self.state.outbox.iter().take_while(|o| !o.sig.is_empty()).cloned().collect()
    }

    /// Signs every queued op, in one go: for tests, which hold no lock.
    #[cfg(test)]
    pub(crate) fn sign_all(&mut self) -> Result<()> {
        let signed = Self::sign(&self.edge.key()?, self.unsigned())?;
        self.signed(signed);
        Ok(())
    }

    /// Writes the next entry of the log (this member being its authority).
    fn write_entry(&mut self, log: &Log, what: EntryType, epoch: u32, id: String, fill: impl FnOnce(&mut Entry), back: String) -> Op {
        let mut entry = Entry { what, n: log.entries.len() as u64, prev: log.head().unwrap_or_default().to_owned(), epoch, id, member: None, removed: Vec::new(), authority: None, wraps: BTreeMap::new() };
        fill(&mut entry);
        let sealed = op::plain_body(&entry);
        let key = op::entry_key(&op::head_of(&sealed));
        let kind = if what == EntryType::Remove { Kind::Rekey } else { Kind::MemberAdd };
        self.write(kind, key, entry.n, sealed, back, 0)
    }

    /// The authority only: what it does, or why this machine can't.
    fn as_authority(&self, log: &Log, doing: &str) -> Result<()> {
        match log.current_authority() {
            Some(a) if a == self.me() => self.may_change_membership(),
            Some(a) => bail!("only the ring's authority can {doing}: that is {a} ({}); run it there", log.members.get(a).map_or("?", |m| m.keys.name.as_str())),
            None => bail!("this machine isn't a member of the ring, so it can't {doing}"),
        }
    }

    /// Founds the ring when the edge has no ops yet, or asks to join the one
    /// it has. Never gives a ring up by itself (only `trust` does), and
    /// opens no ring key, so the worker can run it with the vault locked.
    pub(crate) fn found_or_request(&mut self) -> Result<Option<&'static str>> {
        if !self.state.ring.is_empty() || self.state.founded {
            return Ok(None);
        }
        let others = self.state.authors.keys().any(|a| *a != self.edge.device) || !self.state.rejected.is_empty();
        if !others && self.state.member_ops.is_empty() && self.state.fell_back.is_none() {
            let ring = random_key();
            let mine = public_key(&self.agree_pub)?;
            let me = self.edge.device.clone();
            let own = self.own_keys();
            let wrap = b64(wrap_ring(&mine, 0, &me, &ring));
            self.write_entry(&Log::default(), EntryType::Found, 0, ring_id(&ring, 0), |e| {
                e.member = Some(own);
                e.wraps.insert(me.clone(), wrap);
            }, String::new());
            let keys = vec![RingKey { epoch: 0, key: ring }];
            self.keep_keys(&keys)?;
            self.keys = Some(keys);
            self.state.founded = true;
            self.state.trusted = Some(ring_fingerprint(&self.sign_pub, &self.agree_pub));
            return Ok(Some("founded"));
        }
        if self.state.requested {
            return Ok(None);
        }
        let request = Request { what: RequestType::Request, member: self.own_keys() };
        self.write(Kind::MemberAdd, op::request_key(self.me()), 0, op::plain_body(&request), String::new(), 0);
        self.state.requested = true;
        Ok(Some("requested"))
    }

    /// Pins the ring to join by its fingerprint (from `harar edge sync
    /// status` on any member). Until then, no log is followed. A founder whose
    /// ring has no other member gives its own up for the one pinned (two
    /// rings founded at once): only the person decides that, never the code.
    pub(crate) fn trust(&mut self, fingerprint: &str) -> Result<Value> {
        let fp = normal_fingerprint(fingerprint).ok_or_else(|| anyhow!("{fingerprint:?} is not a ring fingerprint: 32 hex, in groups of four"))?;
        if self.state.trusted.as_deref().is_some_and(|t| t != fp) && (!self.state.ring.is_empty() || self.state.founded) {
            let log = self.log();
            if !self.state.founded || log.members.keys().any(|id| *id != self.edge.device) {
                bail!("this machine is already a member of the ring {}", self.state.trusted.as_deref().unwrap_or("?"));
            }
            self.state.ring.clear();
            self.keys = None;
            self.state.founded = false;
            self.state.requested = false;
            self.state.fell_back = Some(fp.clone());
        }
        self.state.trusted = Some(fp.clone());
        Ok(json!({ "trusted": fp }))
    }

    /// The authority adds `device`, which asked to join and whose fingerprint
    /// the person read on it: an `add` entry wrapping the current key to it.
    pub(crate) fn approve(&mut self, device: &str, fingerprint: &str) -> Result<Value> {
        let log = self.opened()?;
        self.as_authority(&log, "approve a device")?;
        if log.members.contains_key(device) {
            bail!("{device} is a member already, or was one (a removed device pairs again, as a new device)");
        }
        let Some(request) = log.requests.get(device).cloned() else {
            bail!("{device} hasn't asked to join; run harar edge sync on there first (then harar edge sync now here)");
        };
        let theirs = device_fingerprint(&unb64(&request.sign_pub)?, &unb64(&request.agree_pub)?);
        let Some(typed) = normal_fingerprint(fingerprint) else { bail!("{fingerprint:?} is not a device fingerprint: 32 hex, in groups of four") };
        if typed != theirs {
            bail!("{device}'s request has the fingerprint {theirs}, not {typed}: don't approve it unless it is the device in front of you");
        }
        let (epoch, ring) = self.current(&log).ok_or_else(|| anyhow!("this machine doesn't hold the ring's current key"))?;
        let recipient = public_key(&unb64(&request.agree_pub)?)?;
        let wrap = b64(wrap_ring(&recipient, epoch, device, &ring));
        let name = request.name.clone();
        self.write_entry(&log, EntryType::Add, epoch, ring_id(&ring, epoch), |e| {
            e.member = Some(request);
            e.wraps.insert(device.to_owned(), wrap);
        }, String::new());
        Ok(json!({ "approved": device, "name": name, "fingerprint": theirs }))
    }

    /// The authority removes `device`: one `remove` entry that names it,
    /// with a new epoch key wrapped to every member that remains. Returns
    /// None when `device` isn't a member.
    pub(crate) fn remove(&mut self, device: &str) -> Result<Option<Value>> {
        let log = self.opened()?;
        self.as_authority(&log, "remove a device")?;
        if device == self.me() || !log.is_active(device) {
            return Ok(None);
        }
        let (epoch, old) = self.current(&log).ok_or_else(|| anyhow!("this machine doesn't hold the ring's current key"))?;
        let next = next_epoch(epoch)?;
        let (after, after_hash) = self.state.authors.get(device).map_or((0, String::new()), |a| (a.seq, a.hash.clone()));
        let new = random_key();
        let mut wraps = BTreeMap::new();
        for m in log.active().filter(|m| m.keys.device != device) {
            wraps.insert(m.keys.device.clone(), b64(wrap_ring(&public_key(&unb64(&m.keys.agree_pub)?)?, next, &m.keys.device, &new)));
        }
        let back = b64(gcm_seal(&wrap_key(&new), &*old, op::rekey_ad(next).as_bytes(), random_iv()));
        self.write_entry(&log, EntryType::Remove, next, ring_id(&new, next), |e| {
            e.removed = vec![Removed { device: device.to_owned(), after, after_hash }];
            e.wraps = wraps;
        }, back);
        let mut keys = self.keys.take().unwrap_or_default();
        keys.push(RingKey { epoch: next, key: new });
        self.keep_keys(&keys)?;
        self.keys = Some(keys);
        Ok(Some(json!({ "removed": device, "after": after, "epoch": next })))
    }

    /// The authority hands its role to `device`, an active member.
    pub(crate) fn transfer(&mut self, device: &str) -> Result<Value> {
        let log = self.log();
        self.as_authority(&log, "hand the authority over")?;
        if device == self.me() || !log.is_active(device) {
            bail!("{device} isn't another active member of the ring");
        }
        let (epoch, id) = log.epoch().map(|(e, id)| (e, id.to_owned())).expect("a member");
        self.write_entry(&log, EntryType::Transfer, epoch, id, |e| e.authority = Some(device.to_owned()), String::new());
        Ok(json!({ "authority": device }))
    }

    // ------------------------------------------------------------ the vault

    /// With the vault open: applies what other members wrote (last write
    /// wins), then turns what changed here into ops. `keys` is the vault.
    /// Nothing from the vault is sealed until this member holds the ring's
    /// current key and is a member. The waiting ops it applied are let go
    /// only after the vault is saved (`applied`).
    pub(crate) fn step(&mut self, keys: &mut HashMap<String, String>) -> Result<Stepped> {
        let log = self.opened()?;
        let Some(head) = log.head().map(str::to_owned) else { return Ok(Stepped::default()) };
        if !log.is_active(self.me()) || self.current(&log).is_none() {
            return Ok(Stepped::default());
        }
        let mut meta = VaultMeta::read(keys);
        if !self.state.renamed.is_empty() {
            meta.rename(&self.state.renamed);
            self.state.renamed.clear();
        }
        let first = meta.ring.as_deref() != log.founder();
        // The vault and this state are marked alike at every step: when they
        // differ, one was restored from an older copy, and what was applied
        // can't be told. The view starts over: everything is pulled again
        // (applying again is harmless).
        if !first && self.state.mark != 0 && meta.mark != self.state.mark && meta.mark != self.state.prev_mark {
            self.reset_view();
            meta.mark = 0;
            meta.write(keys);
            return Ok(Stepped::default());
        }
        // A joiner's first step waits for a pull that reached the end.
        if first && !self.state.founded && !self.pull_complete {
            return Ok(Stepped::default());
        }
        // Removals cut their device's ops: what came after a cut is taken
        // back, each path falling back to its best op that still counts.
        let mut revoked = BTreeSet::new();
        for m in log.members.values() {
            if let Some((after, _)) = log.cut_of(&m.keys.device) {
                revoked.extend(meta.revoke(keys, &m.keys.device, after));
            }
        }
        let incoming = self.open_pending(&log);
        let applied: BTreeSet<String> = incoming.iter().map(|i| i.hash.clone()).collect();
        let mut changed = if first {
            // Joining (or founding): the ring's current value wins. What the
            // vault held that differs goes to history, flagged; what the ring
            // lacks becomes this member's write at the lowest rank.
            meta.paths.clear();
            meta.ring = log.founder().map(str::to_owned);
            let (mut dry, mut view) = (VaultMeta::default(), keys.clone());
            dry.apply(&mut view, incoming.clone());
            let now = now_ms();
            let me = self.edge.device.clone();
            let local: Vec<String> = keys.keys().filter(|p| !p.starts_with("harar:")).cloned().collect();
            for path in local {
                let Some(theirs) = dry.paths.get(&path) else { continue };
                if view.get(&path) != keys.get(&path) {
                    let lost = Side { device: me.clone(), seq: 0, at: now, version: 0 };
                    meta.history.push(Lost { path: path.clone(), version: 0, rank: Rank { at: now, author: me.clone(), seq: 0 }, hash: String::new(), value: keys.get(&path).cloned(), lost_to: theirs.hash.clone() });
                    meta.conflicts.push(Conflict { path: path.clone(), kept: Side { device: theirs.rank.author.clone(), seq: theirs.rank.seq, at: theirs.rank.at, version: theirs.version }, lost });
                }
            }
            let changed = meta.apply(keys, incoming);
            if !self.state.founded {
                self.record_changes(&mut meta, keys, &log, &head, Some(0))?;
            }
            changed
        } else {
            // Changes here that no op records yet (sync was off) are
            // concurrent with what arrived: recorded first, so last write wins.
            self.record_changes(&mut meta, keys, &log, &head, None)?;
            meta.apply(keys, incoming)
        };
        self.record_changes(&mut meta, keys, &log, &head, None)?;
        changed.extend(revoked);
        meta.prune(now_ms());
        let mark = loop {
            let m = rand_mark();
            if m != 0 {
                break m;
            }
        };
        meta.mark = mark;
        self.state.prev_mark = self.state.mark;
        self.state.mark = mark;
        meta.write(keys);
        Ok(Stepped { changed, applied })
    }

    /// Starts this member's view of the edge over: cursors, chains and what
    /// it holds go, and the next pull brings everything again. Its ring keys,
    /// its own queued ops and its seqs stay.
    fn reset_view(&mut self) {
        let own: Vec<Served> = self.state.member_ops.iter().filter(|o| o.author == self.edge.device && o.sig.is_empty()).cloned().collect();
        let (high, acked) = (self.state.high_seq, self.state.acked_seq);
        self.state.next.clear();
        self.state.authors.clear();
        self.state.member_ops = own;
        self.state.pending.clear();
        self.state.parked.clear();
        self.state.discover.clear();
        self.state.key_tips.clear();
        self.state.mark = 0;
        self.state.prev_mark = 0;
        self.state.high_seq = high;
        self.state.acked_seq = acked;
        self.log_cache.borrow_mut().take();
    }

    /// The vault holding what `step` applied is saved: let those ops go.
    pub(crate) fn applied(&mut self, hashes: &BTreeSet<String>) {
        self.state.pending.retain(|op| !hashes.contains(&op.hash));
    }

    /// A change's tag: the same change gets the same tag, so after a crash
    /// between saving the ops and saving the vault it isn't written twice.
    fn change_tag(ring: &[u8; 32], epoch: u32, change: &Change) -> String {
        let value = change.value.as_deref().map(sha256_hex).unwrap_or_default();
        member_mac(ring, &format!("harar:change|{epoch}|{}|{}|{}|{value}", change.path, change.version, change.base))
    }

    /// Records the vault's changes as ops under `head`; with `at`, at exactly
    /// that time.
    fn record_changes(&mut self, meta: &mut VaultMeta, keys: &HashMap<String, String>, log: &Log, head: &str, at: Option<u64>) -> Result<()> {
        let changes = meta.changes(keys);
        if changes.is_empty() {
            return Ok(());
        }
        let (epoch, ring) = self.current(log).ok_or_else(|| anyhow!("no ring key to write with"))?;
        for change in changes {
            let tag = Self::change_tag(&ring, epoch, &change);
            if let Some((_, hash, rank)) = self.state.own_changes.iter().find(|(t, _, _)| *t == tag) {
                meta.record_own(&change, hash, rank.clone());
                continue;
            }
            let key = name_mac(&ring, &change.path);
            let body = ValueBody { path: change.path.clone(), value: change.value.clone(), base: change.base.clone(), head: head.to_owned() };
            let plain = Zeroizing::new(serde_json::to_vec(&body)?);
            let (sealed, wrapped) = seal_value(&ring, &key, change.version, &plain, None);
            if sealed.len() > MAX_SEALED {
                // The edge would refuse the whole push; this one stays here.
                eprintln!("harar agent: a secret of {} bytes is too large to sync (at most about {} KiB); it stays on this machine only", plain.len(), MAX_SEALED * 3 / 4 / 1024);
                continue;
            }
            // Later than what it replaces, so it outranks it everywhere.
            let min_at = meta.paths.get(&change.path).map_or(0, |m| m.rank.at.saturating_add(1));
            let op = match at {
                Some(at) => self.write_at(change.kind, key.clone(), change.version, sealed, wrapped, at),
                None => self.write(change.kind, key.clone(), change.version, sealed, wrapped, min_at),
            };
            let rank = Served::from(&op).rank();
            self.state.key_tips.insert(format!("{}|{key}", self.edge.device), rank.clone());
            meta.record_own(&change, &op.hash(), rank.clone());
            self.state.own_changes.push((tag, op.hash(), rank));
            if self.state.own_changes.len() > OWN_CHANGES {
                self.state.own_changes.remove(0);
            }
        }
        Ok(())
    }

    /// The waiting secret ops that count now, opened. One that names a head
    /// this member doesn't have is behind: it waits. One that doesn't count
    /// at its head is refused (forged ones pull their author's chain again).
    /// A compacted one counts only when a later op by its author on its key
    /// counted; otherwise it waits.
    fn open_pending(&mut self, log: &Log) -> Vec<Incoming> {
        let keys = self.keys.as_deref().unwrap_or_default();
        let now = now_ms();
        let mut out = Vec::new();
        let mut done: Vec<(String, Option<Rejected>)> = Vec::new();
        let mut forged = Vec::new();
        let mut tips: Vec<(String, Rank)> = Vec::new();
        let all_epochs = log.entries.iter().all(|l| keys.iter().any(|k| k.epoch == l.entry.epoch));
        let mut unopenable = 0;
        for op in &self.state.pending {
            let tip_key = format!("{}|{}", op.author, op.key);
            let Some((sealed, wrapped)) = op.ciphertext() else {
                if self.state.key_tips.get(&tip_key).is_some_and(|tip| *tip > op.rank()) {
                    done.push((op.hash.clone(), None));
                }
                continue;
            };
            if op.at > now + AHEAD_MS {
                continue;
            }
            let opened = keys.iter().find_map(|k| {
                let plain = super::crypto::open_value(&k.key, &op.key, op.version, sealed, wrapped).ok()?;
                let body: ValueBody = serde_json::from_slice(&plain).ok()?;
                (name_mac(&k.key, &body.path) == op.key).then_some((k.epoch, body))
            });
            let refuse = |reason: &str| Some(Rejected { author: op.author.clone(), seq: op.seq, reason: reason.to_owned() });
            let Some((epoch, body)) = opened else {
                // Every epoch's key is held and none opens it: it never will.
                if all_epochs {
                    done.push((op.hash.clone(), None));
                    unopenable += 1;
                }
                continue;
            };
            let Some(n) = log.heads.get(&body.head).copied() else { continue };
            if log.entries[n as usize].entry.epoch != epoch {
                done.push((op.hash.clone(), refuse("not sealed with the key of the head it names")));
                continue;
            }
            match log.counts(op, n, &self.state.authors) {
                ledger::Verdict::Counts => {}
                ledger::Verdict::Waits => continue,
                ledger::Verdict::Forged => {
                    forged.push(Rejected { author: op.author.clone(), seq: op.seq, reason: "forged: not signed by the key the log gives its author".into() });
                    continue;
                }
                ledger::Verdict::Refused(reason) => {
                    done.push((op.hash.clone(), refuse(reason)));
                    continue;
                }
            }
            if (op.kind == Kind::Delete) != body.value.is_none() || body.path.starts_with("harar:") || body.path.is_empty() {
                done.push((op.hash.clone(), refuse("what it holds doesn't match its kind")));
                continue;
            }
            tips.push((tip_key, op.rank()));
            out.push(Incoming { hash: op.hash.clone(), base: body.base, rank: op.rank(), version: op.version, path: body.path, value: body.value });
        }
        for (key, rank) in tips {
            let tip = self.state.key_tips.entry(key).or_insert_with(|| rank.clone());
            if rank > *tip {
                *tip = rank;
            }
        }
        for (hash, rejected) in done {
            self.state.pending.retain(|op| op.hash != hash);
            if let Some(r) = rejected {
                self.reject(r);
            }
        }
        for f in forged {
            self.forged(f);
        }
        self.state.unopenable += unopenable;
        out
    }

    // ------------------------------------------------------------ the edge

    /// How the next pull reads the authors it doesn't follow: through the
    /// discovery cursor once this member follows a ring; before that (it
    /// is deciding whether to found one, or waits to join), everything with
    /// no lag, so it never founds a second ring for missing an op stored a
    /// moment ago.
    pub(crate) fn discovery(&self) -> Option<String> {
        self.log().head().is_some().then(|| self.state.discover.clone())
    }

    /// The ops after the cursor, up to PULL_PAGES pages. Each page's `next`
    /// must move the cursor on, or the edge is refused. Without `discover`
    /// (`Member::discovery`), every author is read from `since` or 0, with
    /// no lag.
    pub(crate) fn pull(edge: &Paired, device: &DeviceKey, since: &BTreeMap<String, u64>, discovery: Option<&str>) -> Result<Pulled> {
        let mut since = since.clone();
        let mut discover = discovery.unwrap_or_default().to_owned();
        let mut ops = Vec::new();
        for _ in 0..PULL_PAGES {
            let body = match discovery {
                Some(_) => json!({ "since": since, "discover": discover }),
                None => json!({ "since": since }),
            };
            let page = edge.call_with(device, "POST", "/v1/sync", Some(&body))?;
            let got: Vec<Served> = serde_json::from_value(page["ops"].clone()).context("the edge's ops")?;
            let next: BTreeMap<String, u64> = serde_json::from_value(page["next"].clone()).context("the edge's next")?;
            let found = page["discover"].as_str().unwrap_or(&discover).to_owned();
            let more = page["more"] == Value::Bool(true);
            let moved = (next.iter().any(|(a, s)| since.get(a).is_none_or(|old| s > old)) || found > discover) && next.iter().all(|(a, s)| since.get(a).is_none_or(|old| s >= old)) && found >= discover;
            if more && !moved {
                bail!("{} says there is more to pull but doesn't move the cursor on", edge.url);
            }
            ops.extend(got);
            since = next;
            discover = found;
            if !more {
                return Ok(Pulled { ops, complete: true, discover });
            }
        }
        Ok(Pulled { ops, complete: false, discover })
    }

    /// Sends `ops` in batches the edge takes: how many were sent, and the
    /// error that stopped the rest (they stay queued).
    pub(crate) fn push(edge: &Paired, device: &DeviceKey, ops: &[Op]) -> (usize, Result<()>) {
        let mut sent = 0;
        while sent < ops.len() {
            let mut end = sent;
            let mut bytes = 0;
            while end < ops.len() && end - sent < PUSH_OPS {
                let size = serde_json::to_vec(&ops[end]).map_or(0, |b| b.len());
                if end > sent && bytes + size > PUSH_BYTES {
                    break;
                }
                bytes += size;
                end += 1;
            }
            if let Err(err) = edge.call_with(device, "PUT", "/v1/sync", Some(&json!({ "ops": &ops[sent..end] }))) {
                return (sent, Err(err));
            }
            sent = end;
        }
        (sent, Ok(()))
    }

    /// Takes the ops a push sent out of the outbox, and notes how far the
    /// edge has acknowledged this member's chain.
    pub(crate) fn sent(&mut self, ops: &[Op], error: Option<&anyhow::Error>) {
        let hashes: BTreeSet<String> = ops.iter().map(Op::hash).collect();
        self.state.outbox.retain(|op| !hashes.contains(&op.hash()));
        if let Some(seq) = ops.iter().map(|o| o.seq).max() {
            self.state.acked_seq = self.state.acked_seq.max(seq);
        }
        self.state.last_error = error.map(|err| format!("push: {err:#}"));
        let Some(text) = error.map(|e| format!("{e:#}")) else { return };
        if ["fork", "wrong_seq", "wrong_prev"].iter().any(|code| text.contains(&format!(" {code})"))) {
            // The edge doesn't take this device's chain where it continues:
            // nothing is re-signed below what was written. Check whether the
            // edge was restored, then harar edge sync reset-edge-view.
            self.state.chain_error = Some(format!("the edge refused this device's chain ({text}); if the edge was restored from a backup, run harar edge sync reset-edge-view"));
        } else if text.contains(" clock)") {
            // An op dated ahead of the edge's clock that it never took:
            // dated again, no later than now, and signed again.
            let (acked, now) = (self.state.acked_seq, now_ms());
            self.rewrite_outbox(|op| {
                if op.seq > acked {
                    op.at = op.at.min(now);
                }
            });
        }
    }

    // ------------------------------------------------------------ status

    /// What `harar edge sync status` shows. Paths appear only in conflicts,
    /// which come from the unlocked vault; values never.
    pub(crate) fn status(&mut self, meta: Option<&VaultMeta>) -> Result<Value> {
        let log = if meta.is_some() { self.opened()? } else { self.log() };
        let me = self.edge.device.clone();
        let role = if log.current_authority() == Some(me.as_str()) {
            "authority"
        } else if log.is_active(&me) {
            "member"
        } else if log.members.contains_key(&me) {
            "removed"
        } else if self.state.requested {
            "requested"
        } else {
            "not a member"
        };
        let members: Vec<Value> = log.members.values().map(|m| json!({ "device": m.keys.device, "name": m.keys.name, "added_at": m.added_at, "removed_at": m.removed.as_ref().map(|(n, _, _)| *n) })).collect();
        // A request shows no fingerprint here: the person reads it on the
        // joining device, never copies it from the approver's own screen.
        let requests: Vec<Value> = log.requests.values().map(|r| json!({ "device": r.device, "name": r.name })).collect();
        let others: Vec<Value> = log.other_founders.iter().filter(|(id, _)| !log.members.contains_key(id) && *id != me).map(|(id, ring)| json!({ "device": id, "ring": ring })).collect();
        let behind = self
            .keys
            .as_deref()
            .map(|keys| {
                self.state
                    .pending
                    .iter()
                    .filter(|op| {
                        op.ciphertext().is_some_and(|(s, w)| {
                            keys.iter().any(|k| {
                                super::crypto::open_value(&k.key, &op.key, op.version, s, w).ok().and_then(|p| serde_json::from_slice::<ValueBody>(&p).ok()).is_some_and(|b| !log.heads.contains_key(&b.head))
                            })
                        })
                    })
                    .count()
            })
            .map_or(Value::Null, |n| json!(n));
        let next = match role {
            "requested" if self.state.trusted.is_none() => Some("pin the ring: harar edge sync trust <the ring fingerprint harar edge sync status shows on a member>; then the authority approves this device with the fingerprint shown here"),
            "requested" => Some("waiting for the authority: harar edge sync approve <this device> <this fingerprint>"),
            _ => None,
        };
        let member_or_authority = role == "member" || role == "authority";
        Ok(json!({
            "edge": self.edge.url,
            "device": me,
            "fingerprint": self.fingerprint(),
            "role": role,
            "ring": if member_or_authority { self.state.trusted.clone() } else { None },
            "trusted": self.state.trusted,
            "next": next,
            "founder": log.founder(),
            "authority": log.current_authority(),
            "log": json!({ "length": log.entries.len(), "head": log.head(), "fork_at": log.fork }),
            "epoch": log.epoch().map(|(e, _)| e),
            "members": members,
            "requests": requests,
            "ring_conflicts": json!({
                "ours": self.state.trusted,
                "other_founders": others,
                "gave_up_ours_for": self.state.fell_back,
                "resolve": if others.is_empty() { Value::Null } else { json!("another ring was founded on this edge: keep this one, or give it up for the other with harar edge sync trust <its ring fingerprint> (only while this ring has no other member)") },
            }),
            "queued": self.state.outbox.len(),
            "waiting": self.state.pending.len(),
            "behind": behind,
            "waiting_compacted": self.state.pending.iter().filter(|o| o.compacted).count(),
            "parked": self.state.parked,
            "unheld_authors": self.state.unheld_authors,
            "unopenable": self.state.unopenable,
            "restored": self.state.restored,
            "forged": self.state.forged,
            "ignored": log.ignored,
            "forks": self.state.forks,
            "rejected": self.state.rejected,
            "chain": self.state.chain_error.clone().unwrap_or_else(|| "ok".into()),
            "rebased": self.state.rebased,
            "conflicts": meta.map(|m| json!(m.conflicts)).unwrap_or(json!("unlock the vault to see them")),
            "last_error": self.state.last_error,
        }))
    }
}

type Key = Zeroizing<[u8; 32]>;
