//! The agent's vault as a member of a ring (docs/edge.md §5b): its sync
//! state on disk, how it founds a ring, asks to join one, pins it, approves
//! and removes members, and turns ops into vault changes and back.
//!
//! The state file (`sync/<edge>.json` in the state folder, 0600) holds only
//! what the edge holds too, plus the ring keys wrapped to this member's
//! key-agreement key: ops are ciphertext, and a secret's path or value is
//! never in it. What the vault knows about sync is inside the vault
//! (`apply::VaultMeta`).
//!
//! Ops are written unsigned, under the agent's lock, and signed outside it
//! (an op's hash doesn't cover its signature), so a Secure Enclave signature
//! never holds the vault.

use super::apply::{Change, Conflict, Incoming, Lost, Side, VaultMeta};
use super::crypto::{
    b64, device_fingerprint, gcm_seal, member_mac, name_mac, normal_fingerprint, public_key, random_iv, random_key, ring_fingerprint, seal_value, sha256_hex,
    unb64, unwrapped_ring, wrap_key, wrap_ring,
};
use super::ledger::{self, Author, Fork, Rejected, RingKey, Roster, ring_id};
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
/// One sync pulls at most this many pages; the rest waits for the next.
const PULL_PAGES: usize = 20;
/// Ops kept waiting per author that isn't a member, at most (secret ops, and
/// ring ops); past it, its newest are let go and pulled again later.
const PER_AUTHOR: usize = if cfg!(test) { 20 } else { 2000 };
/// Refusals kept per author.
const REJECTED_PER_AUTHOR: usize = 20;
/// Changes remembered, so one recorded again after a crash isn't a new op.
const OWN_CHANGES: usize = 512;

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
    /// Whether this member founded its ring.
    #[serde(default)]
    pub founded: bool,
    /// The ring this member gave its own up for, when the person pinned it.
    #[serde(default)]
    pub fell_back: Option<String>,
    /// Forks the edge served (two ops at one place in a chain).
    #[serde(default)]
    pub forks: Vec<Fork>,
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
    /// Verified secret ops not applied yet (the vault was locked, their
    /// author isn't known to be a member yet, or one served compacted with
    /// nothing later on its key).
    #[serde(default)]
    pub pending: Vec<Served>,
    /// Ops let go past PER_AUTHOR (to be pulled again).
    #[serde(default)]
    pub dropped: u64,
    /// Each secret key's highest-ranked op held with its ciphertext.
    #[serde(default)]
    pub key_tips: BTreeMap<String, Rank>,
    #[serde(default)]
    pub rejected: Vec<Rejected>,
    /// This member's ops not yet on the edge, in seq order; unsigned until
    /// the sync that sends them.
    #[serde(default)]
    pub outbox: Vec<Op>,
    /// The newest op this member wrote: its seq, hash and time.
    #[serde(default)]
    pub tip: Tip,
    /// Changes already written as ops: (tag, op hash, rank).
    #[serde(default)]
    pub own_changes: Vec<(String, String, Rank)>,
    /// Ops signed again after the chain diverged: old hash to (new hash, new
    /// seq), until the vault's record of them is updated.
    #[serde(default)]
    pub renamed: BTreeMap<String, (String, u64)>,
    /// The edge refused a push for this member's chain (fork, wrong seq or
    /// prev): the queued ops are signed again after the next full pull.
    #[serde(default)]
    pub diverged: bool,
    /// How many queued ops were signed again so far.
    #[serde(default)]
    pub rebased: u64,
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
    /// for one.
    pub pull_complete: bool,
}

/// What one step did to the vault.
#[derive(Debug, Default)]
pub(crate) struct Stepped {
    /// Paths whose value another member's op changed.
    pub changed: BTreeSet<String>,
}

/// A pull: the ops, and whether it reached the end.
pub(crate) struct Pulled {
    pub ops: Vec<Served>,
    pub complete: bool,
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
        Ok(Member { edge, state, path, agree_pub, sign_pub, keys: None, pull_complete: false })
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

    /// This device's fingerprint: what a member checks before approving it.
    pub(crate) fn fingerprint(&self) -> String {
        device_fingerprint(&self.sign_pub, &self.agree_pub)
    }

    // ------------------------------------------------------------ ingest

    /// Takes pulled ops: each author's chain and signatures are verified, the
    /// ring's ops kept, and secret ops queued until they can be applied.
    pub(crate) fn ingest(&mut self, ops: Vec<Served>) {
        let me = self.edge.device.clone();
        let verified = ledger::verify_chains(&mut self.state.authors, &me, ops);
        for r in verified.rejected {
            if !self.state.rejected.iter().any(|x| x.author == r.author && x.seq == r.seq) {
                self.state.rejected.push(r);
            }
        }
        for fork in verified.forks {
            if !self.state.forks.iter().any(|f| f.author == fork.author && f.seq == fork.seq) {
                self.state.forks.push(fork);
            }
        }
        for op in verified.good {
            let at = self.state.next.entry(op.author.clone()).or_insert(0);
            *at = (*at).max(op.seq);
            if op.author == me {
                // Already on the edge: never send it again. And our chain
                // continues from the newest of ours the edge has.
                self.state.outbox.retain(|o| o.hash() != op.hash);
                if op.seq > self.state.tip.seq {
                    self.state.tip = Tip { seq: op.seq, hash: op.hash.clone(), at: op.at };
                }
            }
            if op.kind.is_value() && op.ciphertext().is_some() {
                let tip = self.state.key_tips.entry(op.key.clone()).or_insert_with(|| op.rank());
                if op.rank() > *tip {
                    *tip = op.rank();
                }
            }
            if !op.kind.is_value() {
                if !self.state.member_ops.iter().any(|o| o.hash == op.hash) {
                    self.state.member_ops.push(op);
                }
            } else if op.author != me {
                self.state.pending.push(op);
            }
        }
        self.bound();
    }

    /// Keeps what an author that isn't a member can make this member hold
    /// under PER_AUTHOR ops (secret ops and ring ops each), and its refusals
    /// under REJECTED_PER_AUTHOR. Past the cap its newest ops are let go and
    /// its chain and cursor go back to before them, so they are pulled again,
    /// never lost. Nothing is let go while no ring key is open: without one,
    /// nobody can be told from a member.
    fn bound(&mut self) {
        let mut by_author: BTreeMap<String, usize> = BTreeMap::new();
        for r in self.state.rejected.iter().rev() {
            *by_author.entry(r.author.clone()).or_default() += 1;
        }
        if by_author.values().any(|n| *n > REJECTED_PER_AUTHOR) {
            let mut seen: BTreeMap<String, usize> = BTreeMap::new();
            let mut keep = Vec::new();
            for r in self.state.rejected.drain(..).rev() {
                let n = seen.entry(r.author.clone()).or_default();
                *n += 1;
                if *n <= REJECTED_PER_AUTHOR {
                    keep.push(r);
                }
            }
            keep.reverse();
            self.state.rejected = keep;
        }
        if self.keys.as_ref().is_none_or(Vec::is_empty) {
            return;
        }
        let Ok(roster) = self.roster_now() else { return };
        let mut counts: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        for op in &self.state.pending {
            counts.entry(op.author.clone()).or_default().0 += 1;
        }
        for op in &self.state.member_ops {
            counts.entry(op.author.clone()).or_default().1 += 1;
        }
        let over: Vec<String> = counts.into_iter().filter(|(a, (p, m))| !roster.members.contains_key(a) && *a != self.edge.device && (*p > PER_AUTHOR || *m > PER_AUTHOR)).map(|(a, _)| a).collect();
        for author in over {
            let mut theirs: Vec<&Served> = self.state.pending.iter().chain(self.state.member_ops.iter()).filter(|o| o.author == author).collect();
            theirs.sort_by_key(|o| o.seq);
            let pending_seqs: Vec<u64> = self.state.pending.iter().filter(|o| o.author == author).map(|o| o.seq).collect();
            let member_seqs: Vec<u64> = self.state.member_ops.iter().filter(|o| o.author == author).map(|o| o.seq).collect();
            // The first seq past which either kind is over its cap.
            let cut = [pending_seqs, member_seqs]
                .into_iter()
                .filter_map(|mut seqs| {
                    seqs.sort_unstable();
                    seqs.get(PER_AUTHOR).copied()
                })
                .min()
                .expect("over a cap");
            let Some(first) = theirs.iter().find(|o| o.seq == cut).map(|o| (*o).clone()) else { continue };
            let before = self.state.pending.len() + self.state.member_ops.len();
            self.state.pending.retain(|o| o.author != author || o.seq < cut);
            self.state.member_ops.retain(|o| o.author != author || o.seq < cut);
            self.state.dropped += (before - self.state.pending.len() - self.state.member_ops.len()) as u64;
            if let Some(a) = self.state.authors.get_mut(&author) {
                a.seq = cut - 1;
                a.hash = first.prev.clone();
                a.recent.retain(|seq, _| *seq < cut);
            }
            self.state.next.insert(author, cut - 1);
        }
    }

    /// After a full pull: when the edge has ops of ours that the queued ones
    /// don't follow (this state file was restored from an older copy, or a
    /// push was refused as a fork), they are written again after the edge's
    /// newest, to be signed and sent; the vault learns their new hashes.
    pub(crate) fn rebase(&mut self) {
        let (seq, hash) = self.state.authors.get(self.me()).map(|a| (a.seq, a.hash.clone())).unwrap_or((0, String::new()));
        let Some(first) = self.state.outbox.first() else {
            self.state.diverged = false;
            return;
        };
        if first.seq == seq + 1 && first.prev == hash {
            self.state.diverged = false;
            return;
        }
        let mut prev = (seq, hash);
        let mut moved = Vec::new();
        for op in &mut self.state.outbox {
            let old = op.hash();
            op.seq = prev.0 + 1;
            op.prev = prev.1.clone();
            op.sig = String::new();
            let new = op.hash();
            prev = (op.seq, new.clone());
            moved.push((old, new, op.clone()));
        }
        for (old, new, op) in moved {
            if let Some(m) = self.state.member_ops.iter_mut().find(|o| o.hash == old) {
                *m = Served::from(&op);
            }
            for (_, h, r) in &mut self.state.own_changes {
                if *h == old {
                    *h = new.clone();
                    r.seq = op.seq;
                }
            }
            self.state.renamed.insert(old, (new, op.seq));
            self.state.rebased += 1;
        }
        let last = self.state.outbox.last().expect("not empty");
        self.state.tip = Tip { seq: last.seq, hash: last.hash(), at: self.state.tip.at.max(last.at) };
        self.state.diverged = false;
    }

    // ------------------------------------------------------------ keys

    /// Opens the ring keys this member holds (asking the enclave once while
    /// the vault stays unlocked), plus any that a grant to it from the ring it
    /// pinned, or a rekey by a member, gives.
    fn open_keys(&mut self) -> Result<()> {
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
        let mut changed = false;
        // A joiner takes a grant only once it has pinned the ring, and only
        // one that chains to the founder it pinned.
        if keys.is_empty()
            && let Some(trusted) = self.state.trusted.clone()
        {
            for (epoch, wrapped, grant) in ledger::grants_to(&me, &self.state.member_ops) {
                let Some(key) = unb64(&wrapped).ok().and_then(|w| unwrap(&w).ok()).and_then(|plain| unwrapped_ring(&plain, epoch, &me)) else { continue };
                let mut candidate = vec![RingKey { epoch, key }];
                ledger::reach_back(&self.state.member_ops, &mut candidate);
                let roster = ledger::roster(&self.state.member_ops, &candidate, &self.state.authors, Some(&trusted));
                if roster.founder.is_some() && roster.counts(&grant.author, grant.seq) && roster.members.contains_key(&me) {
                    keys = candidate;
                    changed = true;
                    break;
                }
            }
        }
        // A member takes a grant of an epoch it doesn't hold (a re-grant after
        // a rekey crossed its approval) when a counting member made that key.
        if !keys.is_empty() {
            let roster = ledger::roster(&self.state.member_ops, &keys, &self.state.authors, self.state.trusted.as_deref());
            for (epoch, wrapped, grant) in ledger::grants_to(&me, &self.state.member_ops) {
                if keys.iter().any(|k| k.epoch == epoch) || !roster.counts(&grant.author, grant.seq) {
                    continue;
                }
                let Some(key) = unb64(&wrapped).ok().and_then(|w| unwrap(&w).ok()).and_then(|plain| unwrapped_ring(&plain, epoch, &me)) else { continue };
                let candidate = RingKey { epoch, key };
                if ledger::given_to(&candidate, &self.state.member_ops, &roster).is_some() {
                    keys.push(candidate);
                    changed = true;
                }
            }
        }
        loop {
            let back = ledger::reach_back(&self.state.member_ops, &mut keys);
            let roster = ledger::roster(&self.state.member_ops, &keys, &self.state.authors, self.state.trusted.as_deref());
            let forward = ledger::reach_forward(&me, &self.state.member_ops, &mut keys, &roster, &unwrap);
            if !(back || forward) {
                break;
            }
            changed = true;
        }
        if changed {
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

    fn roster_now(&self) -> Result<Roster> {
        Ok(ledger::roster(&self.state.member_ops, self.keys.as_deref().unwrap_or_default(), &self.state.authors, self.state.trusted.as_deref()))
    }

    pub(crate) fn roster(&mut self) -> Result<Roster> {
        self.open_keys()?;
        self.roster_now()
    }

    fn current(&self, roster: &Roster) -> Option<&RingKey> {
        ledger::current(self.keys.as_deref().unwrap_or_default(), &self.state.member_ops, roster)
    }

    /// The ring key new writes use, for tests that play a member gone bad.
    #[cfg(test)]
    pub(crate) fn current_key_for_test(&mut self) -> (u32, [u8; 32]) {
        let roster = self.roster().unwrap();
        let k = self.current(&roster).expect("a member");
        (k.epoch, *k.key)
    }

    /// The ring's fingerprint, when this member founded or pinned one.
    #[cfg(test)]
    pub(crate) fn ring_fingerprint(&self) -> Option<String> {
        self.state.trusted.clone()
    }

    // ------------------------------------------------------------ writing ops

    /// This member's next op, unsigned, queued. `at` is never before
    /// `min_at` nor this member's last op.
    pub(crate) fn write(&mut self, kind: Kind, key: String, version: u64, sealed: String, wrapped_key: String, min_at: u64) -> Op {
        let at = now_ms().max(self.state.tip.at).max(min_at);
        self.write_at(kind, key, version, sealed, wrapped_key, at)
    }

    /// The same, at exactly `at` (a joiner's own older values: 0, the lowest).
    fn write_at(&mut self, kind: Kind, key: String, version: u64, sealed: String, wrapped_key: String, at: u64) -> Op {
        let me = self.edge.device.clone();
        let op = Op { author: me.clone(), seq: self.state.tip.seq + 1, prev: self.state.tip.hash.clone(), kind, key, version, sealed, wrapped_key, at, sig: String::new() };
        let hash = op.hash();
        self.state.tip = Tip { seq: op.seq, hash, at: self.state.tip.at.max(at) };
        let (sign_pub, agree_pub) = (b64(&self.sign_pub), b64(&self.agree_pub));
        self.state.authors.entry(me).or_insert_with(|| Author { sign_pub, agree_pub, seq: 0, hash: String::new(), recent: BTreeMap::new(), fork_at: None });
        if !kind.is_value() {
            self.state.member_ops.push(Served::from(&op));
        }
        self.state.outbox.push(op.clone());
        op
    }

    /// The queued ops not signed yet.
    pub(crate) fn unsigned(&self) -> Vec<Op> {
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
    }

    /// The queued ops ready to send: signed, from the first on.
    pub(crate) fn ready(&self) -> Vec<Op> {
        self.state.outbox.iter().take_while(|o| !o.sig.is_empty()).cloned().collect()
    }

    /// Signs every queued op, in one go: for tests, which hold no lock.
    #[cfg(test)]
    pub(crate) fn sign_all(&mut self) -> Result<()> {
        let signed = Self::sign(&self.edge.key()?, self.unsigned())?;
        self.signed(signed);
        Ok(())
    }

    pub(crate) fn own_body(&self, epoch: u32) -> MemberBody {
        MemberBody { device: self.edge.device.clone(), name: self.edge.name.clone(), sign_pub: b64(&self.sign_pub), agree_pub: b64(&self.agree_pub), epoch, removal: String::new() }
    }

    /// Founds the ring when the edge has no ops yet, or asks to join the one
    /// it has. Never gives a ring up by itself (only `trust` does), and
    /// opens no ring key, so the worker can run it with the vault locked.
    pub(crate) fn found_or_request(&mut self) -> Result<Option<&'static str>> {
        if !self.state.ring.is_empty() {
            return Ok(None);
        }
        let others = self.state.authors.keys().any(|a| *a != self.edge.device) || !self.state.rejected.is_empty();
        if !others && self.state.member_ops.is_empty() && !self.state.founded && self.state.fell_back.is_none() {
            let ring = random_key();
            let mine = public_key(&self.agree_pub)?;
            let body = self.own_body(0);
            let key = member_mac(&ring, &op::add_mac_text(self.me(), &body));
            let wrap = b64(wrap_ring(&mine, 0, self.me(), &ring));
            self.write(Kind::MemberAdd, key, 0, op::plain_body(&body), wrap, 0);
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
        let body = self.own_body(0);
        self.write(Kind::MemberAdd, op::request_key(self.me()), 0, op::plain_body(&body), String::new(), 0);
        self.state.requested = true;
        Ok(Some("requested"))
    }

    /// Pins the ring to join by its fingerprint (from `harar edge sync
    /// status` on any member). Until then, no grant is taken. A founder whose
    /// ring has no other member yet gives its own up for the one pinned (two
    /// rings founded at once): only the person decides that, never the code.
    pub(crate) fn trust(&mut self, fingerprint: &str) -> Result<Value> {
        let fp = normal_fingerprint(fingerprint).ok_or_else(|| anyhow!("{fingerprint:?} is not a ring fingerprint: 32 hex, in groups of four"))?;
        if !self.state.ring.is_empty() && self.state.trusted.as_deref() != Some(fp.as_str()) {
            let roster = self.roster()?;
            if !self.state.founded || roster.members.keys().any(|id| *id != self.edge.device) {
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

    /// Adds `device`, which asked to join and whose fingerprint the person
    /// read on it: the ring key, wrapped to the key-agreement key in its
    /// request, in a member.add.
    pub(crate) fn approve(&mut self, device: &str, fingerprint: &str) -> Result<Value> {
        let roster = self.roster()?;
        if roster.members.contains_key(device) {
            bail!("{device} is already a member");
        }
        let Some(request) = roster.requests.get(device).cloned() else {
            bail!("{device} hasn't asked to join; run harar edge sync on there first (then harar edge sync now here)");
        };
        let own = self.state.authors.get(device).ok_or_else(|| anyhow!("no ops from {device}"))?;
        if own.sign_pub != request.sign_pub || own.agree_pub != request.agree_pub {
            bail!("{device}'s request names keys that aren't its own");
        }
        let theirs = device_fingerprint(&unb64(&request.sign_pub)?, &unb64(&request.agree_pub)?);
        let Some(typed) = normal_fingerprint(fingerprint) else { bail!("{fingerprint:?} is not a device fingerprint: 32 hex, in groups of four") };
        if typed != theirs {
            bail!("{device}'s fingerprint is {theirs}, not {typed}: don't approve it unless it is the device in front of you");
        }
        let current = self.current(&roster).ok_or_else(|| anyhow!("this machine isn't a member of the ring, so it can't add one"))?;
        let (epoch, ring) = (current.epoch, current.key.clone());
        let removal = ledger::latest_removal(&self.state.member_ops, self.keys.as_deref().unwrap_or_default(), &roster);
        let body = MemberBody { epoch, removal, ..request.clone() };
        self.grant(&body, &ring)?;
        Ok(json!({ "approved": device, "name": request.name, "fingerprint": theirs }))
    }

    /// A member.add of `body.device`, wrapping `ring` (of `body.epoch`) to it.
    fn grant(&mut self, body: &MemberBody, ring: &[u8; 32]) -> Result<()> {
        let recipient = public_key(&unb64(&body.agree_pub)?)?;
        let key = member_mac(ring, &op::add_mac_text(self.me(), body));
        let wrap = b64(wrap_ring(&recipient, body.epoch, &body.device, ring));
        self.write(Kind::MemberAdd, key, u64::from(body.epoch), op::plain_body(body), wrap, 0);
        Ok(())
    }

    /// Removes `device` from the ring, then rekeys: a new ring key, wrapped
    /// to every member that remains, used for every write from now on.
    /// Returns None when `device` isn't a member; fails when this machine
    /// isn't one (so `unpair` never thinks a rekey was done).
    pub(crate) fn remove(&mut self, device: &str) -> Result<Option<Value>> {
        let roster = self.roster()?;
        let Some(current) = self.current(&roster).filter(|_| roster.counts(self.me(), self.state.tip.seq + 1)) else {
            bail!("this machine isn't a member of the ring, so it can't remove a device from it");
        };
        let (epoch, old) = (current.epoch, current.key.clone());
        if device == self.me() || !roster.active().any(|(id, _)| id == device) {
            return Ok(None);
        }
        let after = self.state.authors.get(device).map_or(0, |a| a.seq);
        let removed = RemoveBody { device: device.to_owned(), after };
        let me = self.edge.device.clone();
        self.write(Kind::MemberRemove, member_mac(&old, &op::remove_mac_text(&me, device, after)), u64::from(epoch), op::plain_body(&removed), String::new(), 0);
        let remaining: Vec<(String, String)> = roster.active().filter(|(id, _)| *id != device).map(|(id, m)| (id.clone(), m.agree_pub.clone())).collect();
        let next = self.rekey(epoch, &old, &remaining)?;
        Ok(Some(json!({ "removed": device, "after": after, "epoch": next })))
    }

    /// A new ring key for the epoch after `epoch`, wrapped to `to` (device,
    /// agreement key), backing onto `old`.
    fn rekey(&mut self, epoch: u32, old: &[u8; 32], to: &[(String, String)]) -> Result<u32> {
        let next = next_epoch(epoch)?;
        let new = random_key();
        let mut wraps = BTreeMap::new();
        for (id, agree) in to {
            wraps.insert(id.clone(), b64(wrap_ring(&public_key(&unb64(agree)?)?, next, id, &new)));
        }
        let id = ring_id(&new, next);
        let body = RekeyBody { epoch: next, id: id.clone(), wraps };
        let back = b64(gcm_seal(&wrap_key(&new), old, op::rekey_ad(next).as_bytes(), random_iv()));
        let me = self.edge.device.clone();
        self.write(Kind::Rekey, member_mac(old, &op::rekey_mac_text(&me, next, &id)), u64::from(next), op::plain_body(&body), back, 0);
        let mut keys = self.keys.take().unwrap_or_default();
        keys.push(RingKey { epoch: next, key: new });
        self.keep_keys(&keys)?;
        self.keys = Some(keys);
        Ok(next)
    }

    /// Keeps the ring's write key one that only active members hold: when
    /// the newest key was given to a device since removed (two removals at
    /// once each wrap their rekey to the other's removed device), it rekeys
    /// to the next epoch, wrapped only to active members; and an active
    /// member that never got the write key (approved across a rekey) is
    /// granted it again.
    fn maintain(&mut self, roster: &Roster) -> Result<()> {
        let keys = self.keys.as_deref().unwrap_or_default();
        let Some(newest) = ledger::newest(keys, &self.state.member_ops, roster) else { return Ok(()) };
        let current = ledger::current(keys, &self.state.member_ops, roster).map(|k| (k.epoch, k.key.clone()));
        let active: Vec<(String, String)> = roster.active().map(|(id, m)| (id.clone(), m.agree_pub.clone())).collect();
        match current {
            Some((epoch, _)) if epoch >= newest => {}
            _ => {
                // Back onto a key of the newest epoch, which every member that
                // holds any of them can follow.
                let back = keys
                    .iter()
                    .filter(|k| k.epoch == newest && ledger::given_to(k, &self.state.member_ops, roster).is_some())
                    .max_by_key(|k| ring_id(&k.key, k.epoch))
                    .map(|k| k.key.clone());
                if let Some(back) = back {
                    self.rekey(newest, &back, &active)?;
                }
                return Ok(());
            }
        }
        let (epoch, ring) = current.expect("checked above");
        let held = RingKey { epoch, key: ring.clone() };
        let given = ledger::given_to(&held, &self.state.member_ops, roster).unwrap_or_default();
        let removal = ledger::latest_removal(&self.state.member_ops, keys, roster);
        let lacking: Vec<MemberBody> = roster
            .active()
            .filter(|(id, _)| !given.contains(*id))
            .map(|(id, m)| MemberBody { device: id.clone(), name: m.name.clone(), sign_pub: m.sign_pub.clone(), agree_pub: m.agree_pub.clone(), epoch, removal: removal.clone() })
            .collect();
        for body in lacking {
            self.grant(&body, &ring)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------ the vault

    /// With the vault open: applies what other members wrote (last write
    /// wins), then turns what changed here into ops. `keys` is the vault.
    /// Nothing from the vault is sealed until this member holds a ring key
    /// it founded or pinned, and counts as a member.
    pub(crate) fn step(&mut self, keys: &mut HashMap<String, String>) -> Result<Stepped> {
        let roster = self.roster()?;
        if self.keys.as_ref().is_none_or(Vec::is_empty) || !roster.counts(self.me(), self.state.tip.seq + 1) {
            return Ok(Stepped::default());
        }
        self.maintain(&roster)?;
        let roster = self.roster()?;
        let mut meta = VaultMeta::read(keys);
        if !self.state.renamed.is_empty() {
            meta.rename(&self.state.renamed);
            self.state.renamed.clear();
        }
        let first = meta.ring != roster.founder;
        let incoming = self.open_pending(&roster);
        // A joiner's first step waits for a pull that reached the end, with
        // nothing from a member left waiting, so it sees the ring whole.
        let waiting = self.state.pending.iter().any(|op| roster.counts(&op.author, op.seq) && !incoming.iter().any(|i| i.hash == op.hash));
        if first && !self.state.founded && (!self.pull_complete || waiting) {
            return Ok(Stepped::default());
        }
        let applied: BTreeSet<String> = incoming.iter().map(|i| i.hash.clone()).collect();
        let changed = if first {
            // Joining (or founding): the ring's current value wins. What the
            // vault held that differs goes to history, flagged; what the
            // ring lacks becomes this member's write, at the lowest rank, so
            // it loses to any ring op on its path that shows up later.
            meta.paths.clear();
            meta.ring = roster.founder.clone();
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
                self.record_changes_at(&mut meta, keys, &roster, Some(0))?;
            }
            changed
        } else {
            // Changes here that no op records yet (sync was off) are
            // concurrent with what arrived: recorded first, so last write wins.
            self.record_changes(&mut meta, keys, &roster)?;
            meta.apply(keys, incoming)
        };
        self.state.pending.retain(|op| !applied.contains(&op.hash));
        self.record_changes(&mut meta, keys, &roster)?;
        meta.write(keys);
        Ok(Stepped { changed })
    }

    /// A change's tag: the same change gets the same tag, so after a crash
    /// between saving the ops and saving the vault it isn't written twice.
    fn change_tag(ring: &[u8; 32], epoch: u32, change: &Change) -> String {
        let value = change.value.as_deref().map(sha256_hex).unwrap_or_default();
        member_mac(ring, &format!("harar:change|{epoch}|{}|{}|{}|{value}", change.path, change.version, change.base))
    }

    fn record_changes(&mut self, meta: &mut VaultMeta, keys: &HashMap<String, String>, roster: &Roster) -> Result<()> {
        self.record_changes_at(meta, keys, roster, None)
    }

    /// Records the vault's changes as ops; with `at`, at exactly that time.
    fn record_changes_at(&mut self, meta: &mut VaultMeta, keys: &HashMap<String, String>, roster: &Roster, at: Option<u64>) -> Result<()> {
        let changes = meta.changes(keys);
        if changes.is_empty() {
            return Ok(());
        }
        let current = self.current(roster).ok_or_else(|| anyhow!("no ring key to write with"))?;
        let (epoch, ring) = (current.epoch, current.key.clone());
        for change in changes {
            let tag = Self::change_tag(&ring, epoch, &change);
            if let Some((_, hash, rank)) = self.state.own_changes.iter().find(|(t, _, _)| *t == tag) {
                meta.record_own(&change, hash, rank.clone());
                continue;
            }
            let key = name_mac(&ring, &change.path);
            let body = ValueBody { path: change.path.clone(), value: change.value.clone(), base: change.base.clone() };
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
                Some(at) => self.write_at(change.kind, key, change.version, sealed, wrapped, at),
                None => self.write(change.kind, key, change.version, sealed, wrapped, min_at),
            };
            let rank = Served::from(&op).rank();
            meta.record_own(&change, &op.hash(), rank.clone());
            self.state.own_changes.push((tag, op.hash(), rank));
            if self.state.own_changes.len() > OWN_CHANGES {
                self.state.own_changes.remove(0);
            }
        }
        Ok(())
    }

    /// The pending secret ops that can be applied now, opened. An op whose
    /// author is no longer a member at its seq is rejected; one whose author
    /// isn't known to be a member yet waits. One served compacted counts
    /// only when a later op on its key is held; otherwise it waits.
    fn open_pending(&mut self, roster: &Roster) -> Vec<Incoming> {
        let keys = self.keys.as_deref().unwrap_or_default();
        let mut out = Vec::new();
        let mut drop = Vec::new();
        for op in &self.state.pending {
            if !roster.counts(&op.author, op.seq) {
                if roster.members.contains_key(&op.author) || roster.mismatched.contains(&op.author) {
                    drop.push((op.hash.clone(), Some(Rejected { author: op.author.clone(), seq: op.seq, reason: "its author was removed before it, or isn't the device its grant named".into() })));
                }
                continue;
            }
            let Some((sealed, wrapped)) = op.ciphertext() else {
                if self.state.key_tips.get(&op.key).is_some_and(|tip| *tip > op.rank()) {
                    drop.push((op.hash.clone(), None));
                }
                continue;
            };
            let opened = keys.iter().rev().find_map(|k| {
                let plain = super::crypto::open_value(&k.key, &op.key, op.version, sealed, wrapped).ok()?;
                let body: ValueBody = serde_json::from_slice(&plain).ok()?;
                (name_mac(&k.key, &body.path) == op.key).then_some(body)
            });
            match opened {
                Some(body) if (op.kind == Kind::Delete) == body.value.is_none() && !body.path.starts_with("harar:") && !body.path.is_empty() => {
                    out.push(Incoming { hash: op.hash.clone(), base: body.base, rank: op.rank(), version: op.version, path: body.path, value: body.value });
                }
                Some(_) => drop.push((op.hash.clone(), Some(Rejected { author: op.author.clone(), seq: op.seq, reason: "what it holds doesn't match its kind".into() }))),
                None => {}
            }
        }
        for (hash, rejected) in drop {
            self.state.pending.retain(|op| op.hash != hash);
            if let Some(rejected) = rejected {
                self.state.rejected.push(rejected);
            }
        }
        out
    }

    // ------------------------------------------------------------ the edge

    /// The ops after the cursor, up to PULL_PAGES pages. Each page's `next`
    /// must move the cursor on, or the edge is refused.
    pub(crate) fn pull(edge: &Paired, device: &DeviceKey, since: &BTreeMap<String, u64>) -> Result<Pulled> {
        let mut since = since.clone();
        let mut ops = Vec::new();
        for _ in 0..PULL_PAGES {
            let page = edge.call_with(device, "POST", "/v1/sync", Some(&json!({ "since": since })))?;
            let got: Vec<Served> = serde_json::from_value(page["ops"].clone()).context("the edge's ops")?;
            let next: BTreeMap<String, u64> = serde_json::from_value(page["next"].clone()).context("the edge's next")?;
            let more = page["more"] == Value::Bool(true);
            let moved = next.iter().any(|(a, s)| since.get(a).is_none_or(|old| s > old)) && next.iter().all(|(a, s)| since.get(a).is_none_or(|old| s >= old));
            if more && (got.is_empty() || !moved) {
                bail!("{} says there is more to pull but doesn't move the cursor on", edge.url);
            }
            ops.extend(got);
            since = next;
            if !more {
                return Ok(Pulled { ops, complete: true });
            }
        }
        Ok(Pulled { ops, complete: false })
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

    /// Takes the ops a push sent out of the outbox; a refusal of this
    /// member's chain marks it diverged.
    pub(crate) fn sent(&mut self, ops: &[Op], error: Option<&anyhow::Error>) {
        let hashes: BTreeSet<String> = ops.iter().map(Op::hash).collect();
        self.state.outbox.retain(|op| !hashes.contains(&op.hash()));
        self.state.last_error = error.map(|err| format!("push: {err:#}"));
        if let Some(err) = error {
            let text = format!("{err:#}");
            if ["fork", "wrong_seq", "wrong_prev"].iter().any(|code| text.contains(&format!(" {code})"))) {
                self.state.diverged = true;
            }
        }
    }

    // ------------------------------------------------------------ status

    /// What `harar edge sync status` shows. Paths appear only in conflicts,
    /// which come from the unlocked vault; values never.
    pub(crate) fn status(&mut self, meta: Option<&VaultMeta>) -> Result<Value> {
        let roster = self.roster()?;
        let member = roster.counts(self.me(), self.state.tip.seq + 1) && self.keys.as_ref().is_some_and(|k| !k.is_empty());
        let role = if member {
            "member"
        } else if roster.members.contains_key(self.me()) {
            "removed"
        } else if self.state.requested {
            "requested"
        } else {
            "not a member"
        };
        let fp = |sign: &str, agree: &str| device_fingerprint(&unb64(sign).unwrap_or_default(), &unb64(agree).unwrap_or_default());
        let members: Vec<Value> = roster.members.iter().map(|(id, m)| json!({ "device": id, "name": m.name, "fingerprint": fp(&m.sign_pub, &m.agree_pub), "removed_after": m.after })).collect();
        // A request shows no fingerprint here: the person reads it on the
        // joining device, never copies it from the approver's own screen.
        let requests: Vec<Value> = roster.requests.iter().map(|(id, r)| json!({ "device": id, "name": r.name })).collect();
        let others: Vec<Value> = roster
            .other_founders
            .iter()
            .filter(|(id, _, _)| !roster.members.contains_key(id) && *id != self.edge.device)
            .map(|(id, rank, ring)| json!({ "device": id, "at": rank.at, "ring": ring }))
            .collect();
        let grant_view = ledger::my_grant_view(self.me(), &self.state.member_ops, &roster).map(|(epoch, removal)| {
            let known = ledger::latest_removal(&self.state.member_ops, self.keys.as_deref().unwrap_or_default(), &roster);
            json!({ "epoch": epoch, "removal": removal, "stale": removal != known })
        });
        let waiting_compacted = self.state.pending.iter().filter(|o| o.compacted).count();
        let next = match role {
            "requested" if self.state.trusted.is_none() => Some("pin the ring: harar edge sync trust <the ring fingerprint harar edge sync status shows on a member>; then a member approves this device with its fingerprint"),
            "requested" => Some("waiting for a member: harar edge sync approve <this device> <this fingerprint>"),
            _ => None,
        };
        let epoch = self.current(&roster).map(|k| k.epoch);
        Ok(json!({
            "edge": self.edge.url,
            "device": self.edge.device,
            "fingerprint": self.fingerprint(),
            "role": role,
            "ring": if member { self.state.trusted.clone() } else { None },
            "trusted": self.state.trusted,
            "next": next,
            "founder": roster.founder,
            "epoch": epoch,
            "members": members,
            "requests": requests,
            "ring_conflicts": json!({
                "unresolved": roster.conflict,
                "ours": self.state.trusted,
                "other_founders": others,
                "gave_up_ours_for": self.state.fell_back,
                "resolve": if others.is_empty() { Value::Null } else { json!("another ring was founded on this edge: keep this one, or give it up for the other with harar edge sync trust <its ring fingerprint> (only while this ring has no other member)") },
            }),
            "forks": self.state.forks,
            "grant_view": grant_view,
            "queued": self.state.outbox.len(),
            "waiting": self.state.pending.len(),
            "waiting_compacted": if waiting_compacted > 0 { json!(waiting_compacted) } else { Value::Null },
            "dropped": self.state.dropped,
            "rejected": self.state.rejected,
            "chain": if self.state.diverged { "diverged: the queued ops are signed again after the next full pull" } else { "ok" },
            "rebased": self.state.rebased,
            "conflicts": meta.map(|m| json!(m.conflicts)).unwrap_or(json!("unlock the vault to see them")),
            "last_error": self.state.last_error,
        }))
    }
}
