//! What a member keeps of the ring's ops, and what it works out from them
//! (docs/edge.md §5b): each author's chain, the membership log, and the
//! ring keys. Nothing here is trusted to the edge.
//!
//! - Every author's chain links from its first op: seq counts up by one,
//!   prev is the hash before. A second, different op at a seq already held
//!   is a fork. Signatures aren't checked here: a device's keys come only
//!   from the membership log.
//! - The log starts at the `found` entry of the ring the member pinned,
//!   signed by that founder's own key; every later entry is signed by the
//!   authority of the entry before, with the next `n` and the right `prev`.
//!   Only the authority's entries count, so there is nothing to reconcile.
//! - An entry that claims a place on the log but isn't the authority's is
//!   forged: refused, and its author's chain is pulled again.

use super::crypto::{Key32, gcm_open, member_mac, ring_fingerprint, unb64, unwrapped_ring, wrap_key};
use super::op::{Entry, EntryType, Kind, MemberKeys, Request, Served, head_of, read_plain_body, rekey_ad, ring_id_text};
use anyhow::Result;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Hashes kept per author for telling a fork from a repeat.
const RECENT: usize = 64;

/// The tip of an author's chain as linked so far.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Author {
    pub seq: u64,
    pub hash: String,
    /// The last few ops' hashes, by seq.
    #[serde(default)]
    pub recent: BTreeMap<u64, String>,
    /// The first seq at which the edge served this author two different ops.
    #[serde(default)]
    pub fork_at: Option<u64>,
}

impl Author {
    fn advance(&mut self, seq: u64, hash: &str) {
        self.seq = seq;
        self.hash = hash.to_owned();
        self.recent.insert(seq, hash.to_owned());
        while self.recent.len() > RECENT {
            let first = *self.recent.keys().next().expect("not empty");
            self.recent.remove(&first);
        }
    }

    /// Back to just before `seq`, whose prev was `prev`.
    pub(crate) fn back_to(&mut self, seq: u64, prev: &str) {
        self.seq = seq.saturating_sub(1);
        self.hash = prev.to_owned();
        self.recent.retain(|s, _| *s < seq);
    }
}

/// An op refused, and why. Never its contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rejected {
    pub author: String,
    pub seq: u64,
    pub reason: String,
}

/// Two different ops the edge served at one place in an author's chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Fork {
    pub author: String,
    pub seq: u64,
    pub hashes: [String; 2],
}

/// One ring key, in memory only while the vault is unlocked.
pub(crate) struct RingKey {
    pub epoch: u32,
    pub key: Key32,
}

impl std::fmt::Debug for RingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingKey").field("epoch", &self.epoch).finish_non_exhaustive()
    }
}

/// A ring key's id: a MAC under it of its epoch.
pub(crate) fn ring_id(key: &[u8; 32], epoch: u32) -> String {
    member_mac(key, &ring_id_text(epoch))
}

/// What linking a pull found.
#[derive(Default)]
pub(crate) struct Linked {
    pub good: Vec<Served>,
    pub rejected: Vec<Rejected>,
    pub forks: Vec<Fork>,
}

/// Links `ops` (one pull, in each author's seq order) onto the chains in
/// `authors`. An author whose chain breaks has nothing after the break taken.
pub(crate) fn link_chains(authors: &mut BTreeMap<String, Author>, me: &str, ops: Vec<Served>) -> Linked {
    let mut out = Linked::default();
    let mut broken: Vec<String> = Vec::new();
    for op in ops {
        if broken.contains(&op.author) {
            continue;
        }
        let a = authors.entry(op.author.clone()).or_default();
        if a.fork_at.is_some() {
            continue;
        }
        let refuse = |reason: &str| Rejected { author: op.author.clone(), seq: op.seq, reason: reason.to_owned() };
        if op.seq <= a.seq && op.author != me {
            if let Some(known) = a.recent.get(&op.seq).filter(|h| **h != op.hash) {
                out.forks.push(Fork { author: op.author.clone(), seq: op.seq, hashes: [known.clone(), op.hash.clone()] });
                a.fork_at = Some(op.seq);
                broken.push(op.author.clone());
            }
            continue;
        }
        let canonical = match op.canonical() {
            Ok(text) => text,
            Err(err) => {
                out.rejected.push(refuse(&format!("{err:#}")));
                broken.push(op.author.clone());
                continue;
            }
        };
        if super::crypto::sha256_hex(&canonical) != op.hash {
            out.rejected.push(refuse("its hash is not the hash of the op"));
            broken.push(op.author.clone());
            continue;
        }
        if op.compacted && !op.kind.is_value() {
            out.rejected.push(refuse("a ring op served compacted: the edge never compacts one"));
            broken.push(op.author.clone());
            continue;
        }
        if op.author == me {
            // Our own op back from the edge; our chain is built here.
            if op.seq > a.seq {
                a.advance(op.seq, &op.hash);
            }
            out.good.push(op);
            continue;
        }
        if op.seq != a.seq + 1 {
            out.rejected.push(refuse(&format!("seq {} after {}", op.seq, a.seq)));
            broken.push(op.author.clone());
            continue;
        }
        if op.prev != a.hash {
            out.rejected.push(refuse("prev is not the hash of the author's op before"));
            broken.push(op.author.clone());
            continue;
        }
        a.advance(op.seq, &op.hash);
        out.good.push(op);
    }
    out
}

/// Whether `op` is signed by `sign_pub` (raw P-256, base64url).
pub(crate) fn signed_by(op: &Served, sign_pub: &str) -> bool {
    unb64(sign_pub).ok().and_then(|raw| VerifyingKey::from_sec1_bytes(&raw).ok()).is_some_and(|key| op.verify(&key).is_ok())
}

/// A member as the log has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Member {
    pub keys: MemberKeys,
    /// The entry that added it.
    pub added_at: u64,
    /// The entry that removed it, and its last op that counts.
    pub removed: Option<(u64, u64)>,
}

/// One entry on the log, and the op that carried it.
#[derive(Debug, Clone)]
pub(crate) struct Logged {
    pub head: String,
    pub entry: Entry,
    /// The back-wrap (a remove's previous key under its new one).
    pub back: String,
}

/// The membership log, followed from the founder the member pinned.
#[derive(Debug, Clone, Default)]
pub(crate) struct Log {
    pub entries: Vec<Logged>,
    pub members: BTreeMap<String, Member>,
    /// The authority after each entry.
    pub authority: Vec<String>,
    /// Each entry's place, by head.
    pub heads: BTreeMap<String, u64>,
    /// Two different entries at this place, both the authority's.
    pub fork: Option<u64>,
    /// Ops by a member that don't verify with the key the log gives it.
    pub forged: Vec<Rejected>,
    /// Entries that claimed a place on the log but aren't the authority's.
    pub ignored: Vec<Rejected>,
    /// Other rings' founders on this edge: device and ring fingerprint.
    pub other_founders: Vec<(String, String)>,
    /// Devices that asked to join and aren't members: their request.
    pub requests: BTreeMap<String, MemberKeys>,
}

impl Log {
    pub(crate) fn founder(&self) -> Option<&str> {
        self.entries.first().and_then(|l| l.entry.member.as_ref()).map(|m| m.device.as_str())
    }

    pub(crate) fn head(&self) -> Option<&str> {
        self.entries.last().map(|l| l.head.as_str())
    }

    pub(crate) fn current_authority(&self) -> Option<&str> {
        self.authority.last().map(String::as_str)
    }

    /// The epoch after the last entry, and its key's id.
    pub(crate) fn epoch(&self) -> Option<(u32, &str)> {
        self.entries.last().map(|l| (l.entry.epoch, l.entry.id.as_str()))
    }

    /// The id of `epoch`'s key, as the log has it.
    pub(crate) fn id_of(&self, epoch: u32) -> Option<&str> {
        self.entries.iter().find(|l| l.entry.epoch == epoch).map(|l| l.entry.id.as_str())
    }

    /// Whether `device` is a member at entry `n`.
    pub(crate) fn member_at(&self, device: &str, n: u64) -> Option<&Member> {
        self.members.get(device).filter(|m| m.added_at <= n && m.removed.is_none_or(|(r, _)| n < r))
    }

    /// Members now.
    pub(crate) fn active(&self) -> impl Iterator<Item = &Member> {
        self.members.values().filter(|m| m.removed.is_none())
    }

    pub(crate) fn is_active(&self, device: &str) -> bool {
        self.members.get(device).is_some_and(|m| m.removed.is_none())
    }

    /// Whether `op` (a value op written under entry `n`) counts: its author
    /// is a member there, signed it with the key the log gives it, and, if
    /// removed later, wrote it no later than the removal's cut.
    pub(crate) fn counts(&self, op: &Served, n: u64) -> Result<(), &'static str> {
        let m = self.member_at(&op.author, n).ok_or("its author isn't a member at the head it names")?;
        if m.removed.is_some_and(|(_, after)| op.seq > after) {
            return Err("its author was removed before it");
        }
        if !signed_by(op, &m.keys.sign_pub) {
            return Err("forged: not signed by the key the log gives its author");
        }
        Ok(())
    }
}

/// Opens an ECIES wrap with this member's key-agreement key.
pub(crate) type Unwrap<'a> = &'a dyn Fn(&[u8]) -> Result<Zeroizing<Vec<u8>>>;

/// An entry an op carries, if it carries one.
pub(crate) fn entry_of(op: &Served) -> Option<Entry> {
    if !matches!(op.kind, Kind::MemberAdd | Kind::Rekey) {
        return None;
    }
    read_plain_body(op.sealed.as_deref()?).ok()
}

/// A ring's fingerprint, from its founder's keys.
pub(crate) fn fingerprint_of(m: &MemberKeys) -> String {
    ring_fingerprint(&unb64(&m.sign_pub).unwrap_or_default(), &unb64(&m.agree_pub).unwrap_or_default())
}

/// The log, followed from the `found` entry whose ring fingerprint is
/// `trusted`, through `ops` (the ring ops held, from every author). `me`'s
/// own queued ops aren't signed until the sync that sends them: one with no
/// signature at all can only be this member's own local copy (the edge takes
/// none without), so it is taken as signed. Any op with a signature is
/// checked.
pub(crate) fn follow(ops: &[Served], trusted: Option<&str>, me: &str) -> Log {
    let signed_by = |op: &Served, sign_pub: &str| (op.author == me && op.sig.is_empty()) || signed_by(op, sign_pub);
    let candidates: Vec<(&Served, Entry, String)> = ops.iter().filter_map(|op| entry_of(op).map(|e| (op, e, head_of(op.sealed.as_deref().unwrap_or_default())))).collect();
    let mut log = Log::default();
    let founding: Vec<&(&Served, Entry, String)> = candidates
        .iter()
        .filter(|(op, e, _)| e.what == EntryType::Found && e.n == 0 && e.prev.is_empty() && e.member.as_ref().is_some_and(|m| m.device == op.author))
        .collect();
    for (op, e, _) in &founding {
        let m = e.member.as_ref().expect("checked");
        if trusted != Some(fingerprint_of(m).as_str()) {
            log.other_founders.push((op.author.clone(), fingerprint_of(m)));
        }
    }
    let ours: Vec<&&(&Served, Entry, String)> = founding.iter().filter(|(op, e, _)| trusted == Some(fingerprint_of(e.member.as_ref().expect("checked")).as_str()) && signed_by(op, &e.member.as_ref().expect("checked").sign_pub)).collect();
    let heads: BTreeSet<&str> = ours.iter().map(|(_, _, h)| h.as_str()).collect();
    match heads.len() {
        0 => {}
        1 => {
            let (op, e, head) = ours[0];
            let m = e.member.clone().expect("checked");
            log.members.insert(m.device.clone(), Member { keys: m, added_at: 0, removed: None });
            log.authority.push(op.author.clone());
            log.heads.insert(head.clone(), 0);
            log.entries.push(Logged { head: head.clone(), entry: e.clone(), back: String::new() });
        }
        _ => log.fork = Some(0),
    }
    while log.fork.is_none() && !log.entries.is_empty() {
        let n = log.entries.len() as u64;
        let prev = log.head().expect("not empty").to_owned();
        let authority = log.current_authority().expect("not empty").to_owned();
        let mut next: BTreeMap<String, (&Served, Entry)> = BTreeMap::new();
        for (op, e, head) in &candidates {
            if e.n != n || e.prev != prev {
                continue;
            }
            let genuine = log.members.get(&op.author).is_some_and(|m| signed_by(op, &m.keys.sign_pub));
            if op.author != authority || !genuine || !valid_next(&log, op, e) {
                let rejected = Rejected { author: op.author.clone(), seq: op.seq, reason: "a membership entry that isn't the authority's: ignored".into() };
                if genuine || !log.members.contains_key(&op.author) {
                    log.ignored.push(rejected);
                } else {
                    log.forged.push(Rejected { reason: "forged: not signed by the key the log gives its author".into(), ..rejected });
                }
                continue;
            }
            next.insert(head.clone(), (*op, e.clone()));
        }
        match next.len() {
            0 => break,
            1 => {
                let (head, (op, e)) = next.into_iter().next().expect("one");
                apply_entry(&mut log, head, e, op.wrapped_key.clone().unwrap_or_default());
            }
            _ => log.fork = Some(n),
        }
    }
    // Requests: a device's own, signed by the key it names, while it isn't a member.
    for op in ops.iter().filter(|op| op.kind == Kind::MemberAdd) {
        if let Some(r) = op.sealed.as_deref().and_then(|s| read_plain_body::<Request>(s).ok())
            && r.member.device == op.author
            && !log.members.contains_key(&op.author)
            && signed_by(op, &r.member.sign_pub)
        {
            log.requests.insert(op.author.clone(), r.member);
        }
    }
    log
}

/// What an entry may say, given the log before it.
fn valid_next(log: &Log, op: &Served, e: &Entry) -> bool {
    let (epoch, id) = log.epoch().expect("not empty");
    let keeps_epoch = e.epoch == epoch && e.id == id;
    match e.what {
        EntryType::Found => false,
        EntryType::Add => keeps_epoch && op.kind == Kind::MemberAdd && e.member.as_ref().is_some_and(|m| !log.members.contains_key(&m.device)),
        EntryType::Transfer => keeps_epoch && op.kind == Kind::MemberAdd && e.authority.as_deref().is_some_and(|a| log.is_active(a) && Some(a) != log.current_authority()),
        EntryType::Remove => {
            op.kind == Kind::Rekey
                && epoch.checked_add(1) == Some(e.epoch)
                && !e.removed.is_empty()
                && e.removed.iter().all(|r| log.is_active(&r.device) && Some(r.device.as_str()) != log.current_authority())
                && e.wraps.keys().all(|d| log.is_active(d) && !e.removed.iter().any(|r| r.device == *d))
        }
    }
}

fn apply_entry(log: &mut Log, head: String, e: Entry, back: String) {
    let n = e.n;
    let mut authority = log.current_authority().expect("not empty").to_owned();
    match e.what {
        EntryType::Add => {
            let m = e.member.clone().expect("checked");
            log.members.insert(m.device.clone(), Member { keys: m, added_at: n, removed: None });
        }
        EntryType::Remove => {
            for r in &e.removed {
                if let Some(m) = log.members.get_mut(&r.device) {
                    m.removed = Some((n, r.after));
                }
            }
        }
        EntryType::Transfer => authority = e.authority.clone().expect("checked"),
        EntryType::Found => {}
    }
    log.authority.push(authority);
    log.heads.insert(head.clone(), n);
    log.entries.push(Logged { head, entry: e, back });
}

/// The ring keys `me` can reach from the log: each entry's wrap to it, and
/// each remove's back-wrap (its new key opens the one before). Every key is
/// checked against the id the log has for its epoch. Returns whether `held`
/// changed.
pub(crate) fn reach_keys(me: &str, log: &Log, held: &mut Vec<RingKey>, unwrap: Unwrap) -> bool {
    let mut changed = false;
    let has = |held: &Vec<RingKey>, epoch: u32| held.iter().any(|k| k.epoch == epoch);
    for l in &log.entries {
        let e = &l.entry;
        if has(held, e.epoch) {
            continue;
        }
        let Some(wrap) = e.wraps.get(me) else { continue };
        if let Some(key) = unb64(wrap).ok().and_then(|w| unwrap(&w).ok()).and_then(|plain| unwrapped_ring(&plain, e.epoch, me))
            && ring_id(&key, e.epoch) == e.id
        {
            held.push(RingKey { epoch: e.epoch, key });
            changed = true;
        }
    }
    loop {
        let mut more = false;
        for l in log.entries.iter().rev().filter(|l| l.entry.what == EntryType::Remove) {
            let e = &l.entry;
            let before = e.epoch - 1;
            if has(held, before) {
                continue;
            }
            let Some(new) = held.iter().find(|k| k.epoch == e.epoch) else { continue };
            let Some(wrapped) = unb64(&l.back).ok() else { continue };
            let Some(prev) = gcm_open(&wrap_key(&new.key), &wrapped, rekey_ad(e.epoch).as_bytes()).ok() else { continue };
            let Ok(prev) = <[u8; 32]>::try_from(prev.as_slice()) else { continue };
            if log.id_of(before).is_some_and(|id| ring_id(&prev, before) == id) {
                held.push(RingKey { epoch: before, key: Zeroizing::new(prev) });
                more = true;
            }
        }
        changed |= more;
        if !more {
            return changed;
        }
    }
}
