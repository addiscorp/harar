//! What a member keeps of the ring's ops, and what it works out from them
//! (docs/edge.md §5b): each author's verified chain, who the members are,
//! and the ring keys. Nothing here is trusted to the edge.
//!
//! - Every author's chain verifies from its first op: seq counts up by one,
//!   prev is the hash before, and each op is signed by the author's key. A
//!   ring op served compacted breaks the chain (the edge never compacts
//!   one). A second, different op at a seq already held is a fork: shown,
//!   and the author's ops from there on don't count.
//! - An author's first op is a member.add of itself, which carries its
//!   signing and key-agreement keys; every later op is checked against it.
//! - The founder is the one author whose first op adds itself with a MAC
//!   under the epoch-0 ring key this member holds, and whose ring
//!   fingerprint this member founded or pinned.
//! - Members are the founder and the devices grants by counting members
//!   name. Every ring MAC covers the author and the whole body. A counting
//!   member's grant that names a device with keys other than its own makes
//!   no member, and that device's ops don't count. A member.remove ends a
//!   member's ops at the seq it names. Three fixed passes, each growing a set
//!   only, so the answer doesn't depend on the order ops arrive in.
//! - A ring key is named by its id (a MAC under it), never by the op that
//!   carried it, so re-signing an op changes nothing. A key is written with
//!   only if a counting member made it (epoch 0: the founder) and nobody it
//!   was ever given to has been removed since.

use super::crypto::{Key32, gcm_open, member_mac, ring_fingerprint, unb64, unwrapped_ring, wrap_key};
use super::op::{Kind, MemberBody, Rank, RekeyBody, RemoveBody, Served, add_mac_text, read_plain_body, rekey_ad, rekey_mac_text, remove_mac_text, ring_id_text};
use anyhow::Result;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// Hashes kept per author for telling a fork from a repeat.
const RECENT: usize = 64;

/// The verified tip of an author's chain, and the keys its first op carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Author {
    pub sign_pub: String,
    #[serde(default)]
    pub agree_pub: String,
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
    fn new(sign_pub: String, agree_pub: String) -> Author {
        Author { sign_pub, agree_pub, seq: 0, hash: String::new(), recent: BTreeMap::new(), fork_at: None }
    }

    fn advance(&mut self, seq: u64, hash: &str) {
        self.seq = seq;
        self.hash = hash.to_owned();
        self.recent.insert(seq, hash.to_owned());
        while self.recent.len() > RECENT {
            let first = *self.recent.keys().next().expect("not empty");
            self.recent.remove(&first);
        }
    }
}

/// An op the ledger refused, and why. Never its contents.
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct Member {
    pub name: String,
    pub sign_pub: String,
    pub agree_pub: String,
    /// Set once removed: its ops after this seq don't count.
    pub after: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Roster {
    pub founder: Option<String>,
    pub members: BTreeMap<String, Member>,
    /// Devices that asked to join and aren't members: their newest request.
    pub requests: BTreeMap<String, MemberBody>,
    /// Devices a counting member's grant named with keys that aren't theirs.
    pub mismatched: BTreeSet<String>,
    /// Authors the edge forked, from the seq it did.
    pub forked: BTreeMap<String, u64>,
    /// Every other device whose first op founds a ring on this edge, with
    /// that ring's fingerprint.
    pub other_founders: Vec<(String, Rank, String)>,
    /// More than one founder verifies under the keys held: nobody counts.
    pub conflict: bool,
}

impl Roster {
    /// Whether `author`'s op `seq` counts.
    pub(crate) fn counts(&self, author: &str, seq: u64) -> bool {
        !self.mismatched.contains(author)
            && self.forked.get(author).is_none_or(|at| seq < *at)
            && self.members.get(author).is_some_and(|m| m.after.is_none_or(|after| seq <= after))
    }

    /// Members not removed, nor named with other keys.
    pub(crate) fn active(&self) -> impl Iterator<Item = (&String, &Member)> {
        self.members.iter().filter(|(id, m)| m.after.is_none() && !self.mismatched.contains(*id))
    }

    fn is_active(&self, id: &str) -> bool {
        self.active().any(|(m, _)| m == id)
    }
}

/// What verifying a pull found.
#[derive(Default)]
pub(crate) struct Verified {
    pub good: Vec<Served>,
    pub rejected: Vec<Rejected>,
    pub forks: Vec<Fork>,
}

/// Checks `ops` (one pull, in each author's seq order) against the chains
/// already verified in `authors`, and advances them. An author whose chain
/// breaks has nothing after the break taken.
pub(crate) fn verify_chains(authors: &mut BTreeMap<String, Author>, me: &str, ops: Vec<Served>) -> Verified {
    let mut out = Verified::default();
    let mut broken: Vec<String> = Vec::new();
    for op in ops {
        if broken.contains(&op.author) {
            continue;
        }
        match verify_one(authors, me, &op) {
            Ok(true) => out.good.push(op),
            Ok(false) => {}
            Err(Bad::Rejected(reason)) => {
                out.rejected.push(Rejected { author: op.author.clone(), seq: op.seq, reason });
                broken.push(op.author.clone());
            }
            Err(Bad::Fork(known)) => {
                let a = authors.get_mut(&op.author).expect("a fork is of a known author");
                a.fork_at = Some(a.fork_at.map_or(op.seq, |f| f.min(op.seq)));
                out.forks.push(Fork { author: op.author.clone(), seq: op.seq, hashes: [known, op.hash.clone()] });
                broken.push(op.author.clone());
            }
        }
    }
    out
}

enum Bad {
    Rejected(String),
    Fork(String),
}

impl From<String> for Bad {
    fn from(reason: String) -> Bad {
        Bad::Rejected(reason)
    }
}

impl From<&str> for Bad {
    fn from(reason: &str) -> Bad {
        Bad::Rejected(reason.to_owned())
    }
}

/// Ok(true): verified and new. Ok(false): already have it.
fn verify_one(authors: &mut BTreeMap<String, Author>, me: &str, op: &Served) -> std::result::Result<bool, Bad> {
    let (tip_seq, tip_hash) = authors.get(&op.author).map(|a| (a.seq, a.hash.clone())).unwrap_or((0, String::new()));
    if op.seq <= tip_seq && op.author != me {
        let known = authors.get(&op.author).and_then(|a| a.recent.get(&op.seq).cloned());
        return match known {
            Some(known) if known != op.hash => Err(Bad::Fork(known)),
            _ => Ok(false),
        };
    }
    if op.compacted && !op.kind.is_value() {
        return Err("a ring op served compacted: the edge never compacts one".into());
    }
    let (sign_pub, agree_pub) = match authors.get(&op.author) {
        Some(a) => (a.sign_pub.clone(), a.agree_pub.clone()),
        None => {
            // The first op carries the keys: a member.add of the author itself.
            if op.seq != 1 || op.kind != Kind::MemberAdd {
                return Err("the author's first op is not a member.add of itself".into());
            }
            let body: MemberBody = op.sealed.as_deref().ok_or("its first op has no body").and_then(|s| read_plain_body(s).map_err(|_| "its first op's body doesn't read"))?;
            if body.device != op.author {
                return Err("the author's first op is not a member.add of itself".into());
            }
            (body.sign_pub, body.agree_pub)
        }
    };
    let key = unb64(&sign_pub).ok().and_then(|raw| VerifyingKey::from_sec1_bytes(&raw).ok()).ok_or("the author's key doesn't read")?;
    op.verify(&key).map_err(|err| format!("{err:#}"))?;
    if op.author == me {
        // Our own op back from the edge: signed by us, so ours. Our chain is
        // built here, so it is not checked against itself.
        let a = authors.entry(op.author.clone()).or_insert_with(|| Author::new(sign_pub, agree_pub));
        if op.seq > a.seq {
            a.advance(op.seq, &op.hash);
        }
        return Ok(op.seq > tip_seq);
    }
    if op.seq != tip_seq + 1 {
        return Err(format!("seq {} after {tip_seq}", op.seq).into());
    }
    if op.prev != tip_hash {
        return Err("prev is not the hash of the author's op before".into());
    }
    authors.entry(op.author.clone()).or_insert_with(|| Author::new(sign_pub, agree_pub)).advance(op.seq, &op.hash);
    Ok(true)
}

/// What a member.add or member.remove says, read once.
enum Said {
    Add { body: MemberBody, wraps: bool },
    Remove(RemoveBody),
}

fn said(op: &Served) -> Option<Said> {
    let sealed = op.sealed.as_deref()?;
    match op.kind {
        Kind::MemberAdd => read_plain_body(sealed).ok().map(|body| Said::Add { body, wraps: op.wrapped_key.as_deref().is_some_and(|w| !w.is_empty()) }),
        Kind::MemberRemove => read_plain_body(sealed).ok().map(Said::Remove),
        _ => None,
    }
}

/// Opens an ECIES wrap with this member's key-agreement key.
pub(crate) type Unwrap<'a> = &'a dyn Fn(&[u8]) -> Result<Zeroizing<Vec<u8>>>;

fn add_ok(keys: &[RingKey], op: &Served, body: &MemberBody) -> bool {
    let text = add_mac_text(&op.author, body);
    keys.iter().filter(|k| k.epoch == body.epoch).any(|k| member_mac(&k.key, &text) == op.key)
}

/// The ops whose first op founds a ring: a member.add of itself, wrapping a
/// ring key, at epoch 0.
pub(crate) fn founder_shaped(ops: &[Served]) -> Vec<(&Served, MemberBody)> {
    ops.iter()
        .filter_map(|op| match said(op) {
            Some(Said::Add { body, wraps: true }) if op.seq == 1 && body.device == op.author && body.epoch == 0 => Some((op, body)),
            _ => None,
        })
        .collect()
}

/// A ring's fingerprint, from its founder's member.add.
pub(crate) fn fingerprint_of(body: &MemberBody) -> String {
    ring_fingerprint(&unb64(&body.sign_pub).unwrap_or_default(), &unb64(&body.agree_pub).unwrap_or_default())
}

/// Who the members are, from every ring op this member has verified, the
/// ring keys it holds (a ring op counts only with a MAC under one), the
/// authors' own keys, and the ring fingerprint it pinned.
pub(crate) fn roster(ops: &[Served], keys: &[RingKey], authors: &BTreeMap<String, Author>, trusted: Option<&str>) -> Roster {
    let read: Vec<(&Served, Said)> = ops.iter().filter_map(|op| said(op).map(|s| (op, s))).collect();
    let shaped = founder_shaped(ops);
    let verifying: Vec<&(&Served, MemberBody)> = shaped.iter().filter(|(op, body)| add_ok(keys, op, body)).collect();
    let mut roster = Roster { forked: authors.iter().filter_map(|(id, a)| a.fork_at.map(|f| (id.clone(), f))).collect(), ..Roster::default() };
    let founder = match verifying.as_slice() {
        [one] if trusted.is_some_and(|t| fingerprint_of(&one.1) == t) => Some(*one),
        [_, _, ..] => {
            roster.conflict = true;
            None
        }
        _ => None,
    };
    roster.other_founders = shaped
        .iter()
        .filter(|(op, _)| founder.is_none_or(|(f, _)| f.author != op.author))
        .map(|(op, body)| (op.author.clone(), op.rank(), fingerprint_of(body)))
        .collect();
    let Some((founder_op, founder_body)) = founder else {
        roster.requests = requests(&read, &roster);
        return roster;
    };
    let founder = founder_op.author.clone();
    let not_forked = |author: &str, seq: u64| roster.forked.get(author).is_none_or(|at| seq < *at);

    let grants: Vec<(&Served, &MemberBody)> = read
        .iter()
        .filter_map(|(op, s)| match s {
            Said::Add { body, wraps: true } if add_ok(keys, op, body) && not_forked(&op.author, op.seq) => Some((*op, body)),
            _ => None,
        })
        .collect();
    let removes: Vec<(&Served, &RemoveBody)> = read
        .iter()
        .filter_map(|(op, s)| match s {
            Said::Remove(body) if not_forked(&op.author, op.seq) && keys.iter().any(|k| member_mac(&k.key, &remove_mac_text(&op.author, &body.device, body.after)) == op.key) => Some((*op, body)),
            _ => None,
        })
        .collect();
    let start = || BTreeMap::from([(founder.clone(), Member { name: founder_body.name.clone(), sign_pub: founder_body.sign_pub.clone(), agree_pub: founder_body.agree_pub.clone(), after: None })]);
    // Grants by members, within their cuts. A grant naming a device with
    // keys other than its own makes no member and marks the device; only a
    // grant whose author counts can do that.
    let closure = |cuts: &BTreeMap<String, u64>| {
        let mut set = start();
        let mut mismatched = BTreeSet::new();
        loop {
            let mut grew = false;
            for (op, body) in &grants {
                let by_member = set.contains_key(&op.author) && cuts.get(&op.author).is_none_or(|after| op.seq <= *after);
                if !by_member {
                    continue;
                }
                if authors.get(&body.device).is_some_and(|a| a.sign_pub != body.sign_pub || a.agree_pub != body.agree_pub) {
                    grew |= mismatched.insert(body.device.clone());
                } else if !set.contains_key(&body.device) {
                    set.insert(body.device.clone(), Member { name: body.name.clone(), sign_pub: body.sign_pub.clone(), agree_pub: body.agree_pub.clone(), after: None });
                    grew = true;
                }
            }
            if !grew {
                return (set, mismatched);
            }
        }
    };
    let cut_by = |set: &BTreeMap<String, Member>, cuts: &BTreeMap<String, u64>| {
        let mut out: BTreeMap<String, u64> = BTreeMap::new();
        for (op, body) in &removes {
            if set.contains_key(&op.author) && cuts.get(&op.author).is_none_or(|after| op.seq <= *after) {
                let at = out.entry(body.device.clone()).or_insert(body.after);
                *at = (*at).min(body.after);
            }
        }
        out
    };
    // 1: everyone a grant reaches; 2: the removals they made; 3: everyone a
    // grant within its author's cut reaches, and the removals within theirs.
    let (first, _) = closure(&BTreeMap::new());
    let cuts = cut_by(&first, &BTreeMap::new());
    let (mut members, mismatched) = closure(&cuts);
    let cuts = cut_by(&members, &cuts);
    for (id, m) in &mut members {
        m.after = cuts.get(id).copied();
    }
    for id in &mismatched {
        members.remove(id);
    }
    roster.founder = Some(founder);
    roster.members = members;
    roster.mismatched = mismatched;
    roster.requests = requests(&read, &roster);
    roster
}

fn requests(read: &[(&Served, Said)], roster: &Roster) -> BTreeMap<String, MemberBody> {
    let mut out = BTreeMap::new();
    for (op, s) in read {
        if let Said::Add { body, wraps: false } = s
            && body.device == op.author
            && !roster.members.contains_key(&op.author)
        {
            out.insert(op.author.clone(), body.clone());
        }
    }
    out
}

/// The rekeys, read.
fn rekeys(ops: &[Served]) -> Vec<(&Served, RekeyBody)> {
    ops.iter().filter(|op| op.kind == Kind::Rekey).filter_map(|op| op.sealed.as_deref().and_then(|s| read_plain_body(s).ok()).map(|b| (op, b))).collect()
}

/// The key a rekey's back-wrap holds, opened with the rekey's own key.
fn back_of(op: &Served, epoch: u32, new: &[u8; 32]) -> Option<Key32> {
    let wrapped = unb64(op.wrapped_key.as_deref()?).ok()?;
    let prev = gcm_open(&wrap_key(new), &wrapped, rekey_ad(epoch).as_bytes()).ok()?;
    let prev: [u8; 32] = prev.as_slice().try_into().ok()?;
    Some(Zeroizing::new(prev))
}

/// Whether `op` is the rekey that made `key`, and what it backs onto.
fn rekey_of(op: &Served, body: &RekeyBody, key: &[u8; 32]) -> Option<Key32> {
    if body.epoch == 0 || ring_id(key, body.epoch) != body.id {
        return None;
    }
    let prev = back_of(op, body.epoch, key)?;
    (member_mac(&prev, &rekey_mac_text(&op.author, body.epoch, &body.id)) == op.key).then_some(prev)
}

/// Older keys reached from the keys held: each rekey's own key opens the one
/// before (so a member approved after a rekey reads the whole history).
/// Never a second, different epoch-0 key. Returns whether `held` changed.
pub(crate) fn reach_back(ops: &[Served], held: &mut Vec<RingKey>) -> bool {
    let mut changed = false;
    loop {
        let mut more = false;
        for (op, body) in rekeys(ops) {
            let Some(prev) = held.iter().filter(|k| k.epoch == body.epoch).find_map(|k| rekey_of(op, &body, &k.key)) else { continue };
            let before = body.epoch - 1;
            let have = held.iter().any(|k| k.epoch == before && *k.key == *prev);
            let other_zero = before == 0 && held.iter().any(|k| k.epoch == 0 && *k.key != *prev);
            if !have && !other_zero {
                held.push(RingKey { epoch: before, key: prev });
                more = true;
            }
        }
        changed |= more;
        if !more {
            return changed;
        }
    }
}

/// Newer keys: a rekey's wrap to `me` gives its key, only when its author
/// counts at its seq, its epoch is one past a key held, its back-wrap opens
/// to that key, and its MAC is under that key. Returns whether `held` changed.
pub(crate) fn reach_forward(me: &str, ops: &[Served], held: &mut Vec<RingKey>, roster: &Roster, unwrap: Unwrap) -> bool {
    let mut changed = false;
    for (op, body) in rekeys(ops) {
        if body.epoch == 0 || !roster.counts(&op.author, op.seq) || held.iter().any(|k| k.epoch == body.epoch && ring_id(&k.key, body.epoch) == body.id) {
            continue;
        }
        let Some(wrap) = body.wraps.get(me) else { continue };
        let Some(new) = unb64(wrap).ok().and_then(|w| unwrap(&w).ok()).and_then(|plain| unwrapped_ring(&plain, body.epoch, me)) else { continue };
        let Some(prev) = rekey_of(op, &body, &new) else { continue };
        if held.iter().any(|k| k.epoch == body.epoch - 1 && *k.key == *prev) {
            held.push(RingKey { epoch: body.epoch, key: new });
            changed = true;
        }
    }
    changed
}

/// Who a key was given to, if a counting member made it (the founder, for
/// epoch 0): its maker, a rekey's wraps, and every counting grant under it.
/// None: nobody who counts made it, so it is never written with.
pub(crate) fn given_to(key: &RingKey, ops: &[Served], roster: &Roster) -> Option<BTreeSet<String>> {
    let founder = roster.founder.as_deref()?;
    let mut to = if key.epoch == 0 {
        let (op, body) = founder_shaped(ops).into_iter().find(|(op, _)| op.author == founder)?;
        add_ok(std::slice::from_ref(key), op, &body).then(|| BTreeSet::from([founder.to_owned()]))?
    } else {
        let mut made = None;
        for (op, body) in rekeys(ops) {
            if body.epoch == key.epoch && roster.counts(&op.author, op.seq) && rekey_of(op, &body, &key.key).is_some() {
                let set = made.get_or_insert_with(BTreeSet::new);
                set.insert(op.author.clone());
                set.extend(body.wraps.keys().cloned());
            }
        }
        made?
    };
    for op in ops.iter().filter(|op| op.kind == Kind::MemberAdd && roster.counts(&op.author, op.seq)) {
        if let Some(Said::Add { body, wraps: true }) = said(op)
            && add_ok(std::slice::from_ref(key), op, &body)
        {
            to.insert(body.device);
        }
    }
    Some(to)
}

/// The key new writes use: of the keys a counting member made and that were
/// never given to a device since removed (or named with other keys), the
/// newest epoch, and of two at one epoch the one with the larger id.
pub(crate) fn current<'a>(keys: &'a [RingKey], ops: &[Served], roster: &Roster) -> Option<&'a RingKey> {
    keys.iter()
        .filter(|k| given_to(k, ops, roster).is_some_and(|to| to.iter().all(|d| roster.is_active(d) || (!roster.members.contains_key(d) && !roster.mismatched.contains(d)))))
        .max_by(|a, b| (a.epoch, ring_id(&a.key, a.epoch)).cmp(&(b.epoch, ring_id(&b.key, b.epoch))))
}

/// The newest epoch a counting member made a key for, among those held.
pub(crate) fn newest(keys: &[RingKey], ops: &[Served], roster: &Roster) -> Option<u32> {
    keys.iter().filter(|k| given_to(k, ops, roster).is_some()).map(|k| k.epoch).max()
}

/// The grants to `me` in `ops`: (epoch, the wrapped ring key, the op).
pub(crate) fn grants_to<'a>(me: &str, ops: &'a [Served]) -> Vec<(u32, String, &'a Served)> {
    ops.iter()
        .filter_map(|op| match said(op) {
            Some(Said::Add { body, wraps: true }) if body.device == me => op.wrapped_key.clone().map(|w| (body.epoch, w, op)),
            _ => None,
        })
        .collect()
}

/// The newest member.remove (by rank) that counts: its hash, or "".
pub(crate) fn latest_removal(ops: &[Served], keys: &[RingKey], roster: &Roster) -> String {
    ops.iter()
        .filter(|op| op.kind == Kind::MemberRemove && roster.counts(&op.author, op.seq))
        .filter(|op| matches!(said(op), Some(Said::Remove(body)) if keys.iter().any(|k| member_mac(&k.key, &remove_mac_text(&op.author, &body.device, body.after)) == op.key)))
        .max_by(|a, b| a.rank().cmp(&b.rank()))
        .map(|op| op.hash.clone())
        .unwrap_or_default()
}

/// The newest epoch a counting grant to `me` carried, and its granter's
/// newest removal.
pub(crate) fn my_grant_view(me: &str, ops: &[Served], roster: &Roster) -> Option<(u32, String)> {
    ops.iter()
        .filter(|op| op.kind == Kind::MemberAdd && roster.counts(&op.author, op.seq))
        .filter_map(|op| match said(op) {
            Some(Said::Add { body, wraps: true }) if body.device == me && op.author != me => Some((op.rank(), body.epoch, body.removal)),
            _ => None,
        })
        .max_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, epoch, removal)| (epoch, removal))
}
