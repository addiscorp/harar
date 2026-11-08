//! What a member keeps of the ring's ops, and what it works out from them
//! (docs/edge.md §5b): each author's verified chain, who the members are,
//! and the ring keys. Nothing here is trusted to the edge.
//!
//! - Every author's chain verifies from its first op: seq counts up by one,
//!   prev is the hash before, and each op is signed by the author's key. A
//!   ring op served compacted breaks the chain: the edge never compacts one,
//!   so it is hiding it.
//! - An author's first op is a member.add of itself, which carries its
//!   signing and key-agreement keys; every later op is checked against it.
//! - The founder is the one author whose first op adds itself with a MAC
//!   under the epoch-0 ring key this member holds, and whose ring
//!   fingerprint this member pinned. Two such ops are a ring conflict, and
//!   nobody is a member until it is resolved.
//! - Members are the founder and the devices members' grants name, with the
//!   keys that device's own chain carries (a grant naming other keys makes no
//!   member, and that device's ops don't count). A member.remove ends a
//!   member's ops at the seq it names. Three fixed passes, each growing a set
//!   only, so the answer doesn't depend on the order ops arrive in.
//! - A rekey is taken only from an author who counts at its seq, to the next
//!   epoch after a key this member holds, with its back-wrap opening to that
//!   key. Epoch 0 comes only from the founder's self-grant.

use super::crypto::{Key32, gcm_open, member_mac, ring_fingerprint, unb64, wrap_key};
use super::op::{Kind, MemberBody, Rank, RekeyBody, RemoveBody, Served, add_mac_text, read_plain_body, rekey_ad, rekey_mac_text, remove_mac_text};
use anyhow::Result;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// The verified tip of an author's chain, and the keys its first op carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Author {
    pub sign_pub: String,
    #[serde(default)]
    pub agree_pub: String,
    pub seq: u64,
    pub hash: String,
}

/// An op the ledger refused, and why. Never its contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Rejected {
    pub author: String,
    pub seq: u64,
    pub reason: String,
}

/// One ring key, in memory only while the vault is unlocked.
pub(crate) struct RingKey {
    pub epoch: u32,
    pub key: Key32,
    /// The rekey that made it, once known; None for epoch 0.
    pub rank: Option<Rank>,
}

impl std::fmt::Debug for RingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingKey").field("epoch", &self.epoch).field("rank", &self.rank).finish_non_exhaustive()
    }
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
    /// Devices a grant named with keys that aren't their own.
    pub mismatched: BTreeSet<String>,
    /// Every other device whose first op founds a ring on this edge.
    pub other_founders: Vec<(String, Rank)>,
    /// More than one founder verifies under the keys held: nobody counts.
    pub conflict: bool,
}

impl Roster {
    /// Whether `author`'s op `seq` counts.
    pub(crate) fn counts(&self, author: &str, seq: u64) -> bool {
        !self.mismatched.contains(author) && self.members.get(author).is_some_and(|m| m.after.is_none_or(|after| seq <= after))
    }

    pub(crate) fn active(&self) -> impl Iterator<Item = (&String, &Member)> {
        self.members.iter().filter(|(id, m)| m.after.is_none() && !self.mismatched.contains(*id))
    }
}

/// Checks `ops` (one pull, in each author's seq order) against the chains
/// already verified in `authors`, and advances them. Returns the ops that
/// verified, in order; the others are rejected with a reason. An author whose
/// chain breaks has nothing after the break taken.
pub(crate) fn verify_chains(authors: &mut BTreeMap<String, Author>, me: &str, ops: Vec<Served>, rejected: &mut Vec<Rejected>) -> Vec<Served> {
    let mut good = Vec::new();
    let mut broken: Vec<String> = Vec::new();
    for op in ops {
        if broken.contains(&op.author) {
            continue;
        }
        match verify_one(authors, me, &op) {
            Ok(true) => good.push(op),
            Ok(false) => {}
            Err(reason) => {
                rejected.push(Rejected { author: op.author.clone(), seq: op.seq, reason });
                broken.push(op.author.clone());
            }
        }
    }
    good
}

/// Ok(true): verified and new. Ok(false): already have it.
fn verify_one(authors: &mut BTreeMap<String, Author>, me: &str, op: &Served) -> std::result::Result<bool, String> {
    let (tip_seq, tip_hash) = authors.get(&op.author).map(|a| (a.seq, a.hash.clone())).unwrap_or((0, String::new()));
    if op.seq <= tip_seq && op.author != me {
        return Ok(false);
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
        let a = authors.entry(op.author.clone()).or_insert(Author { sign_pub, agree_pub, seq: 0, hash: String::new() });
        if op.seq > a.seq {
            a.seq = op.seq;
            a.hash = op.hash.clone();
        }
        return Ok(op.seq > tip_seq);
    }
    if op.seq != tip_seq + 1 {
        return Err(format!("seq {} after {tip_seq}", op.seq));
    }
    if op.prev != tip_hash {
        return Err("prev is not the hash of the author's op before".into());
    }
    authors.insert(op.author.clone(), Author { sign_pub, agree_pub, seq: op.seq, hash: op.hash.clone() });
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

fn mac_ok(keys: &[RingKey], epoch: u32, text: &str, mac: &str) -> bool {
    keys.iter().filter(|k| k.epoch == epoch).any(|k| member_mac(&k.key, text) == mac)
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
    let verifying: Vec<&(&Served, MemberBody)> = shaped.iter().filter(|(op, body)| mac_ok(keys, 0, &add_mac_text(&body.device, 0), &op.key)).collect();
    let mut roster = Roster::default();
    let founder = match verifying.as_slice() {
        [one] if trusted.is_some_and(|t| fingerprint_of(&one.1) == t) => Some(*one),
        [_, _, ..] => {
            roster.conflict = true;
            None
        }
        _ => None,
    };
    roster.other_founders = shaped.iter().filter(|(op, _)| founder.is_none_or(|(f, _)| f.author != op.author)).map(|(op, _)| (op.author.clone(), op.rank())).collect();
    let Some((founder_op, founder_body)) = founder else {
        roster.requests = requests(&read, &roster);
        return roster;
    };
    let founder = founder_op.author.clone();

    // A grant names its device with the keys that device's own chain has, or
    // it makes no member (and that device's ops don't count).
    let mut grants = Vec::new();
    for (op, s) in &read {
        if let Said::Add { body, wraps: true } = s
            && mac_ok(keys, body.epoch, &add_mac_text(&body.device, body.epoch), &op.key)
        {
            if authors.get(&body.device).is_some_and(|a| a.sign_pub != body.sign_pub || a.agree_pub != body.agree_pub) {
                roster.mismatched.insert(body.device.clone());
            } else {
                grants.push((*op, body));
            }
        }
    }
    let removes: Vec<(&Served, &RemoveBody)> = read
        .iter()
        .filter_map(|(op, s)| match s {
            Said::Remove(body) if keys.iter().any(|k| member_mac(&k.key, &remove_mac_text(&body.device, body.after)) == op.key) => Some((*op, body)),
            _ => None,
        })
        .collect();
    let start = || BTreeMap::from([(founder.clone(), Member { name: founder_body.name.clone(), sign_pub: founder_body.sign_pub.clone(), agree_pub: founder_body.agree_pub.clone(), after: None })]);
    let closure = |cuts: &BTreeMap<String, u64>| {
        let mut set = start();
        loop {
            let mut grew = false;
            for (op, body) in &grants {
                let by_member = set.contains_key(&op.author) && cuts.get(&op.author).is_none_or(|after| op.seq <= *after);
                if by_member && !set.contains_key(&body.device) {
                    set.insert(body.device.clone(), Member { name: body.name.clone(), sign_pub: body.sign_pub.clone(), agree_pub: body.agree_pub.clone(), after: None });
                    grew = true;
                }
            }
            if !grew {
                return set;
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
    let first = closure(&BTreeMap::new());
    let cuts = cut_by(&first, &BTreeMap::new());
    let mut members = closure(&cuts);
    let cuts = cut_by(&members, &cuts);
    for (id, m) in &mut members {
        m.after = cuts.get(id).copied();
    }
    for id in &roster.mismatched {
        members.remove(id);
    }
    roster.founder = Some(founder);
    roster.members = members;
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

/// The key a rekey's back-wrap holds, opened with `new` (the rekey's own key).
fn back_of(op: &Served, epoch: u32, new: &[u8; 32]) -> Option<Key32> {
    let wrapped = unb64(op.wrapped_key.as_deref()?).ok()?;
    let prev = gcm_open(&wrap_key(new), &wrapped, rekey_ad(epoch).as_bytes()).ok()?;
    let prev: [u8; 32] = prev.as_slice().try_into().ok()?;
    Some(Zeroizing::new(prev))
}

/// Older keys reached from the keys held: each rekey's own key opens the one
/// before (so a member approved after a rekey reads the whole history), and
/// learns which rekey made it. Never a second, different epoch-0 key.
/// Returns whether `held` changed.
pub(crate) fn reach_back(ops: &[Served], held: &mut Vec<RingKey>) -> bool {
    let mut changed = false;
    loop {
        let mut more = false;
        for (op, body) in rekeys(ops) {
            if body.epoch == 0 {
                continue;
            }
            let Some(i) = held.iter().position(|k| k.epoch == body.epoch && back_of(op, body.epoch, &k.key).is_some()) else { continue };
            if held[i].rank.is_none() {
                held[i].rank = Some(op.rank());
                more = true;
            }
            let prev = back_of(op, body.epoch, &held[i].key).expect("it opened above");
            let before = body.epoch - 1;
            let mac = member_mac(&prev, &rekey_mac_text(body.epoch)) == op.key;
            let have = held.iter().any(|k| k.epoch == before && *k.key == *prev);
            let other_zero = before == 0 && held.iter().any(|k| k.epoch == 0 && *k.key != *prev);
            if mac && !have && !other_zero {
                held.push(RingKey { epoch: before, key: prev, rank: None });
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
        if body.epoch == 0 || !roster.counts(&op.author, op.seq) || held.iter().any(|k| k.epoch == body.epoch && back_of(op, body.epoch, &k.key).is_some()) {
            continue;
        }
        let Some(wrap) = body.wraps.get(me) else { continue };
        let Some(new) = unb64(wrap).ok().and_then(|w| unwrap(&w).ok()).and_then(|plain| super::crypto::unwrapped_ring(&plain, body.epoch, me)) else { continue };
        let Some(prev) = back_of(op, body.epoch, &new) else { continue };
        let before = body.epoch - 1;
        if held.iter().any(|k| k.epoch == before && *k.key == *prev) && member_mac(&prev, &rekey_mac_text(body.epoch)) == op.key {
            held.push(RingKey { epoch: body.epoch, key: new, rank: Some(op.rank()) });
            changed = true;
        }
    }
    changed
}

/// The key new writes use: the newest epoch a counting member's rekey made
/// (the later rekey when two made the same epoch), else the founder's
/// epoch-0 key. Nothing else: a key with no such origin is never written with.
pub(crate) fn current<'a>(keys: &'a [RingKey], ops: &[Served], roster: &Roster) -> Option<&'a RingKey> {
    let founder = roster.founder.as_deref()?;
    let founding = founder_shaped(ops).into_iter().find(|(op, _)| op.author == founder)?.0;
    let valid: Vec<Rank> = rekeys(ops).into_iter().filter(|(op, b)| b.epoch > 0 && roster.counts(&op.author, op.seq)).map(|(op, _)| op.rank()).collect();
    keys.iter()
        .filter(|k| match (&k.rank, k.epoch) {
            (_, 0) => member_mac(&k.key, &add_mac_text(founder, 0)) == founding.key,
            (Some(rank), _) => valid.contains(rank),
            (None, _) => false,
        })
        .max_by(|a, b| (a.epoch, a.rank.as_ref()).cmp(&(b.epoch, b.rank.as_ref())))
}

/// The grants to `me` in `ops`: (epoch, the wrapped ring key, author, seq).
pub(crate) fn grants_to<'a>(me: &str, ops: &'a [Served]) -> Vec<(u32, String, &'a Served)> {
    ops.iter()
        .filter_map(|op| match said(op) {
            Some(Said::Add { body, wraps: true }) if body.device == me => op.wrapped_key.clone().map(|w| (body.epoch, w, op)),
            _ => None,
        })
        .collect()
}
