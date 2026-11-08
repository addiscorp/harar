//! What a member keeps of the ring's ops, and what it works out from them
//! (docs/edge.md §5b): each author's verified chain, who the members are,
//! and the ring keys.
//!
//! The rules, all checked here and not trusted to the edge:
//! - Every author's chain verifies from its first op: seq counts up by one,
//!   prev is the hash before, and each op is signed by the author's key.
//! - An author's first op is a member.add of itself, which carries its
//!   signing key; that op is checked against the key it carries, and every
//!   later op against it.
//! - The founder is the author whose first op adds itself with the ring key
//!   of epoch 0 (its `key` is a MAC under that key). Members are the founder
//!   and every device a member's member.add names; a member.remove ends a
//!   member's ops at the seq it names. Who is a member doesn't depend on the
//!   order ops arrive in.
//! - A secret op counts only if its author is a member at that seq.

use super::crypto::{Key32, gcm_open, ring_mac, unb64};
use super::op::{Kind, MemberBody, Rank, RekeyBody, RemoveBody, Served, add_mac_text, read_plain_body, rekey_ad, rekey_mac_text, remove_mac_text};
use anyhow::Result;
use p256::ecdsa::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// The verified tip of an author's chain, and the key its ops verify with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Author {
    pub sign_pub: String,
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
    /// The rekey that made it; None for epoch 0 or a key a grant gave.
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
}

impl Roster {
    /// Whether `author`'s op `seq` counts.
    pub(crate) fn counts(&self, author: &str, seq: u64) -> bool {
        self.members.get(author).is_some_and(|m| m.after.is_none_or(|after| seq <= after))
    }

    pub(crate) fn active(&self) -> impl Iterator<Item = (&String, &Member)> {
        self.members.iter().filter(|(_, m)| m.after.is_none())
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
    let sign_pub = match authors.get(&op.author) {
        Some(a) => a.sign_pub.clone(),
        None => {
            // The first op carries the key: a member.add of the author itself.
            if op.seq != 1 || op.kind != Kind::MemberAdd {
                return Err("the author's first op is not a member.add of itself".into());
            }
            let body: MemberBody = op.sealed.as_deref().ok_or("its first op has no body").and_then(|s| read_plain_body(s).map_err(|_| "its first op's body doesn't read"))?;
            if body.device != op.author {
                return Err("the author's first op is not a member.add of itself".into());
            }
            body.sign_pub
        }
    };
    let key = unb64(&sign_pub).ok().and_then(|raw| VerifyingKey::from_sec1_bytes(&raw).ok()).ok_or("the author's key doesn't read")?;
    op.verify(&key).map_err(|err| format!("{err:#}"))?;
    if op.author == me {
        // Our own op back from the edge: signed by us, so ours. Our chain is
        // built here, so it is not checked against itself.
        let a = authors.entry(op.author.clone()).or_insert(Author { sign_pub, seq: 0, hash: String::new() });
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
    authors.insert(op.author.clone(), Author { sign_pub, seq: op.seq, hash: op.hash.clone() });
    Ok(true)
}

/// What a member.add or member.remove says, read once. (Rekeys are read by
/// `reach_keys` and `current`.)
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
    keys.iter().filter(|k| k.epoch == epoch).any(|k| ring_mac(&k.key, text) == mac)
}

/// Who the members are, from every member op this member has verified, given
/// the ring keys it holds (a member op counts only with a MAC under one).
pub(crate) fn roster(ops: &[Served], keys: &[RingKey]) -> Roster {
    let read: Vec<(&Served, Said)> = ops.iter().filter_map(|op| said(op).map(|s| (op, s))).collect();
    let founder = read.iter().find_map(|(op, s)| match s {
        Said::Add { body, wraps: true } if op.seq == 1 && body.device == op.author && body.epoch == 0 && mac_ok(keys, 0, &add_mac_text(&body.device, 0), &op.key) => {
            Some((op.author.clone(), body.clone()))
        }
        _ => None,
    });
    let mut roster = Roster::default();
    let Some((founder, body)) = founder else {
        roster.requests = requests(&read, &roster);
        return roster;
    };
    let start = BTreeMap::from([(founder.clone(), Member { name: body.name, sign_pub: body.sign_pub, agree_pub: body.agree_pub, after: None })]);
    roster.founder = Some(founder);
    roster.members = start.clone();
    // A fixed point, so the answer doesn't depend on the order of the ops:
    // each round judges every op against the round before.
    for _ in 0..=read.len() {
        let mut next = start.clone();
        for (op, s) in &read {
            if !roster.counts(&op.author, op.seq) {
                continue;
            }
            match s {
                Said::Add { body, wraps: true } if mac_ok(keys, body.epoch, &add_mac_text(&body.device, body.epoch), &op.key) => {
                    next.entry(body.device.clone()).or_insert_with(|| Member { name: body.name.clone(), sign_pub: body.sign_pub.clone(), agree_pub: body.agree_pub.clone(), after: None });
                }
                _ => {}
            }
        }
        for (op, s) in &read {
            if let Said::Remove(body) = s
                && roster.counts(&op.author, op.seq)
                && keys.iter().any(|k| ring_mac(&k.key, &remove_mac_text(&body.device, body.after)) == op.key)
                && let Some(m) = next.get_mut(&body.device)
            {
                m.after = Some(m.after.map_or(body.after, |a| a.min(body.after)));
            }
        }
        if next == roster.members {
            break;
        }
        roster.members = next;
    }
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

/// The ring keys member `me` can reach from what it holds: a rekey's wrap to
/// it gives the new key, and a rekey's key opens the one before. Each key
/// learns which rekey made it. `unwrap` opens an ECIES wrap with this
/// member's key-agreement key. Returns whether `held` changed.
pub(crate) fn reach_keys(me: &str, ops: &[Served], held: &mut Vec<RingKey>, unwrap: Unwrap) -> bool {
    let mut changed = false;
    let rekeys: Vec<(&Served, RekeyBody)> = ops.iter().filter(|op| op.kind == Kind::Rekey).filter_map(|op| op.sealed.as_deref().and_then(|s| read_plain_body(s).ok()).map(|b| (op, b))).collect();
    loop {
        let mut more = false;
        for (op, body) in &rekeys {
            let rank = op.rank();
            let Some(wrapped) = op.wrapped_key.as_deref().and_then(|w| unb64(w).ok()) else { continue };
            // The new key: a wrap to me, when no key I hold is this rekey's.
            let opens = |k: &RingKey| k.epoch == body.epoch && gcm_open(&k.key, &wrapped, rekey_ad(body.epoch).as_bytes()).is_ok();
            if !held.iter().any(opens)
                && let Some(wrap) = body.wraps.get(me)
                && let Ok(raw) = unb64(wrap).and_then(|w| unwrap(&w))
                && let Ok(key) = <[u8; 32]>::try_from(raw.as_slice())
            {
                held.push(RingKey { epoch: body.epoch, key: Zeroizing::new(key), rank: None });
                more = true;
            }
            // This rekey's key: it learns its rank and opens the key before.
            let Some(this) = held.iter_mut().find(|k| opens(k)) else { continue };
            if this.rank.is_none() {
                this.rank = Some(rank);
                more = true;
            }
            let prev = gcm_open(&this.key, &wrapped, rekey_ad(body.epoch).as_bytes()).expect("it opened above");
            if let Ok(prev) = <[u8; 32]>::try_from(prev.as_slice())
                && body.epoch > 0
                && ring_mac(&prev, &rekey_mac_text(body.epoch)) == op.key
                && !held.iter().any(|k| k.epoch == body.epoch - 1 && *k.key == prev)
            {
                held.push(RingKey { epoch: body.epoch - 1, key: Zeroizing::new(prev), rank: None });
                more = true;
            }
        }
        changed |= more;
        if !more {
            return changed;
        }
    }
}

/// The key new writes use: the newest epoch a member's rekey made (the
/// later rekey when two made the same epoch), or epoch 0.
pub(crate) fn current<'a>(keys: &'a [RingKey], ops: &[Served], roster: &Roster) -> Option<&'a RingKey> {
    let valid: Vec<Rank> = ops.iter().filter(|op| op.kind == Kind::Rekey && roster.counts(&op.author, op.seq)).map(Served::rank).collect();
    keys.iter()
        .filter(|k| k.epoch == 0 || k.rank.as_ref().is_some_and(|r| valid.contains(r)))
        .max_by(|a, b| (a.epoch, a.rank.as_ref()).cmp(&(b.epoch, b.rank.as_ref())))
}

/// The grants to `me` in `ops`: (epoch, the wrapped ring key).
pub(crate) fn grants_to(me: &str, ops: &[Served]) -> Vec<(u32, String)> {
    ops.iter()
        .filter_map(|op| match said(op) {
            Some(Said::Add { body, wraps: true }) if body.device == me => op.wrapped_key.clone().map(|w| (body.epoch, w)),
            _ => None,
        })
        .collect()
}
