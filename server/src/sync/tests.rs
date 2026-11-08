//! Members against each other, through a stand-in for the edge that stores
//! and serves ops as the real one does (edge/test covers the real one), and
//! the test vectors the edge's tests read too.

use super::apply::VaultMeta;
use super::crypto::{b64, name_mac, raw_public, seal_value, wrap_ring_with};
use super::ledger;
use super::member::Member;
use super::op::{self, Entry, EntryType, Kind, MemberKeys, Op, Served, ValueBody};
use crate::cli::edge::{Paired, StoredKey, SyncConfig};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap};

pub(crate) const A: &str = "d-aaaaaaaaaaaaaaaa";
pub(crate) const B: &str = "d-bbbbbbbbbbbbbbbb";
pub(crate) const C: &str = "d-cccccccccccccccc";

// ------------------------------------------------------------------ harness

/// A member with file keys in its own folder, as `harar edge sync on` sets
/// one up with --file-key.
pub(crate) fn member(dir: &std::path::Path, id: &str, name: &str) -> Member {
    let sign = dir.join(format!("{id}.p256"));
    let agree = dir.join(format!("{id}.agree.p256"));
    std::fs::write(&sign, STANDARD.encode(SigningKey::random(&mut OsRng).to_bytes())).unwrap();
    std::fs::write(&agree, STANDARD.encode(p256::SecretKey::random(&mut OsRng).to_bytes())).unwrap();
    let edge = Paired {
        url: "http://127.0.0.1:1".into(),
        device: id.into(),
        name: name.into(),
        key: StoredKey::File { path: sign },
        edge_key: None,
        sync: Some(SyncConfig { on: true, agreement: StoredKey::File { path: agree } }),
    };
    Member::load_at(edge, dir.join(format!("{id}.sync.json"))).unwrap()
}

/// Stores and serves ops as the edge does: each author's ops in seq order,
/// as sent, with their hashes.
#[derive(Default)]
pub(crate) struct Edge {
    pub ops: Vec<Served>,
}

impl Edge {
    /// Signs the member's queued ops and stores them, refusing as the edge
    /// does an op that doesn't continue its author's chain.
    pub(crate) fn push(&mut self, m: &mut Member) {
        m.sign_all().unwrap();
        let ready = m.ready();
        for op in &ready {
            let last = self.ops.iter().filter(|o| o.author == op.author).map(|o| (o.seq, o.hash.clone())).max();
            let (seq, prev) = last.unwrap_or((0, String::new()));
            if (op.seq, op.prev.clone()) != (seq + 1, prev) {
                let refused = anyhow::anyhow!("refused (409 wrong_seq)");
                m.sent(&[], Some(&refused));
                return;
            }
            self.ops.push(Served::from(op));
        }
        m.sent(&ready, None);
    }

    /// Serves everything after the member's cursor (`since`), as the edge does.
    pub(crate) fn pull(&self, m: &mut Member) {
        let since = m.since();
        let mut ops: Vec<Served> = self.ops.iter().filter(|o| o.seq > since.get(&o.author).copied().unwrap_or(0)).cloned().collect();
        ops.sort_by(|a, b| (&a.author, a.seq).cmp(&(&b.author, b.seq)));
        m.ingest(ops);
        m.pull_complete = true;
        m.rebase();
    }

    /// One sync as the agent does it: pull, apply, save, push.
    pub(crate) fn sync(&mut self, m: &mut Member, vault: &mut HashMap<String, String>) {
        self.pull(m);
        m.found_or_request().unwrap();
        let stepped = m.step(vault).unwrap();
        m.applied(&stepped.applied);
        self.push(m);
    }
}

pub(crate) fn vault(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
}

/// Syncs every member `rounds` times, in order.
pub(crate) fn settle(edge: &mut Edge, members: &mut [(&mut Member, &mut HashMap<String, String>)], rounds: usize) {
    for _ in 0..rounds {
        for (m, v) in members.iter_mut() {
            edge.sync(m, v);
        }
    }
}

/// The joiner pins the ring by the fingerprint a member shows.
pub(crate) fn trust(existing: &Member, joiner: &mut Member) {
    joiner.trust(&existing.ring_fingerprint().unwrap()).unwrap();
}

/// The authority approves a joiner the way a person would: with the
/// fingerprint read on the joiner.
pub(crate) fn approve(authority: &mut Member, joiner: &Member) {
    authority.approve(&joiner.edge.device.clone(), &joiner.fingerprint()).unwrap();
}

/// A joiner asks, pins the ring and is approved: what a person does on both.
pub(crate) fn join(edge: &mut Edge, authority: &mut Member, av: &mut HashMap<String, String>, joiner: &mut Member, jv: &mut HashMap<String, String>) {
    edge.sync(joiner, jv);
    trust(authority, joiner);
    edge.sync(authority, av);
    approve(authority, joiner);
    edge.push(authority);
    edge.sync(joiner, jv);
}

/// A founds a ring and each of `joiners` joins it.
pub(crate) fn ring(dir: &std::path::Path, edge: &mut Edge, joiners: &[&str]) -> (Member, Vec<Member>) {
    let mut a = member(dir, A, "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let mut out = Vec::new();
    for id in joiners {
        let mut m = member(dir, id, id);
        join(edge, &mut a, &mut av, &mut m, &mut vault(&[]));
        out.push(m);
    }
    for m in &mut out {
        edge.sync(m, &mut vault(&[]));
    }
    (a, out)
}

pub(crate) fn role(m: &mut Member) -> String {
    m.status(None).unwrap()["role"].as_str().unwrap().to_owned()
}

// ------------------------------------------------------------------ members

#[test]
fn a_ring_is_founded_joined_on_approval_and_shared_and_the_edge_sees_no_name_or_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut a_vault = vault(&[("prod/shop/STRIPE_KEY", "sk_live_from_a"), ("same/everywhere", "x")]);
    edge.sync(&mut a, &mut a_vault);
    assert_eq!(role(&mut a), "authority");
    assert_eq!(a.status(None).unwrap()["founder"], A);

    // B has its own secrets: one the same as A's, one that differs, one A lacks.
    let mut b = member(dir.path(), B, "laptop");
    let mut b_vault = vault(&[("same/everywhere", "x"), ("only/b", "b-secret"), ("prod/shop/STRIPE_KEY", "sk_live_from_b")]);
    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "requested");
    assert_eq!(b_vault.len(), 3, "nothing changes before approval");
    assert!(b.state.ring.is_empty());

    edge.sync(&mut a, &mut a_vault);
    let requests = a.status(None).unwrap()["requests"].clone();
    assert_eq!(requests[0]["device"], B);
    assert_eq!(requests[0]["fingerprint"], Value::Null, "the approver reads the fingerprint on B, never copies it from its own screen");
    assert_eq!(b.status(None).unwrap()["fingerprint"], b.fingerprint());
    assert!(a.approve(C, &b.fingerprint()).is_err(), "only a device that asked");
    let wrong = super::crypto::device_fingerprint(b"not", b"b");
    assert!(a.approve(B, &wrong).unwrap_err().to_string().contains("fingerprint"), "only with B's own fingerprint");
    a.approve(B, &b.fingerprint()).unwrap();
    assert!(a.approve(B, &b.fingerprint()).is_err(), "once");
    edge.push(&mut a);

    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "requested", "approved, but B hasn't pinned the ring: it follows no log");
    assert!(b.trust("not a fingerprint").is_err());
    trust(&a, &mut b);
    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "member");
    assert_eq!(b.status(None).unwrap()["ring"], a.status(None).unwrap()["ring"], "both show one ring fingerprint");
    assert_eq!(b.status(None).unwrap()["authority"], A);
    edge.sync(&mut a, &mut a_vault);
    edge.sync(&mut b, &mut b_vault);
    // On joining, the ring's value wins: B's different STRIPE_KEY goes to
    // B's history, flagged on B; A never sees it. The same value is adopted
    // without a conflict, and B's own secret reaches A.
    for (name, v) in [("a", &a_vault), ("b", &b_vault)] {
        assert_eq!(v.get("prod/shop/STRIPE_KEY").map(String::as_str), Some("sk_live_from_a"), "{name}");
        assert_eq!(v.get("only/b").map(String::as_str), Some("b-secret"), "{name}");
        assert_eq!(v.get("same/everywhere").map(String::as_str), Some("x"), "{name}");
    }
    let meta = VaultMeta::read(&b_vault);
    assert_eq!(meta.conflicts.len(), 1, "B flags the one it gave up");
    assert_eq!(meta.conflicts[0].path, "prod/shop/STRIPE_KEY");
    assert_eq!(meta.conflicts[0].kept.device, A);
    assert_eq!(meta.history[0].value.as_deref(), Some("sk_live_from_b"), "B's value is kept in its history");
    assert!(VaultMeta::read(&a_vault).conflicts.is_empty(), "A has nothing to flag");
    assert_eq!(edge.ops.iter().filter(|o| o.author == B && o.kind.is_value()).count(), 1, "B sent only its own secret");

    // The edge holds no path and no value.
    let dump = serde_json::to_string(&edge.ops).unwrap();
    for plain in ["prod/shop/STRIPE_KEY", "sk_live_from_a", "sk_live_from_b", "only/b", "b-secret", "same/everywhere"] {
        assert!(!dump.contains(plain), "the edge holds {plain}");
    }
    // Nor does either member's state file.
    a.save().unwrap();
    b.save().unwrap();
    for id in [A, B] {
        let state = std::fs::read_to_string(dir.path().join(format!("{id}.sync.json"))).unwrap();
        assert!(!state.contains("STRIPE") && !state.contains("sk_live"), "{id}'s state file");
    }
}

#[test]
fn writes_made_offline_on_two_members_resolve_the_same_on_both_and_both_flag_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), A, "mac"), member(dir.path(), B, "laptop"));
    let (mut av, mut bv) = (vault(&[("k", "v1")]), vault(&[]));
    edge.sync(&mut a, &mut av);
    join(&mut edge, &mut a, &mut av, &mut b, &mut bv);
    assert_eq!(bv["k"], "v1");

    // Offline: each changes k, records it (as the agent does after a put),
    // and neither can push yet.
    av.insert("k".into(), "from a".into());
    a.step(&mut av).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    bv.insert("k".into(), "from b".into());
    b.step(&mut bv).unwrap();
    // Back online, in any order.
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!((av["k"].as_str(), bv["k"].as_str()), ("from b", "from b"), "the later write wins on both");
    for v in [&av, &bv] {
        let meta = VaultMeta::read(v);
        assert_eq!(meta.conflicts.len(), 1);
        assert_eq!(meta.conflicts[0].kept.device, B);
        assert_eq!(meta.conflicts[0].lost.device, A);
        assert_eq!(meta.history[0].value.as_deref(), Some("from a"));
    }
    assert!(a.state.outbox.is_empty() && b.state.outbox.is_empty());
}

#[test]
fn the_authority_removes_a_member_in_one_entry_and_it_can_read_nothing_written_after() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), A, "mac"), member(dir.path(), B, "old-laptop"));
    let (mut av, mut bv) = (vault(&[("k", "v1")]), vault(&[]));
    edge.sync(&mut a, &mut av);
    join(&mut edge, &mut a, &mut av, &mut b, &mut bv);
    bv.insert("before".into(), "counts".into());
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    assert_eq!(av["before"], "counts");

    let removed = a.remove(B).unwrap().unwrap();
    assert_eq!(removed["epoch"], 1);
    assert!(a.remove(B).unwrap().is_none(), "once");
    let entries: Vec<Entry> = a.state.member_ops.iter().filter_map(ledger::entry_of).collect();
    let remove = entries.iter().find(|e| e.what == EntryType::Remove).unwrap();
    assert!(!remove.wraps.contains_key(B) && remove.wraps.contains_key(A), "the new key goes to those who remain, in the same entry");
    av.insert("after".into(), "new-secret".into());
    a.step(&mut av).unwrap();
    edge.push(&mut a);
    assert_eq!(a.status(None).unwrap()["epoch"], 1, "new writes use the new key");

    // B wrote meanwhile, not knowing.
    bv.insert("late".into(), "from-b".into());
    b.step(&mut bv).unwrap();
    edge.push(&mut b);
    edge.sync(&mut b, &mut bv);
    assert_eq!(role(&mut b), "removed");
    assert!(!bv.contains_key("after"), "B can't open what A wrote after");
    edge.sync(&mut a, &mut av);
    assert!(!av.contains_key("late"), "A refuses B's write after its removal");
    assert!(a.state.rejected.iter().any(|r| r.author == B && r.reason.contains("removed")), "{:?}", a.state.rejected);

    // A newcomer approved after the rekey reads everything, old keys included.
    let mut c = member(dir.path(), C, "phone");
    let mut cv = vault(&[]);
    join(&mut edge, &mut a, &mut av, &mut c, &mut cv);
    assert_eq!((cv["k"].as_str(), cv["before"].as_str(), cv["after"].as_str()), ("v1", "counts", "new-secret"));
    assert!(!cv.contains_key("late"));
}

#[test]
fn only_the_authority_changes_membership_and_it_can_hand_that_over() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    let mut c = member(dir.path(), C, "phone");
    let mut cv = vault(&[]);
    edge.sync(&mut c, &mut cv);
    trust(&a, &mut c);
    edge.sync(&mut b, &mut bv);
    assert!(b.approve(C, &c.fingerprint()).unwrap_err().to_string().contains("only the ring's authority"));
    assert!(b.remove(A).unwrap_err().to_string().contains("only the ring's authority"));
    assert!(b.transfer(B).is_err());

    a.transfer(B).unwrap();
    edge.push(&mut a);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    assert_eq!(role(&mut b), "authority");
    assert_eq!(role(&mut a), "member");
    assert!(a.approve(C, &c.fingerprint()).unwrap_err().to_string().contains("only the ring's authority"));
    approve(&mut b, &c);
    edge.push(&mut b);
    edge.sync(&mut c, &mut cv);
    assert_eq!(role(&mut c), "member");
    assert_eq!(c.status(None).unwrap()["authority"], B, "C follows the transfer through the log");
}

#[test]
fn a_chain_that_breaks_is_refused_from_the_break_and_nothing_in_it_applies() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), A, "mac"), member(dir.path(), B, "laptop"));
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    edge.sync(&mut a, &mut av);
    join(&mut edge, &mut a, &mut av, &mut b, &mut bv);

    av.insert("k".into(), "v".into());
    a.step(&mut av).unwrap();
    a.sign_all().unwrap();
    let op = a.state.outbox[0].clone();
    let served = Served::from(&op);
    let mut other = served.clone();
    other.sealed = Some(served.wrapped_key.clone().unwrap());
    let key = a.edge.key().unwrap();
    let resign = |seq: u64, prev: &str| Served::from(&Op::sign(&op.author, seq, prev, op.kind, &op.key, op.version, op.sealed.clone(), op.wrapped_key.clone(), op.at, &|m| key.sign(m)).unwrap());
    let cases: Vec<(&str, Served, &str)> = vec![
        ("tampered ciphertext", other, "ciphertext is not what its hashes say"),
        ("wrong prev", resign(op.seq, &"0".repeat(64)), "prev is not the hash"),
        ("skips a seq", resign(op.seq + 1, &op.prev), "seq"),
        ("hash lies", Served { hash: "f".repeat(64), ..served.clone() }, "hash is not the hash"),
    ];
    for (what, bad, reason) in cases {
        let probe_dir = tempfile::tempdir().unwrap();
        let mut probe = member(probe_dir.path(), B, "laptop");
        probe.state = b.state.clone();
        let before = probe.state.rejected.len();
        probe.ingest(vec![bad, served.clone()]);
        assert_eq!(probe.state.rejected.len(), before + 1, "{what}: rejected");
        let got = &probe.state.rejected.last().unwrap().reason;
        assert!(got.contains(reason), "{what}: rejected for {got:?}");
        assert!(probe.state.pending.is_empty(), "{what}: nothing after the break is taken either");
        assert_eq!(probe.state.next.get(A), b.state.next.get(A), "{what}: the cursor stays");
    }
    // An op that links but isn't signed by the key the log gives A: forged,
    // and A's chain goes back to before it.
    let probe_dir = tempfile::tempdir().unwrap();
    let mut probe = member(probe_dir.path(), B, "laptop");
    probe.state = b.state.clone();
    probe.ingest(vec![Served { sig: edge.ops[0].sig.clone(), ..served.clone() }]);
    assert!(probe.state.forged.iter().any(|f| f.author == A), "{:?}", probe.state.forged);
    assert_eq!(probe.state.next.get(A), b.state.next.get(A), "pulled again");
    // The real op, alone, is taken.
    b.ingest(vec![served]);
    let mut bv2 = bv.clone();
    b.step(&mut bv2).unwrap();
    assert_eq!(bv2["k"], "v");
}

// ------------------------------------------------------------------ vectors

/// edge/test/sync-vectors.json: a founder's chain built from fixed keys,
/// fixed IVs and RFC 6979 signatures, so it comes out the same every time:
/// the `found` entry, then a put, a rotate and a delete under its head. This
/// test builds it here; edge/test/edge.test.ts checks the same file against
/// the edge and its own reading of docs/edge.md.
fn build_vectors() -> Value {
    let sign = SigningKey::from_slice(&[1u8; 32]).unwrap();
    let agree = p256::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let ephemeral = p256::SecretKey::from_slice(&[3u8; 32]).unwrap();
    let ring = [4u8; 32];
    let author = "d-0123456789abcdef";
    let sign_pub = sign.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    let agree_pub = raw_public(&agree.public_key());
    let signer = |m: &[u8]| -> anyhow::Result<[u8; 64]> {
        let sig: p256::ecdsa::Signature = sign.sign(m);
        Ok(sig.to_bytes().into())
    };
    let at = 1_762_603_200_000u64;
    let mut ops: Vec<Value> = Vec::new();
    let mut prev = String::new();
    let mut push = |op: Op, opens: Value, prev: &mut String| {
        *prev = op.hash();
        ops.push(json!({ "op": op, "canonical": op.canonical(), "hash": op.hash(), "opens": opens }));
    };

    let wrap = wrap_ring_with(&agree.public_key(), 0, author, &ring, &ephemeral);
    let found = Entry {
        what: EntryType::Found,
        n: 0,
        prev: String::new(),
        epoch: 0,
        id: ledger::ring_id(&ring, 0),
        member: Some(MemberKeys { device: author.into(), name: "vector".into(), sign_pub: b64(&sign_pub), agree_pub: b64(&agree_pub) }),
        removed: Vec::new(),
        authority: None,
        wraps: BTreeMap::from([(author.to_owned(), b64(&wrap))]),
    };
    let sealed = op::plain_body(&found);
    let head = op::head_of(&sealed);
    let founder = Op::sign(author, 1, &prev, Kind::MemberAdd, &op::entry_key(&head), 0, sealed, String::new(), at, &signer).unwrap();
    push(founder, Value::Null, &mut prev);

    let path = "prod/shop/STRIPE_KEY";
    let key = name_mac(&ring, path);
    let writes: [(Kind, u64, Option<&str>, u8); 3] = [(Kind::Put, 1, Some("sk_live_vector"), 5), (Kind::Rotate, 2, Some("sk_live_rotated"), 6), (Kind::Delete, 3, None, 7)];
    let mut base = String::new();
    for (i, (kind, version, value, n)) in writes.into_iter().enumerate() {
        let body = ValueBody { path: path.into(), value: value.map(Into::into), base: base.clone(), head: head.clone() };
        let plain = serde_json::to_vec(&body).unwrap();
        let (sealed, wrapped) = seal_value(&ring, &key, version, &plain, Some(([n; 32], [n; 12], [n + 10; 12])));
        let op = Op::sign(author, i as u64 + 2, &prev, kind, &key, version, sealed, wrapped, at + 1000 * (i as u64 + 1), &signer).unwrap();
        base = op.hash();
        push(op, serde_json::to_value(&body).unwrap(), &mut prev);
    }
    json!({
        "about": "A ring founder's chain, made by server/src/sync (Rust) from fixed keys and IVs: the found entry of the membership log, then a put, a rotate and a delete written under its head. Both harar's tests and the edge's read it: the canonical encoding, hashes, signatures and seals must agree (docs/edge.md §5a, §5b). The ring's subkeys are HKDF-SHA256(salt harar-ring-v1, info harar-ring-name | harar-ring-member | harar-ring-wrap). Test keys only.",
        "device": {
            "id": author,
            "sign_d": b64([1u8; 32]),
            "sign_pub": b64(&sign_pub),
            "agree_d": b64([2u8; 32]),
            "agree_pub": b64(&agree_pub),
            "fingerprint": super::crypto::device_fingerprint(&sign_pub, &agree_pub),
            "ring_fingerprint": super::crypto::ring_fingerprint(&sign_pub, &agree_pub),
        },
        "ring": b64(ring),
        "head": head,
        "ops": ops,
    })
}

#[test]
fn the_test_vectors_are_what_this_code_makes_and_they_follow_verify_and_open() {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../edge/test/sync-vectors.json");
    let built = build_vectors();
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let stored: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert!(stored == built, "edge/test/sync-vectors.json differs from what this code makes:\n{}", serde_json::to_string_pretty(&built).unwrap());

    // Read back as a member reads ops from the edge: chains, the log, seals.
    let ops: Vec<Served> = built["ops"].as_array().unwrap().iter().map(|v| Served::from(&serde_json::from_value::<Op>(v["op"].clone()).unwrap())).collect();
    let mut authors = Default::default();
    let linked = ledger::link_chains(&mut authors, "d-someone-else", ops.clone());
    assert_eq!((linked.good.len(), linked.rejected.len()), (4, 0), "{:?}", linked.rejected);
    let log = ledger::follow(&ops[..1], built["device"]["ring_fingerprint"].as_str(), "d-someone-else");
    assert_eq!(log.founder(), Some("d-0123456789abcdef"));
    assert_eq!(log.head(), built["head"].as_str());
    let ring = [4u8; 32];
    for (v, op) in built["ops"].as_array().unwrap().iter().zip(&ops).skip(1) {
        assert_eq!(log.counts(op, 0), Ok(()));
        let plain = super::crypto::open_value(&ring, &op.key, op.version, op.sealed.as_deref().unwrap(), op.wrapped_key.as_deref().unwrap()).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), v["opens"]);
    }
    let agree = p256::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let wrap = super::crypto::unb64(&log.entries[0].entry.wraps["d-0123456789abcdef"]).unwrap();
    let plain = super::crypto::ecies_open(&agree, &wrap).unwrap();
    assert_eq!(*super::crypto::unwrapped_ring(&plain, 0, "d-0123456789abcdef").unwrap(), ring);
    // A compacted op (no ciphertext, its hashes kept) still links.
    let mut compacted = ops.clone();
    compacted[1].sealed = None;
    compacted[1].wrapped_key = None;
    compacted[1].compacted = true;
    let mut authors = Default::default();
    let linked = ledger::link_chains(&mut authors, "d-someone-else", compacted);
    assert_eq!((linked.good.len(), linked.rejected.len()), (4, 0));
}
