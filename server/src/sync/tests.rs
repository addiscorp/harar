//! Members against each other, through a stand-in for the edge that stores
//! and serves ops as the real one does (edge/test covers the real one), and
//! the test vectors the edge's tests read too.

use super::apply::VaultMeta;
use super::crypto::{b64, member_mac as crypto_member_mac, name_mac, raw_public, seal_value, wrap_ring_with};
use super::ledger;
use super::member::Member;
use super::op::{self, Kind, MemberBody, Op, Served, ValueBody};
use crate::cli::edge::{Paired, StoredKey, SyncConfig};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use p256::ecdsa::SigningKey;
use p256::ecdsa::signature::Signer;
use p256::elliptic_curve::rand_core::OsRng;
use serde_json::{Value, json};
use std::collections::HashMap;

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

    pub(crate) fn pull(&self, m: &mut Member) {
        let mut ops: Vec<Served> = self.ops.iter().filter(|o| o.seq > m.state.next.get(&o.author).copied().unwrap_or(0)).cloned().collect();
        ops.sort_by(|a, b| (&a.author, a.seq).cmp(&(&b.author, b.seq)));
        m.ingest(ops);
        m.pull_complete = true;
        m.rebase();
    }

    /// One sync as the agent does it: pull, apply, push.
    pub(crate) fn sync(&mut self, m: &mut Member, vault: &mut HashMap<String, String>) {
        self.pull(m);
        m.found_or_request().unwrap();
        m.step(vault).unwrap();
        self.push(m);
    }
}

pub(crate) fn vault(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect()
}

// The steps and formats an attack test plays, in one place.

/// The joiner pins the ring by the fingerprint a member shows.
pub(crate) fn trust(existing: &mut Member, joiner: &mut Member) {
    joiner.trust(&existing.ring_fingerprint().unwrap()).unwrap();
}

/// A member approves a joiner the way a person would: with the fingerprint
/// read on the joiner.
pub(crate) fn approve(existing: &mut Member, joiner: &mut Member) {
    existing.approve(&joiner.edge.device.clone(), &joiner.fingerprint()).unwrap();
}

/// A rogue's own ring approving whoever asked, no questions.
pub(crate) fn approve_unchecked(rogue: &mut Member, device: &str) {
    let request = rogue.roster().unwrap().requests[device].clone();
    let fp = super::crypto::device_fingerprint(&super::crypto::unb64(&request.sign_pub).unwrap(), &super::crypto::unb64(&request.agree_pub).unwrap());
    rogue.approve(device, &fp).unwrap();
}

/// A ring key wrapped to a member's key-agreement key.
pub(crate) fn wrap_to(recipient: &p256::PublicKey, epoch: u32, device: &str, key: &[u8; 32]) -> Vec<u8> {
    super::crypto::wrap_ring(recipient, epoch, device, key)
}

/// A member op's `key`: the ring's MAC of its text.
pub(crate) fn member_mac(ring: &[u8; 32], text: &str) -> String {
    super::crypto::member_mac(ring, text)
}

/// A joiner asks, pins the ring and is approved: what a person does on both.
fn join(edge: &mut Edge, existing: &mut Member, ev: &mut HashMap<String, String>, joiner: &mut Member, jv: &mut HashMap<String, String>) {
    edge.sync(joiner, jv);
    trust(existing, joiner);
    edge.sync(existing, ev);
    approve(existing, joiner);
    edge.push(existing);
    edge.sync(joiner, jv);
}

fn role(m: &mut Member) -> String {
    m.status(None).unwrap()["role"].as_str().unwrap().to_owned()
}

// ------------------------------------------------------------------ members

#[test]
fn a_ring_is_founded_joined_on_approval_and_shared_and_the_edge_sees_no_name_or_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), "d-aaaaaaaaaaaaaaaa", "mac");
    let mut a_vault = vault(&[("prod/shop/STRIPE_KEY", "sk_live_from_a"), ("same/everywhere", "x")]);
    edge.sync(&mut a, &mut a_vault);
    assert_eq!(role(&mut a), "member");
    assert_eq!(a.status(None).unwrap()["founder"], "d-aaaaaaaaaaaaaaaa");

    // B has its own secrets: one the same as A's, one that differs, one A lacks.
    let mut b = member(dir.path(), "d-bbbbbbbbbbbbbbbb", "laptop");
    let mut b_vault = vault(&[("same/everywhere", "x"), ("only/b", "b-secret"), ("prod/shop/STRIPE_KEY", "sk_live_from_b")]);
    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "requested");
    assert_eq!(b_vault.len(), 3, "nothing changes before approval");
    assert!(b.state.outbox.is_empty() && b.state.ring.is_empty());

    edge.sync(&mut a, &mut a_vault);
    let requests = a.status(None).unwrap()["requests"].clone();
    assert_eq!(requests[0]["device"], "d-bbbbbbbbbbbbbbbb");
    assert_eq!(requests[0]["fingerprint"], Value::Null, "the approver reads the fingerprint on B, never copies it from its own screen");
    assert_eq!(b.status(None).unwrap()["fingerprint"], b.fingerprint());
    assert!(a.approve("d-cccccccccccccccc", &b.fingerprint()).is_err(), "only a device that asked");
    let wrong = super::crypto::device_fingerprint(b"not", b"b");
    assert!(a.approve("d-bbbbbbbbbbbbbbbb", &wrong).unwrap_err().to_string().contains("fingerprint"), "only with B's own fingerprint");
    a.approve("d-bbbbbbbbbbbbbbbb", &b.fingerprint()).unwrap();
    assert!(a.approve("d-bbbbbbbbbbbbbbbb", &b.fingerprint()).is_err(), "once");
    edge.push(&mut a);

    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "requested", "approved, but B hasn't pinned the ring: it takes nothing");
    assert!(b.trust("not a fingerprint").is_err());
    trust(&mut a, &mut b);
    edge.sync(&mut b, &mut b_vault);
    assert_eq!(role(&mut b), "member");
    assert_eq!(b.status(None).unwrap()["ring"], a.status(None).unwrap()["ring"], "both show one ring fingerprint");
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
    assert_eq!(meta.conflicts[0].kept.device, "d-aaaaaaaaaaaaaaaa");
    assert_eq!(meta.history[0].value.as_deref(), Some("sk_live_from_b"), "B's value is kept in its history");
    assert!(VaultMeta::read(&a_vault).conflicts.is_empty(), "A has nothing to flag");
    assert!(!serde_json::to_string(&edge.ops).unwrap().contains("sk_live_from_b") && edge.ops.iter().filter(|o| o.author == "d-bbbbbbbbbbbbbbbb" && o.kind.is_value()).count() == 1, "B sent only its own secret");

    // The edge holds no path and no value, and no ring key.
    let dump = serde_json::to_string(&edge.ops).unwrap();
    for plain in ["prod/shop/STRIPE_KEY", "sk_live_from_a", "sk_live_from_b", "only/b", "b-secret", "same/everywhere"] {
        assert!(!dump.contains(plain), "the edge holds {plain}");
    }
    // Nor does either member's state file.
    for id in ["d-aaaaaaaaaaaaaaaa", "d-bbbbbbbbbbbbbbbb"] {
        let state = std::fs::read_to_string(dir.path().join(format!("{id}.sync.json")));
        if let Ok(state) = state {
            assert!(!state.contains("STRIPE") && !state.contains("sk_live"), "{id}'s state file");
        }
    }
    a.save().unwrap();
    assert!(!std::fs::read_to_string(dir.path().join("d-aaaaaaaaaaaaaaaa.sync.json")).unwrap().contains("sk_live"));
}

#[test]
fn writes_made_offline_on_two_members_resolve_the_same_on_both_and_both_flag_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), "d-aaaaaaaaaaaaaaaa", "mac"), member(dir.path(), "d-bbbbbbbbbbbbbbbb", "laptop"));
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
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    assert_eq!((av["k"].as_str(), bv["k"].as_str()), ("from b", "from b"), "the later write wins on both");
    for v in [&av, &bv] {
        let meta = VaultMeta::read(v);
        assert_eq!(meta.conflicts.len(), 1);
        assert_eq!(meta.conflicts[0].kept.device, "d-bbbbbbbbbbbbbbbb");
        assert_eq!(meta.conflicts[0].lost.device, "d-aaaaaaaaaaaaaaaa");
        assert_eq!(meta.history[0].value.as_deref(), Some("from a"));
    }
    assert!(a.state.outbox.is_empty() && b.state.outbox.is_empty());
}

#[test]
fn a_removed_member_can_read_nothing_written_after_and_its_later_writes_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), "d-aaaaaaaaaaaaaaaa", "mac"), member(dir.path(), "d-bbbbbbbbbbbbbbbb", "old-laptop"));
    let (mut av, mut bv) = (vault(&[("k", "v1")]), vault(&[]));
    edge.sync(&mut a, &mut av);
    join(&mut edge, &mut a, &mut av, &mut b, &mut bv);
    bv.insert("before".into(), "counts".into());
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    assert_eq!(av["before"], "counts");

    // A removes B and rekeys; then writes with the new key.
    let removed = a.remove("d-bbbbbbbbbbbbbbbb").unwrap().unwrap();
    assert_eq!(removed["epoch"], 1);
    assert!(a.remove("d-bbbbbbbbbbbbbbbb").unwrap().is_none(), "once");
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
    assert!(!av.contains_key("late"), "A rejects B's write after its removal");
    assert!(a.state.rejected.iter().any(|r| r.author == "d-bbbbbbbbbbbbbbbb" && r.reason.contains("removed")));

    // A newcomer approved after the rekey reads everything, old keys included.
    let mut c = member(dir.path(), "d-cccccccccccccccc", "phone");
    let mut cv = vault(&[]);
    join(&mut edge, &mut a, &mut av, &mut c, &mut cv);
    assert_eq!((cv["k"].as_str(), cv["before"].as_str(), cv["after"].as_str()), ("v1", "counts", "new-secret"));
    assert!(!cv.contains_key("late"));
}

#[test]
fn a_chain_that_breaks_is_refused_from_the_break_and_nothing_in_it_applies() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut b) = (member(dir.path(), "d-aaaaaaaaaaaaaaaa", "mac"), member(dir.path(), "d-bbbbbbbbbbbbbbbb", "laptop"));
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    edge.sync(&mut a, &mut av);
    join(&mut edge, &mut a, &mut av, &mut b, &mut bv);
    let good = edge.ops.clone();

    av.insert("k".into(), "v".into());
    a.step(&mut av).unwrap();
    a.sign_all().unwrap();
    let op = a.state.outbox[0].clone();
    let served = Served::from(&op);
    let mut other = served.clone();
    other.sealed = Some(served.wrapped_key.clone().unwrap());
    // Ops A really signed, but that don't continue its chain.
    let key = a.edge.key().unwrap();
    let resign = |seq: u64, prev: &str| Served::from(&Op::sign(&op.author, seq, prev, op.kind, &op.key, op.version, op.sealed.clone(), op.wrapped_key.clone(), op.at, &|m| key.sign(m)).unwrap());
    let cases: Vec<(&str, Served, &str)> = vec![
        ("tampered ciphertext", other, "ciphertext is not what its hashes say"),
        ("another op's signature", Served { sig: good[0].sig.clone(), ..served.clone() }, "not signed by its author"),
        ("wrong prev", resign(op.seq, &"0".repeat(64)), "prev is not the hash"),
        ("skips a seq", resign(op.seq + 1, &op.prev), "seq"),
        ("hash lies", Served { hash: "f".repeat(64), ..served.clone() }, "hash is not the hash"),
    ];
    for (what, bad, reason) in cases {
        let probe_dir = tempfile::tempdir().unwrap();
        let mut probe = member(probe_dir.path(), "d-bbbbbbbbbbbbbbbb", "laptop");
        probe.state = b.state.clone();
        let before = probe.state.rejected.len();
        probe.ingest(vec![bad, served.clone()]);
        assert_eq!(probe.state.rejected.len(), before + 1, "{what}: rejected");
        let got = &probe.state.rejected.last().unwrap().reason;
        assert!(got.contains(reason), "{what}: rejected for {got:?}");
        assert!(probe.state.pending.is_empty(), "{what}: nothing after the break is taken either");
        assert_eq!(probe.state.next.get("d-aaaaaaaaaaaaaaaa"), b.state.next.get("d-aaaaaaaaaaaaaaaa"), "{what}: the cursor stays");
    }
    // The real op, alone, is taken.
    b.ingest(vec![served]);
    let mut bv2 = bv.clone();
    b.step(&mut bv2).unwrap();
    assert_eq!(bv2["k"], "v");
}

#[test]
fn an_author_must_start_with_its_own_member_add_and_a_ring_it_cant_mac_is_not_ours() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), "d-aaaaaaaaaaaaaaaa", "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    // A device that founds its own ring, with its own key, on the same edge:
    // its self-grant can't be MAC'd with our ring key, so it isn't a member.
    let mut rogue = member(dir.path(), "d-eeeeeeeeeeeeeeee", "rogue");
    rogue.state.authors.clear();
    rogue.found_or_request().unwrap();
    // found_or_request founded a ring of its own (it saw nothing); its ops reach A.
    rogue.state.outbox.iter().for_each(|o| edge.ops.push(Served::from(o)));
    edge.sync(&mut a, &mut av);
    let status = a.status(None).unwrap();
    assert_eq!(status["members"].as_array().unwrap().len(), 1, "{status}");
    assert_eq!(status["founder"], "d-aaaaaaaaaaaaaaaa");
}

// ------------------------------------------------------------------ vectors

/// edge/test/sync-vectors.json: a member's chain built from fixed keys,
/// fixed IVs and RFC 6979 signatures, so it comes out the same every time.
/// This test builds it here; edge/test/edge.test.ts checks the same file
/// against the edge and its own reading of docs/edge.md.
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

    let body = MemberBody { device: author.into(), name: "vector".into(), sign_pub: b64(&sign_pub), agree_pub: b64(&agree_pub), epoch: 0, removal: String::new() };
    let wrap = wrap_ring_with(&agree.public_key(), 0, author, &ring, &ephemeral);
    let founder = Op::sign(author, 1, &prev, Kind::MemberAdd, &crypto_member_mac(&ring, &op::add_mac_text(author, &body)), 0, op::plain_body(&body), b64(&wrap), at, &signer).unwrap();
    push(founder, Value::Null, &mut prev);

    let path = "prod/shop/STRIPE_KEY";
    let key = name_mac(&ring, path);
    let writes: [(Kind, u64, Option<&str>, u8); 3] = [(Kind::Put, 1, Some("sk_live_vector"), 5), (Kind::Rotate, 2, Some("sk_live_rotated"), 6), (Kind::Delete, 3, None, 7)];
    for (i, (kind, version, value, n)) in writes.into_iter().enumerate() {
        let body = ValueBody { path: path.into(), value: value.map(Into::into), base: if i == 0 { String::new() } else { prev.clone() } };
        let plain = serde_json::to_vec(&body).unwrap();
        let (sealed, wrapped) = seal_value(&ring, &key, version, &plain, Some(([n; 32], [n; 12], [n + 10; 12])));
        let op = Op::sign(author, i as u64 + 2, &prev, kind, &key, version, sealed, wrapped, at + 1000 * (i as u64 + 1), &signer).unwrap();
        push(op, serde_json::to_value(&body).unwrap(), &mut prev);
    }
    json!({
        "about": "A ring member's chain, made by server/src/sync (Rust) from fixed keys and IVs. Both harar's tests and the edge's read it: the canonical encoding, hashes, signatures and seals must agree (docs/edge.md §5a, §5b). The ring's subkeys are HKDF-SHA256(salt harar-ring-v1, info harar-ring-name | harar-ring-member | harar-ring-wrap). Test keys only.",
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
        "ops": ops,
    })
}

#[test]
fn the_test_vectors_are_what_this_code_makes_and_they_verify_and_open() {
    let file = concat!(env!("CARGO_MANIFEST_DIR"), "/../edge/test/sync-vectors.json");
    let built = build_vectors();
    let text = std::fs::read_to_string(file).unwrap_or_default();
    let stored: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    assert!(stored == built, "edge/test/sync-vectors.json differs from what this code makes:\n{}", serde_json::to_string_pretty(&built).unwrap());

    // Read back as a member reads ops from the edge: chain, signatures and seals.
    let ops: Vec<Served> = built["ops"].as_array().unwrap().iter().map(|v| Served::from(&serde_json::from_value::<Op>(v["op"].clone()).unwrap())).collect();
    let mut authors = Default::default();
    let verified = ledger::verify_chains(&mut authors, "d-someone-else", ops.clone());
    assert_eq!((verified.good.len(), verified.rejected.len()), (4, 0), "{:?}", verified.rejected);
    let ring = [4u8; 32];
    for (v, op) in built["ops"].as_array().unwrap().iter().zip(&ops).skip(1) {
        let plain = super::crypto::open_value(&ring, &op.key, op.version, op.sealed.as_deref().unwrap(), op.wrapped_key.as_deref().unwrap()).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&plain).unwrap(), v["opens"]);
    }
    let agree = p256::SecretKey::from_slice(&[2u8; 32]).unwrap();
    let wrap = super::crypto::unb64(ops[0].wrapped_key.as_deref().unwrap()).unwrap();
    let plain = super::crypto::ecies_open(&agree, &wrap).unwrap();
    assert_eq!(*super::crypto::unwrapped_ring(&plain, 0, "d-0123456789abcdef").unwrap(), ring);
    // A compacted op (no ciphertext, its hashes kept) still verifies.
    let mut compacted = ops.clone();
    compacted[1].sealed = None;
    compacted[1].wrapped_key = None;
    compacted[1].compacted = true;
    let mut authors = Default::default();
    let verified = ledger::verify_chains(&mut authors, "d-someone-else", compacted);
    assert_eq!((verified.good.len(), verified.rejected.len()), (4, 0));
}
