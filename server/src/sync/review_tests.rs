//! The security review of #105: each finding as an attack, played against
//! members through the stand-in edge of `tests.rs`.

use super::crypto::{b64, gcm_seal, public_key, random_iv, random_key, unb64};
use super::op::{self, Kind, MemberBody, RekeyBody};
use super::tests::{Edge, member, vault};
use std::collections::BTreeMap;

const A: &str = "d-aaaaaaaaaaaaaaaa";
const B: &str = "d-bbbbbbbbbbbbbbbb";
const C: &str = "d-cccccccccccccccc";
const ROGUE: &str = "d-eeeeeeeeeeeeeeee";

/// A founds; each of `joiners` asks, is trusted (where the code has that
/// step) and approved.
pub(crate) fn ring(dir: &std::path::Path, edge: &mut Edge, joiners: &[&str]) -> (super::member::Member, Vec<super::member::Member>) {
    let mut a = member(dir, A, "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let mut out = Vec::new();
    for id in joiners {
        let mut m = member(dir, id, id);
        edge.sync(&mut m, &mut vault(&[]));
        super::tests::trust(&mut a, &mut m);
        edge.sync(&mut a, &mut av);
        super::tests::approve(&mut a, &mut m);
        edge.push(&mut a);
        edge.sync(&mut m, &mut vault(&[]));
        out.push(m);
    }
    for m in &mut out {
        edge.sync(m, &mut vault(&[]));
    }
    (a, out)
}

/// #1: a paired device that isn't a member pushes a rekey wrapping its own
/// key to a member. The member must not take it: its next write still opens
/// for the other members.
#[test]
fn review_1_a_rekey_from_a_device_that_is_not_a_member_is_never_taken() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    edge.sync(&mut rogue, &mut vault(&[]));
    let a_agree = public_key(&unb64(&a.own_body(0).agree_pub).unwrap()).unwrap();
    let evil = random_key();
    for epoch in [0u32, 1] {
        let wrap = super::tests::wrap_to(&a_agree, epoch, A, &evil);
        let id = super::ledger::ring_id(&evil, epoch);
        let body = RekeyBody { epoch, id: id.clone(), wraps: BTreeMap::from([(A.to_owned(), b64(wrap))]) };
        let back = b64(gcm_seal(&super::crypto::wrap_key(&evil), &*evil, op::rekey_ad(epoch).as_bytes(), random_iv()));
        rogue.write(Kind::Rekey, super::tests::member_mac(&evil, &op::rekey_mac_text(ROGUE, epoch, &id)), u64::from(epoch), op::plain_body(&body), back, 0);
    }
    edge.push(&mut rogue);

    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    av.insert("after/rogue/rekey".into(), "still ours".into());
    a.step(&mut av).unwrap();
    edge.push(&mut a);
    let mut bv = vault(&[]);
    edge.sync(&mut b, &mut bv);
    assert_eq!(bv.get("after/rogue/rekey").map(String::as_str), Some("still ours"), "A's write after the rogue rekey opens for B");
    assert_eq!(a.status(None).unwrap()["epoch"], 0, "A still writes with the ring's key");
}

/// #2: a paired device founds a ring of its own and "approves" a joiner. The
/// joiner seals nothing from its vault for a ring it didn't pin.
#[test]
fn review_2_a_joiner_seals_nothing_for_a_ring_it_did_not_pin() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    edge.sync(&mut a, &mut vault(&[]));
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[("b/secret", "the-joiners-own")]);
    edge.sync(&mut b, &mut bv);
    // The rogue founds before it has seen anything, then grants B.
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    rogue.found_or_request().unwrap();
    edge.push(&mut rogue);
    edge.pull(&mut rogue);
    super::tests::approve_unchecked(&mut rogue, B);
    edge.push(&mut rogue);

    edge.sync(&mut b, &mut bv);
    edge.sync(&mut b, &mut bv);
    let sealed: Vec<_> = edge.ops.iter().filter(|o| o.author == B && o.kind.is_value()).collect();
    assert!(sealed.is_empty(), "B sealed {} op(s) from its vault for a ring it never pinned", sealed.len());
    assert_ne!(b.status(None).unwrap()["role"], "member");
}

/// #3: a member's grant names a device id with keys that aren't that
/// device's own. The device's chain doesn't count as a member's.
#[test]
fn review_3_a_grant_whose_keys_are_not_the_devices_own_makes_no_member() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[]);
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    super::tests::trust(&mut a, &mut b);
    // A grants "B", but with a signing key that isn't B's.
    let (epoch, ring) = a.current_key_for_test();
    let real = b.own_body(epoch);
    let other = b64(super::crypto::raw_public(&p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng).public_key()));
    let body = MemberBody { sign_pub: other, ..real.clone() };
    let wrap = super::tests::wrap_to(&public_key(&unb64(&real.agree_pub).unwrap()).unwrap(), epoch, B, &ring);
    a.write(Kind::MemberAdd, super::tests::member_mac(&ring, &op::add_mac_text(A, &body)), u64::from(epoch), op::plain_body(&body), b64(wrap), 0);
    edge.push(&mut a);
    edge.sync(&mut b, &mut bv);
    bv.insert("from/b".into(), "should not count".into());
    let _ = b.step(&mut bv);
    edge.push(&mut b);
    edge.sync(&mut a, &mut av);
    assert!(!av.contains_key("from/b"), "A applied an op from a chain whose key the grant didn't name");
    assert!(a.status(None).unwrap()["members"].as_array().unwrap().iter().all(|m| m["device"] != B), "B is not a member");
}

/// #4: the edge serves a ring op compacted, to hide it, and a secret's only
/// op compacted. The first breaks its author's chain; the second waits.
#[test]
fn review_4_the_edge_cannot_hide_a_ring_op_or_a_latest_value_by_compacting_it() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, C]);
    let mut c = others.remove(1);
    let mut b = others.remove(0);
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    av.insert("only/once".into(), "v".into());
    a.step(&mut av).unwrap();
    a.remove(B).unwrap();
    edge.push(&mut a);
    let mut bv = vault(&[]);
    bv.insert("b/late".into(), "after its removal".into());
    let _ = b.step(&mut bv);
    edge.push(&mut b);

    // What C is served: the put and the member.remove, compacted.
    let mut served = Edge { ops: edge.ops.clone() };
    for op in &mut served.ops {
        if op.author == A && (op.kind == Kind::MemberRemove || op.kind == Kind::Put) {
            op.sealed = None;
            op.wrapped_key = None;
            op.compacted = true;
        }
    }
    let mut cv = vault(&[]);
    served.sync(&mut c, &mut cv);
    let rejected = &c.state.rejected;
    assert!(rejected.iter().any(|r| r.author == A && r.reason.contains("compacted")), "a compacted ring op is a broken chain: {rejected:?}");
    let status = c.status(None).unwrap();
    assert_ne!(status["waiting_compacted"], serde_json::Value::Null, "the compacted latest value is listed: {status}");
}

/// #5: the same three ops, in two batchings, end with the same value.
#[test]
fn review_5_last_write_wins_does_not_depend_on_arrival_order() {
    use super::apply::{Incoming, VaultMeta};
    use super::op::Rank;
    let w = |hash: &str, base: &str, at: u64, author: &str, value: &str| Incoming {
        hash: hash.into(),
        base: base.into(),
        rank: Rank { at, author: author.into(), seq: 1 },
        version: 1,
        path: "p".into(),
        value: Some(value.into()),
    };
    let o1 = w("o1", "", 100, "d-a", "one");
    let o2 = w("o2", "o1", 50, "d-b", "two");
    let o3 = w("o3", "", 75, "d-c", "three");
    let mut ends = Vec::new();
    for batches in [vec![vec![o1.clone(), o2.clone(), o3.clone()]], vec![vec![o1.clone()], vec![o3.clone(), o2.clone()]], vec![vec![o3.clone()], vec![o1.clone()], vec![o2.clone()]]] {
        let (mut meta, mut keys) = (VaultMeta::default(), std::collections::HashMap::new());
        for batch in batches {
            meta.apply(&mut keys, batch);
        }
        ends.push(keys["p"].clone());
    }
    assert!(ends.iter().all(|e| *e == ends[0]), "converged differently: {ends:?}");
    assert_eq!(ends[0], "one", "the highest-ranked op seen is the value");
}

/// #7 (and N6): two devices found a ring at once. Neither gives its ring up
/// by itself, whatever the times say; both show the conflict with the other
/// ring's fingerprint. Once the person pins A's ring on B, B gives its own up,
/// asks, is approved, and its secrets reach the ring.
#[test]
fn review_7_of_two_founders_neither_falls_back_until_the_person_pins_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut b = member(dir.path(), B, "laptop");
    let (mut av, mut bv) = (vault(&[]), vault(&[("b/own", "from-b")]));
    // Both found before either sees the other; B first.
    b.found_or_request().unwrap();
    a.found_or_request().unwrap();
    b.step(&mut bv).unwrap();
    edge.push(&mut a);
    edge.push(&mut b);
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    for (m, other) in [(&mut a, B), (&mut b, A)] {
        let status = m.status(None).unwrap();
        assert_eq!(status["role"], "member", "{status}");
        assert_eq!(status["ring_conflicts"]["other_founders"][0]["device"], other, "{status}");
        assert!(status["ring_conflicts"]["other_founders"][0]["ring"].is_string());
    }
    let a_ring = a.status(None).unwrap()["ring"].as_str().unwrap().to_owned();
    assert_eq!(b.status(None).unwrap()["ring_conflicts"]["other_founders"][0]["ring"], a_ring.as_str(), "B shows A's ring fingerprint to pin");

    super::tests::trust(&mut a, &mut b);
    edge.sync(&mut b, &mut bv);
    let status = b.status(None).unwrap();
    assert_eq!(status["role"], "requested", "{status}");
    assert_eq!(status["ring_conflicts"]["gave_up_ours_for"], a_ring.as_str());
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &mut b);
    edge.push(&mut a);
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    assert_eq!(av.get("b/own").map(String::as_str), Some("from-b"));
    assert_eq!(a.status(None).unwrap()["ring_conflicts"]["other_founders"].as_array().unwrap().len(), 0, "a founder who joined is no conflict");
}

/// #9: the state file is restored from an older copy, so the next op reuses
/// a seq the edge already has. The queued ops are signed again after the
/// edge's newest, and nothing stays stuck.
#[test]
fn review_9_a_restored_state_file_rebases_its_queued_ops_instead_of_forking() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let old = a.state.clone();
    av.insert("x".into(), "1".into());
    edge.sync(&mut a, &mut av);
    a.state = old;
    av.insert("y".into(), "2".into());
    a.step(&mut av).unwrap();
    edge.push(&mut a);
    assert!(a.state.diverged, "the edge refused it as a fork");
    edge.sync(&mut a, &mut av);
    assert!(a.state.outbox.is_empty(), "sent after rebasing");
    assert_eq!(a.status(None).unwrap()["chain"], "ok");
    let mut bv = vault(&[]);
    edge.sync(&mut b, &mut bv);
    assert_eq!((bv.get("x").map(String::as_str), bv.get("y").map(String::as_str)), (Some("1"), Some("2")));
    // And A's vault knows its own op by the new hash: B's next write on y is
    // a successor, not a conflict.
    bv.insert("y".into(), "3".into());
    edge.sync(&mut b, &mut bv);
    edge.sync(&mut a, &mut av);
    assert_eq!(av["y"], "3");
    assert!(super::apply::VaultMeta::read(&av).conflicts.is_empty(), "{:?}", super::apply::VaultMeta::read(&av).conflicts);
}

/// #15: the agent saves the ops, then crashes before the vault is saved.
/// The same change seen again is the same op, not a second (conflicting) one.
#[test]
fn review_15_a_change_recorded_again_after_a_crash_is_not_a_second_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    av.insert("k".into(), "v".into());
    let unsaved = av.clone();
    a.step(&mut av).unwrap();
    let queued = a.state.outbox.len();
    // The vault on disk is still `unsaved`: the step runs on it again.
    let mut again = unsaved;
    a.step(&mut again).unwrap();
    assert_eq!(a.state.outbox.len(), queued, "no second op for the same change");
    assert_eq!(super::apply::VaultMeta::read(&again).paths["k"].hash, super::apply::VaultMeta::read(&av).paths["k"].hash);
}
