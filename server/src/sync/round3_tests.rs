//! The third review of #105, each finding as its scenario, written against
//! the membership model at cae0c3f (they are the fail-before evidence).

use super::crypto::b64;
use super::member::Member;
use super::op::{self, Kind, MemberBody, Served};
use super::review_tests::ring;
use super::tests::{Edge, member, vault};
use std::collections::HashMap;

const A: &str = "d-aaaaaaaaaaaaaaaa";
const B: &str = "d-bbbbbbbbbbbbbbbb";
const D: &str = "d-dddddddddddddddd";
const E: &str = "d-eeeeeeeeeeeeeeee";
const J: &str = "d-3333333333333333";
const R: &str = "d-4444444444444444";
const X: &str = "d-1111111111111111";
const JUNK: &str = "d-0000000000000001";

fn settle(edge: &mut Edge, members: &mut [(&mut Member, &mut HashMap<String, String>)], rounds: usize) {
    for _ in 0..rounds {
        for (m, v) in members.iter_mut() {
            edge.sync(m, v);
        }
    }
}

/// C1: A removes R; R, before it sees that, removes A. A stays, R is out,
/// and what R writes after doesn't count anywhere.
#[test]
fn round3_c1_a_removed_member_cannot_remove_its_remover() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, R]);
    let mut r = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut rv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut r, &mut rv)], 1);
    a.remove(R).unwrap();
    let _ = r.remove(A);
    edge.push(&mut a);
    edge.push(&mut r);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 3);
    rv.insert("r/after".into(), "should not count".into());
    let _ = r.step(&mut rv);
    edge.push(&mut r);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 3);
    let status = b.status(None).unwrap();
    let removed = |id: &str| status["members"].as_array().unwrap().iter().find(|m| m["device"] == id).map(|m| !m["removed_after"].is_null());
    assert_eq!(removed(A), Some(false), "A is still an active member: {status}");
    assert_eq!(removed(R), Some(true), "R is out: {status}");
    assert!(!bv.contains_key("r/after"), "R's write after its removal counted");
}

/// H1: B is served the ring without A's removal of X for a while. Nothing
/// gives X a key made after its removal, and the ring stops rekeying.
#[test]
fn round3_h1_a_member_behind_a_removal_never_regrants_the_removed_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, X]);
    let mut x = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut xv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut x, &mut xv)], 1);
    let before = edge.ops.len();
    a.remove(X).unwrap();
    edge.push(&mut a);
    // B sees everything but A's removal of X (and what follows it in A's chain).
    let removal_seq = edge.ops[before..].iter().find(|o| o.kind == Kind::MemberRemove).unwrap().seq;
    for _ in 0..3 {
        let mut view = Edge { ops: edge.ops.iter().filter(|o| !(o.author == A && o.seq >= removal_seq)).cloned().collect() };
        let n = view.ops.len();
        view.sync(&mut b, &mut bv);
        edge.ops.extend(view.ops.drain(n..));
        edge.sync(&mut a, &mut av);
    }
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 4);
    let rekeys = edge.ops.iter().filter(|o| o.kind == Kind::Rekey).count();
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 4);
    assert_eq!(edge.ops.iter().filter(|o| o.kind == Kind::Rekey).count(), rekeys, "the ring keeps rekeying");
    let to_x = edge.ops[before..]
        .iter()
        .filter(|o| o.author != X && o.sealed.as_deref().is_some_and(|s| super::crypto::unb64(s).ok().is_some_and(|b| String::from_utf8_lossy(&b).contains(X))))
        .filter(|o| o.kind == Kind::MemberAdd)
        .count();
    assert_eq!(to_x, 0, "{to_x} grant(s) to X after its removal");
}

/// H2: the edge serves a fresh joiner a forged first op for member D, with
/// keys that aren't D's. D is still a member there, and its writes count.
#[test]
fn round3_h2_a_forged_first_op_never_ejects_a_member() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[D]);
    let mut d = others.remove(0);
    let (mut av, mut dv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut d, &mut dv)], 1);
    // The forgery: D's first op, signed by a key that isn't D's.
    let attacker = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let body = MemberBody { sign_pub: b64(attacker.verifying_key().to_encoded_point(false).as_bytes()), ..d.own_body(0) };
    let forged = Served::from(&op::Op::sign(D, 1, "", Kind::MemberAdd, &op::request_key(D), 0, op::plain_body(&body), String::new(), 1, &|m| {
        let s: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(&attacker, m);
        Ok(s.to_bytes().into())
    }).unwrap());
    let view_for_j = |edge: &Edge| Edge { ops: edge.ops.iter().filter(|o| o.author != D).cloned().chain(std::iter::once(forged.clone())).collect() };
    let mut j = member(dir.path(), J, "new");
    let mut jv = vault(&[]);
    let mut view = view_for_j(&edge);
    let n = view.ops.len();
    view.sync(&mut j, &mut jv);
    edge.ops.extend(view.ops.drain(n..));
    super::tests::trust(&mut a, &mut j);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &mut j);
    edge.push(&mut a);
    let mut view = view_for_j(&edge);
    let n = view.ops.len();
    view.sync(&mut j, &mut jv);
    edge.ops.extend(view.ops.drain(n..));
    // From now on J is served the real ops.
    dv.insert("from/d".into(), "counts".into());
    settle(&mut edge, &mut [(&mut d, &mut dv), (&mut a, &mut av), (&mut j, &mut jv)], 3);
    assert_eq!(jv.get("from/d").map(String::as_str), Some("counts"), "J dropped member D's write");
}

/// H3: the edge leaves A's own acknowledged op out of a pull. A never signs
/// a seq the edge has already taken from it.
#[test]
fn round3_h3_a_withheld_own_op_never_makes_a_member_reuse_a_seq() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    av.insert("x".into(), "1".into());
    edge.sync(&mut a, &mut av);
    let acked = edge.ops.iter().filter(|o| o.author == A).map(|o| o.seq).max().unwrap();
    av.insert("y".into(), "2".into());
    a.step(&mut av).unwrap();
    // A pull that leaves out A's newest acked op.
    let view = Edge { ops: edge.ops.iter().filter(|o| !(o.author == A && o.seq == acked)).cloned().collect() };
    a.state.next.insert(A.into(), acked - 1);
    view.pull(&mut a);
    let first = a.state.outbox.first().map(|o| o.seq).unwrap();
    assert!(first > acked, "A queued seq {first}, at or below the {acked} the edge already took");
}

/// H4: a device holding the epoch-0 key publishes a second founder op. The
/// ring goes on: A is still the founder and a member.
#[test]
fn round3_h4_a_second_founder_op_never_halts_the_ring() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let (_, k0) = b.current_key_for_test();
    let mut e = member(dir.path(), E, "second-founder");
    let body = e.own_body(0);
    let key = super::crypto::member_mac(&k0, &op::add_mac_text(E, &body));
    e.write(Kind::MemberAdd, key, 0, op::plain_body(&body), b64(b"wrap"), 0);
    edge.push(&mut e);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    let status = b.status(None).unwrap();
    assert_eq!(status["founder"], A, "{status}");
    assert_eq!(status["role"], "member", "{status}");
}

/// H5: a device that isn't a member has pushed far more ops than a member
/// keeps for it. Its cursor is parked: the same ops aren't pulled and let go
/// again on every sync.
#[test]
fn round3_h5_a_capped_author_is_parked_not_pulled_again_and_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    let mut junk = member(dir.path(), JUNK, "junk");
    edge.sync(&mut junk, &mut vault(&[]));
    for i in 0..80 {
        junk.write(Kind::Put, b64([i as u8; 32]), 1, b64(b"junk"), b64(b"junk"), 0);
    }
    edge.push(&mut junk);
    edge.sync(&mut a, &mut av);
    let after_first = a.state.dropped;
    edge.sync(&mut a, &mut av);
    edge.sync(&mut a, &mut av);
    assert_eq!(a.state.dropped, after_first, "the same junk ops were pulled and let go again");
}

/// M1: a sync applies an incoming write, saves its state, and the agent
/// crashes before the vault is saved. The write isn't lost.
#[test]
fn round3_m1_a_crash_before_the_vault_is_saved_loses_no_incoming_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    av.insert("incoming".into(), "v".into());
    edge.sync(&mut a, &mut av);
    edge.pull(&mut b);
    let on_disk = bv.clone();
    let mut applied = bv.clone();
    b.step(&mut applied).unwrap();
    assert_eq!(applied.get("incoming").map(String::as_str), Some("v"));
    b.save().unwrap();
    // Crash: the vault on disk is still `on_disk`; the agent starts again.
    let mut b = Member::load_at(b.edge.clone(), dir.path().join(format!("{B}.sync.json"))).unwrap();
    b.pull_complete = true;
    let mut vault_after = on_disk;
    b.step(&mut vault_after).unwrap();
    assert_eq!(vault_after.get("incoming").map(String::as_str), Some("v"), "the incoming write was lost");
}
