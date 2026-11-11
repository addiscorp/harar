//! The fourth review of #105 (H1–H7), each as its scenario, written against
//! d9111dc (the fail-before evidence).

use super::crypto::b64;
use super::member::Member;
use super::op::{self, Kind, Op, Served};
use super::tests::{A, B, C, Edge, member, ring, settle, trust, vault};
use std::collections::HashMap;

const D: &str = "d-dddddddddddddddd";
const J: &str = "d-3333333333333333";
const R: &str = "d-4444444444444444";

fn view_sync(edge: &mut Edge, view: Edge, m: &mut Member, v: &mut HashMap<String, String>) {
    let mut view = view;
    let n = view.ops.len();
    view.sync(m, v);
    edge.ops.extend(view.ops.drain(n..));
}

/// H1: the edge serves one bogus op (no valid hash or signature) at a seq
/// the authority already has. The authority isn't silenced.
#[test]
fn round4_h1_one_bogus_op_never_silences_an_author() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let tip = b.state.authors[A].seq;
    let real = edge.ops.iter().find(|o| o.author == A && o.seq == tip).unwrap().clone();
    let bogus = Served { hash: "e".repeat(64), sig: "A".repeat(86), ..real };
    b.ingest(vec![bogus]);
    av.insert("after".into(), "still heard".into());
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!(bv.get("after").map(String::as_str), Some("still heard"), "B no longer hears the authority");
}

/// H2: R is removed with its ops up to `after` counting. R and the edge
/// serve a joiner a different chain for those seqs. The joiner never
/// counts it.
#[test]
fn round4_h2_a_removed_device_cannot_rewrite_what_counts_before_its_removal() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, R]);
    let mut r = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut rv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut r, &mut rv)], 1);
    let before_state = r.state.clone();
    let before_vault = rv.clone();
    rv.insert("p".into(), "v-real".into());
    edge.sync(&mut r, &mut rv);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    assert_eq!(av["p"], "v-real");
    a.remove(R).unwrap().unwrap();
    edge.push(&mut a);
    // R's other history: from the same place, p = "v-fake", signed by R.
    let mut alt = Member::load_at(r.edge.clone(), dir.path().join("r-alt.json")).unwrap();
    alt.state = before_state;
    alt.pull_complete = true;
    let mut alt_vault = before_vault;
    alt_vault.insert("p".into(), "v-fake".into());
    alt.step(&mut alt_vault).unwrap();
    alt.sign_all().unwrap();
    let alt_ops: Vec<Served> = alt.state.outbox.iter().map(Served::from).collect();
    let first_alt = alt_ops.iter().map(|o| o.seq).min().unwrap();
    let view_for_j = |edge: &Edge| Edge { ops: edge.ops.iter().filter(|o| !(o.author == R && o.seq >= first_alt)).cloned().chain(alt_ops.iter().cloned()).collect() };
    let mut j = member(dir.path(), J, "new");
    let mut jv = vault(&[]);
    let view = view_for_j(&edge);
    view_sync(&mut edge, view, &mut j, &mut jv);
    trust(&a, &mut j);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &j);
    edge.push(&mut a);
    for _ in 0..3 {
        let view = view_for_j(&edge);
        view_sync(&mut edge, view, &mut j, &mut jv);
    }
    assert_ne!(jv.get("p").map(String::as_str), Some("v-fake"), "J counted R's rewritten history");
}

/// H3: the authority's state file is restored from an older copy and it
/// approves a device before a full sync. It must refuse, and after a full
/// sync its next entry follows the log: no fork.
#[test]
fn round4_h3_a_restored_authority_never_forks_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    // C and D both ask; A sees both requests, then its state is saved.
    let mut c = member(dir.path(), C, "phone");
    let mut d = member(dir.path(), D, "tablet");
    edge.sync(&mut c, &mut vault(&[]));
    edge.sync(&mut d, &mut vault(&[]));
    trust(&a, &mut c);
    trust(&a, &mut d);
    edge.sync(&mut a, &mut av);
    let old = a.state.clone();
    super::tests::approve(&mut a, &c);
    edge.push(&mut a);
    // Restored, and started again: nothing pulled yet.
    a.state = old;
    a.pull_complete = false;
    assert!(a.approve(D, &d.fingerprint()).is_err(), "a restored authority approved before a full sync");
    edge.sync(&mut a, &mut av);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &d);
    edge.push(&mut a);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    let status = b.status(None).unwrap();
    assert!(status["log"]["fork_at"].is_null(), "the log forked: {status}");
    let members: Vec<&str> = status["members"].as_array().unwrap().iter().map(|m| m["device"].as_str().unwrap()).collect();
    assert!(members.contains(&C) && members.contains(&D), "{members:?}");
}

/// H4: a thousand devices that aren't members never make a member's pull
/// carry them all in `since`.
#[test]
fn round4_h4_sock_puppets_never_grow_since() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let puppets: Vec<Served> = (0..1100u64)
        .map(|i| Served::from(&Op { author: format!("d-{i:016x}"), seq: 1, prev: String::new(), kind: Kind::MemberAdd, key: b64([1u8; 32]), version: 0, sealed: b64(b"{}"), wrapped_key: String::new(), at: 1, sig: "A".repeat(86) }))
        .collect();
    a.ingest(puppets);
    assert!(a.since().len() < 10, "since carries {} authors", a.since().len());
}

/// H6: A removes R with an `after` older than what B already applied from
/// R. B takes R's later write back, as A never had it: they agree.
#[test]
fn round4_h6_a_removal_takes_back_what_came_after_its_cut() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, R]);
    let mut r = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut rv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut r, &mut rv)], 1);
    rv.insert("p".into(), "r1".into());
    edge.sync(&mut r, &mut rv);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    rv.insert("p".into(), "r2".into());
    edge.sync(&mut r, &mut rv);
    edge.sync(&mut b, &mut bv);
    assert_eq!(bv["p"], "r2");
    // A hasn't pulled R's second write: its cut is R's first.
    a.remove(R).unwrap().unwrap();
    edge.push(&mut a);
    settle(&mut edge, &mut [(&mut b, &mut bv), (&mut a, &mut av)], 2);
    assert_eq!((av.get("p").map(String::as_str), bv.get("p").map(String::as_str)), (Some("r1"), Some("r1")), "A and B disagree after R's removal");
}

/// H7: a removed device's ops past its cut are let go as they arrive, even
/// with the vault locked.
#[test]
fn round4_h7_a_removed_devices_later_ops_are_not_held() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, R]);
    let mut r = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut rv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut r, &mut rv)], 1);
    a.remove(R).unwrap().unwrap();
    edge.push(&mut a);
    for i in 0..5 {
        rv.insert(format!("late/{i}"), "x".into());
    }
    let _ = r.step(&mut rv);
    edge.push(&mut r);
    b.forget();
    edge.pull(&mut b);
    let after = op::Removed { device: String::new(), after: 0, after_hash: String::new() }.after;
    let held = b.state.pending.iter().filter(|o| o.author == R).count();
    assert_eq!(held, after as usize, "B holds {held} op(s) R wrote after its removal");
}
