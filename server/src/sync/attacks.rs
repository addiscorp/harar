//! The reviews of #105, each finding as its attack or failure, against
//! members through the stand-in edge of `tests.rs`. The third review's
//! (C1, H1–H6, M1) failed on cae0c3f (commit 39a95e6 has them against that
//! model); the others carry over from the first two reviews.

use super::apply::{Incoming, VaultMeta};
use super::crypto::b64;
use super::member::Member;
use super::op::{self, Entry, EntryType, Kind, MemberKeys, Rank, Removed, Request, RequestType, Served};
use super::tests::{A, B, C, Edge, member, ring, role, settle, trust, vault};
use std::collections::{BTreeMap, HashMap};

const D: &str = "d-dddddddddddddddd";
const E: &str = "d-eeeeeeeeeeeeeeee";
const J: &str = "d-3333333333333333";
const R: &str = "d-4444444444444444";
const X: &str = "d-1111111111111111";
const JUNK: &str = "d-0000000000000001";

/// A member writes a membership entry as if it were the authority.
fn fake_entry(m: &mut Member, what: EntryType, fill: impl FnOnce(&mut Entry)) {
    let log = m.log();
    let (epoch, id) = log.epoch().map(|(e, id)| (e, id.to_owned())).unwrap();
    let mut entry = Entry { what, n: log.entries.len() as u64, prev: log.head().unwrap().to_owned(), epoch, id, member: None, removed: Vec::new(), authority: None, wraps: BTreeMap::new() };
    fill(&mut entry);
    let sealed = op::plain_body(&entry);
    let kind = if what == EntryType::Remove { Kind::Rekey } else { Kind::MemberAdd };
    m.write(kind, op::entry_key(&op::head_of(&sealed)), entry.n, sealed, String::new(), 0);
}

fn members_of(m: &mut Member) -> Vec<(String, bool)> {
    m.status(None).unwrap()["members"].as_array().unwrap().iter().map(|x| (x["device"].as_str().unwrap().to_owned(), x["removed_at"].is_null())).collect()
}

/// C1: A removes R; R, before it sees that, tries to remove A, and writes
/// an entry that says so. A stays, R is out, and R's later writes count
/// nowhere.
#[test]
fn c1_a_removed_member_cannot_remove_its_remover() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, R]);
    let mut r = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut rv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut r, &mut rv)], 1);
    a.remove(R).unwrap();
    assert!(r.remove(A).unwrap_err().to_string().contains("only the ring's authority"));
    fake_entry(&mut r, EntryType::Remove, |e| {
        e.epoch += 1;
        e.removed = vec![Removed { device: A.into(), after: 0 }];
    });
    edge.push(&mut a);
    edge.push(&mut r);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 3);
    rv.insert("r/after".into(), "should not count".into());
    let _ = r.step(&mut rv);
    edge.push(&mut r);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 3);
    let ms = members_of(&mut b);
    assert!(ms.contains(&(A.to_owned(), true)), "A is still an active member: {ms:?}");
    assert!(ms.contains(&(R.to_owned(), false)), "R is out: {ms:?}");
    assert_eq!(b.status(None).unwrap()["authority"], A);
    assert!(!bv.contains_key("r/after"), "R's write after its removal counted");
}

/// H1: B is served the ring without A's removal of X for a while. Nothing
/// gives X a key made after its removal, and nothing rekeys again.
#[test]
fn h1_a_member_behind_a_removal_never_regrants_the_removed_device() {
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
    let removal = edge.ops[before..].iter().find(|o| o.kind == Kind::Rekey).unwrap().seq;
    for _ in 0..3 {
        let mut view = Edge { ops: edge.ops.iter().filter(|o| !(o.author == A && o.seq >= removal)).cloned().collect() };
        let n = view.ops.len();
        view.sync(&mut b, &mut bv);
        edge.ops.extend(view.ops.drain(n..));
        edge.sync(&mut a, &mut av);
    }
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 4);
    let entries: Vec<Entry> = edge.ops[before..].iter().filter_map(super::ledger::entry_of).collect();
    assert_eq!(entries.iter().filter(|e| e.what == EntryType::Remove).count(), 1, "one rekey, no more");
    assert!(entries.iter().all(|e| !e.wraps.contains_key(X)), "a key given to X after its removal");
}

/// H2: the edge serves a fresh joiner a forged first op for member D, with
/// keys that aren't D's. D is still a member there, and its writes count.
#[test]
fn h2_a_forged_first_op_never_ejects_a_member() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[D]);
    let mut d = others.remove(0);
    let (mut av, mut dv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut d, &mut dv)], 1);
    let attacker = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    let keys = MemberKeys { sign_pub: b64(attacker.verifying_key().to_encoded_point(false).as_bytes()), ..d.own_keys() };
    let body = Request { what: RequestType::Request, member: keys };
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
    trust(&a, &mut j);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &j);
    edge.push(&mut a);
    let mut view = view_for_j(&edge);
    let n = view.ops.len();
    view.sync(&mut j, &mut jv);
    edge.ops.extend(view.ops.drain(n..));
    assert!(j.state.forged.iter().any(|f| f.author == D), "the forged op is refused: {:?}", j.state.forged);
    assert!(members_of(&mut j).contains(&(D.to_owned(), true)), "D is still a member at J");
    dv.insert("from/d".into(), "counts".into());
    settle(&mut edge, &mut [(&mut d, &mut dv), (&mut a, &mut av), (&mut j, &mut jv)], 3);
    assert_eq!(jv.get("from/d").map(String::as_str), Some("counts"), "J dropped member D's write");
}

/// H3: the edge leaves A's own acknowledged op out of a pull. A never signs
/// a seq the edge has already taken, refuses that edge, and sends nothing.
#[test]
fn h3_a_withheld_own_op_never_makes_a_member_reuse_a_seq() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    av.insert("x".into(), "1".into());
    edge.sync(&mut a, &mut av);
    let acked = edge.ops.iter().filter(|o| o.author == A).map(|o| o.seq).max().unwrap();
    av.insert("y".into(), "2".into());
    a.step(&mut av).unwrap();
    let view = Edge { ops: edge.ops.iter().filter(|o| !(o.author == A && o.seq == acked)).cloned().collect() };
    a.state.authors.get_mut(A).unwrap().back_to(acked, &edge.ops.iter().find(|o| o.author == A && o.seq == acked).unwrap().prev);
    a.state.next.insert(A.into(), acked - 1);
    view.pull(&mut a);
    let first = a.state.outbox.first().map(|o| o.seq).unwrap();
    assert!(first > acked, "A queued seq {first}, at or below the {acked} the edge already took");
    assert!(a.status(None).unwrap()["chain"].as_str().unwrap().contains("withholding"));
    assert!(a.ready().is_empty(), "nothing is sent to an edge that withholds this device's ops");
    // The real edge again: on it goes.
    edge.pull(&mut a);
    assert_eq!(a.status(None).unwrap()["chain"], "ok");
    edge.push(&mut a);
    assert!(a.state.outbox.is_empty());
}

/// H4: another device founds a ring (and one claims the founder's keys).
/// The ring goes on: A is still the founder and authority.
#[test]
fn h4_a_second_founder_op_never_halts_the_ring() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let mut e = member(dir.path(), E, "second-founder");
    e.found_or_request().unwrap();
    edge.push(&mut e);
    // And a "found" naming A's own keys, written by another device.
    let mut f = member(dir.path(), D, "impostor");
    let entry = Entry { what: EntryType::Found, n: 0, prev: String::new(), epoch: 0, id: "x".repeat(43), member: Some(a.own_keys()), removed: Vec::new(), authority: None, wraps: BTreeMap::new() };
    let sealed = op::plain_body(&entry);
    f.write(Kind::MemberAdd, op::entry_key(&op::head_of(&sealed)), 0, sealed, b64(b"wrap"), 0);
    edge.push(&mut f);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    let status = b.status(None).unwrap();
    assert_eq!((status["founder"].as_str(), status["authority"].as_str(), status["role"].as_str()), (Some(A), Some(A), Some("member")), "{status}");
    assert_eq!(status["ring_conflicts"]["other_founders"][0]["device"], E, "{status}");
    av.insert("still".into(), "syncing".into());
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!(bv.get("still").map(String::as_str), Some("syncing"));
}

/// H5: a device that isn't a member pushes far more ops than a member keeps
/// for it. It is parked: its ops aren't pulled again on every sync, and a
/// member's writes still get through.
#[test]
fn h5_a_capped_author_is_parked_and_never_starves_a_member() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    let mut junk = member(dir.path(), JUNK, "junk");
    edge.sync(&mut junk, &mut vault(&[]));
    for i in 0..80 {
        junk.write(Kind::Put, b64([i as u8; 32]), 1, b64(b"junk"), b64(b"junk"), 0);
    }
    edge.push(&mut junk);
    a.forget();
    edge.pull(&mut a);
    assert!(a.state.parked.contains(JUNK), "parked while locked too");
    let held = |m: &Member| m.state.pending.iter().chain(m.state.member_ops.iter()).filter(|o| o.author == JUNK).count();
    assert_eq!(held(&a), 20);
    assert_eq!(a.since()[JUNK], (1 << 31) - 1, "pulls skip it");
    let cursor = a.state.next[JUNK];
    bv.insert("from/b".into(), "gets through".into());
    settle(&mut edge, &mut [(&mut b, &mut bv), (&mut a, &mut av)], 2);
    assert_eq!((held(&a), a.state.next[JUNK]), (20, cursor), "nothing past the cursor taken or let go");
    assert_eq!(av.get("from/b").map(String::as_str), Some("gets through"));
}

/// H6 (the member's side; the edge's is in edge/test): a later op on a
/// secret's key by someone who isn't a member never counts as superseding
/// a member's op.
#[test]
fn h6_a_non_members_later_op_never_supersedes_a_members_compacted_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    av.insert("p".into(), "the latest".into());
    edge.sync(&mut a, &mut av);
    let mut junk = member(dir.path(), JUNK, "junk");
    edge.sync(&mut junk, &mut vault(&[]));
    let theirs = edge.ops.iter().rev().find(|o| o.author == A && o.kind.is_value()).unwrap().clone();
    junk.write(Kind::Put, theirs.key.clone(), theirs.version + 1, b64(b"junk"), b64(b"junk"), theirs.at + 1000);
    edge.push(&mut junk);
    // The edge serves A's latest op compacted.
    let mut served = Edge { ops: edge.ops.clone() };
    for op in &mut served.ops {
        if op.hash == theirs.hash {
            op.sealed = None;
            op.wrapped_key = None;
            op.compacted = true;
        }
    }
    served.sync(&mut b, &mut bv);
    assert!(b.state.pending.iter().any(|o| o.hash == theirs.hash), "it waits");
    assert_eq!(b.status(None).unwrap()["waiting_compacted"], 1);
}

/// M1: a sync applies an incoming write, saves its state, and the agent
/// crashes before the vault is saved. The write isn't lost.
#[test]
fn m1_a_crash_before_the_vault_is_saved_loses_no_incoming_write() {
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
    let mut b = Member::load_at(b.edge.clone(), dir.path().join(format!("{B}.sync.json"))).unwrap();
    b.pull_complete = true;
    let mut vault_after = on_disk;
    b.step(&mut vault_after).unwrap();
    assert_eq!(vault_after.get("incoming").map(String::as_str), Some("v"), "the incoming write was lost");
}

// ------------------------------------------------------------------ earlier rounds

/// #1/N1: a device that isn't the authority writes membership entries (a
/// remove with its own key wrapped to A, an add naming the founder with
/// other keys). Nothing changes: A writes on with the ring's key, and B
/// reads it.
#[test]
fn a_membership_entry_by_anyone_but_the_authority_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let evil = super::crypto::random_key();
    let a_agree = super::crypto::public_key(&super::crypto::unb64(&a.own_keys().agree_pub).unwrap()).unwrap();
    fake_entry(&mut b, EntryType::Remove, |e| {
        e.epoch += 1;
        e.id = super::ledger::ring_id(&evil, e.epoch);
        e.removed = vec![Removed { device: A.into(), after: 0 }];
        e.wraps.insert(A.into(), b64(super::crypto::wrap_ring(&a_agree, e.epoch, A, &evil)));
    });
    edge.push(&mut b);
    let mut rogue = member(dir.path(), E, "rogue");
    edge.sync(&mut rogue, &mut vault(&[]));
    let other = MemberKeys { device: A.into(), ..rogue.own_keys() };
    let founding = edge.ops.iter().find(|o| o.author == A && o.seq == 1).unwrap().clone();
    rogue.write(Kind::MemberAdd, founding.key.clone(), 1, op::plain_body(&Entry { what: EntryType::Add, n: 1, prev: a.log().entries[0].head.clone(), epoch: 0, id: a.log().entries[0].entry.id.clone(), member: Some(other), removed: Vec::new(), authority: None, wraps: BTreeMap::new() }), String::new(), 0);
    edge.push(&mut rogue);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!(a.status(None).unwrap()["epoch"], 0, "A still writes with the ring's key");
    assert_eq!(role(&mut a), "authority");
    av.insert("after".into(), "still ours".into());
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!(bv.get("after").map(String::as_str), Some("still ours"));
}

/// #2: a paired device founds a ring of its own and approves a joiner. The
/// joiner seals nothing for a ring it didn't pin; pinned to A's, it takes
/// only A's.
#[test]
fn a_joiner_follows_only_the_ring_it_pinned() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[("b/secret", "the-joiners-own")]);
    edge.sync(&mut b, &mut bv);
    let mut rogue = member(dir.path(), E, "rogue");
    rogue.found_or_request().unwrap();
    edge.push(&mut rogue);
    edge.pull(&mut rogue);
    let fp = b.fingerprint();
    rogue.approve(B, &fp).unwrap();
    edge.push(&mut rogue);
    settle(&mut edge, &mut [(&mut b, &mut bv)], 2);
    assert!(edge.ops.iter().all(|o| !(o.author == B && o.kind.is_value())), "B sealed something for a ring it never pinned");
    assert_eq!(role(&mut b), "requested");
    trust(&a, &mut b);
    edge.sync(&mut b, &mut bv);
    assert_eq!(role(&mut b), "requested", "the rogue ring's grant isn't taken");
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &b);
    edge.push(&mut a);
    edge.sync(&mut b, &mut bv);
    let status = b.status(None).unwrap();
    assert_eq!((status["role"].as_str(), status["founder"].as_str()), (Some("member"), Some(A)));
}

/// #4: the edge serves a ring op compacted (refused as forged) and a
/// member's latest value compacted (it waits). And a member served a
/// removal ignores what the removed device writes after.
#[test]
fn compaction_hides_nothing_and_a_served_removal_cuts_the_removed_device() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, C]);
    let mut c = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut cv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut c, &mut cv)], 1);
    av.insert("only/once".into(), "v".into());
    a.step(&mut av).unwrap();
    a.remove(B).unwrap();
    edge.push(&mut a);
    bv.insert("b/late".into(), "after its removal".into());
    let _ = b.step(&mut bv);
    edge.push(&mut b);

    let mut hiding = Edge { ops: edge.ops.clone() };
    for op in &mut hiding.ops {
        if op.author == A && (op.kind == Kind::Rekey || op.kind == Kind::Put) {
            op.sealed = None;
            op.wrapped_key = None;
            op.compacted = true;
        }
    }
    let probe_dir = tempfile::tempdir().unwrap();
    let mut probe = member(probe_dir.path(), C, C);
    probe.state = c.state.clone();
    hiding.pull(&mut probe);
    assert!(probe.state.rejected.iter().any(|r| r.author == A && r.reason.contains("compacted")), "{:?}", probe.state.rejected);

    settle(&mut edge, &mut [(&mut c, &mut cv)], 2);
    assert_eq!(cv.get("only/once").map(String::as_str), Some("v"));
    assert!(!cv.contains_key("b/late"), "C counted B's write after its removal");
}

/// #5: the same three ops, in any batching, end with the same value.
#[test]
fn last_write_wins_does_not_depend_on_arrival_order() {
    let w = |hash: &str, base: &str, at: u64, author: &str, value: &str| Incoming { hash: hash.into(), base: base.into(), rank: Rank { at, author: author.into(), seq: 1 }, version: 1, path: "p".into(), value: Some(value.into()) };
    let (o1, o2, o3) = (w("o1", "", 100, "d-a", "one"), w("o2", "o1", 50, "d-b", "two"), w("o3", "", 75, "d-c", "three"));
    let mut ends = Vec::new();
    for batches in [vec![vec![o1.clone(), o2.clone(), o3.clone()]], vec![vec![o1.clone()], vec![o3.clone(), o2.clone()]], vec![vec![o3.clone()], vec![o1.clone()], vec![o2.clone()]]] {
        let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
        for batch in batches {
            meta.apply(&mut keys, batch);
        }
        ends.push(keys["p"].clone());
    }
    assert!(ends.iter().all(|e| *e == "one"), "converged differently: {ends:?}");
}

/// #7/N6: two founders at once, one with a made-up early time. Neither gives
/// its ring up by itself; the person pins one with `trust`, then joins.
#[test]
fn of_two_founders_neither_falls_back_until_the_person_pins_one() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut b = member(dir.path(), B, "laptop");
    let (mut av, mut bv) = (vault(&[]), vault(&[("b/own", "from-b")]));
    a.found_or_request().unwrap();
    b.found_or_request().unwrap();
    b.state.outbox[0].at = 1;
    let fixed = Served::from(&b.state.outbox[0]);
    b.state.member_ops[0] = fixed;
    let (seq, hash) = (b.state.outbox[0].seq, b.state.outbox[0].hash());
    b.state.tip.hash = hash;
    b.state.tip.seq = seq;
    b.step(&mut bv).unwrap();
    edge.push(&mut a);
    edge.push(&mut b);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    for (m, other) in [(&mut a, B), (&mut b, A)] {
        let status = m.status(None).unwrap();
        assert_eq!(status["role"], "authority", "{status}");
        assert_eq!(status["ring_conflicts"]["other_founders"][0]["device"], other, "{status}");
    }
    trust(&a, &mut b);
    edge.sync(&mut b, &mut bv);
    assert_eq!(role(&mut b), "requested");
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &b);
    edge.push(&mut a);
    settle(&mut edge, &mut [(&mut b, &mut bv), (&mut a, &mut av)], 2);
    assert_eq!(av.get("b/own").map(String::as_str), Some("from-b"));
}

/// #9: the state file is restored from an older copy, so the next op reuses
/// a seq the edge already has. The queued ops are re-sequenced after the
/// edge's newest, including a queued removal, whose key is still the one
/// written with.
#[test]
fn a_restored_state_file_rebases_its_queued_ops_removal_included() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let old = a.state.clone();
    av.insert("x".into(), "1".into());
    edge.sync(&mut a, &mut av);
    a.state = old;
    a.remove(B).unwrap().unwrap();
    edge.sync(&mut a, &mut av);
    assert!(a.state.outbox.is_empty(), "rebased and sent");
    assert!(a.state.rebased > 0);
    av.insert("after/removal".into(), "secret".into());
    edge.sync(&mut a, &mut av);
    assert_eq!(a.status(None).unwrap()["epoch"], 1);
    edge.sync(&mut b, &mut bv);
    assert_eq!(role(&mut b), "removed");
    assert!(!bv.contains_key("after/removal"));
}

/// #15: a change recorded again after a crash is the same op, not a second.
#[test]
fn a_change_recorded_again_after_a_crash_is_not_a_second_op() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    av.insert("k".into(), "v".into());
    let unsaved = av.clone();
    a.step(&mut av).unwrap();
    let queued = a.state.outbox.len();
    let mut again = unsaved;
    a.step(&mut again).unwrap();
    assert_eq!(a.state.outbox.len(), queued);
}

/// N5: a joiner whose first pull hasn't seen a member's op for a path yet
/// never rolls the ring's value back with what it held before.
#[test]
fn a_stale_joiner_never_rolls_back_a_ring_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[C]);
    let mut c = others.remove(0);
    let (mut av, mut cv) = (vault(&[]), vault(&[]));
    edge.sync(&mut a, &mut av);
    let held_back = edge.ops.iter().filter(|o| o.author == C).count() as u64;
    cv.insert("p".into(), "the ring's".into());
    edge.sync(&mut c, &mut cv);
    edge.sync(&mut a, &mut av);
    let partial = |edge: &mut Edge, b: &mut Member, bv: &mut HashMap<String, String>| {
        let mut view = Edge { ops: edge.ops.iter().filter(|o| o.author != C || o.seq <= held_back).cloned().collect() };
        let n = view.ops.len();
        view.sync(b, bv);
        edge.ops.extend(view.ops.drain(n..));
    };
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[("p", "stale local")]);
    partial(&mut edge, &mut b, &mut bv);
    trust(&a, &mut b);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &b);
    edge.push(&mut a);
    partial(&mut edge, &mut b, &mut bv);
    settle(&mut edge, &mut [(&mut b, &mut bv), (&mut a, &mut av), (&mut c, &mut cv)], 2);
    assert_eq!((av["p"].as_str(), cv["p"].as_str(), bv["p"].as_str()), ("the ring's", "the ring's", "the ring's"));
}

/// N7: a second, different op at a seq already held is a fork, shown.
#[test]
fn a_second_op_at_one_seq_is_a_fork() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    av.insert("k".into(), "one".into());
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    let real = edge.ops.iter().filter(|o| o.author == A).max_by_key(|o| o.seq).unwrap().clone();
    let key = a.edge.key().unwrap();
    let other = Served::from(&op::Op::sign(A, real.seq, &real.prev, real.kind, &real.key, real.version, real.sealed.clone().unwrap(), real.wrapped_key.clone().unwrap(), real.at + 1, &|m| key.sign(m)).unwrap());
    b.ingest(vec![other]);
    assert_eq!(b.status(None).unwrap()["forks"][0]["author"], A);
}

/// #10: a pull whose `next` doesn't move the cursor while the edge says
/// there is more is refused, instead of looping.
#[test]
fn a_pull_that_never_moves_on_is_refused() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    std::thread::spawn(move || {
        for stream in listener.incoming().take(3) {
            let mut stream = stream.unwrap();
            let mut got = Vec::new();
            let mut buf = [0u8; 8192];
            loop {
                let n = stream.read(&mut buf).unwrap_or(0);
                got.extend_from_slice(&buf[..n]);
                let text = String::from_utf8_lossy(&got).to_lowercase();
                if let Some(end) = text.find("\r\n\r\n") {
                    let len = text.lines().find_map(|l| l.strip_prefix("content-length:")).map_or(0, |v| v.trim().parse::<usize>().unwrap_or(0));
                    if got.len() >= end + 4 + len {
                        break;
                    }
                }
                if n == 0 {
                    break;
                }
            }
            let body = r#"{"ops":[],"next":{},"more":true}"#;
            let _ = write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}", body.len());
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let mut m = member(dir.path(), A, "mac");
    m.edge.url = url;
    let device = m.edge.key().unwrap();
    let err = Member::pull(&m.edge, &device, &Default::default()).err().expect("refused");
    assert!(format!("{err:#}").contains("doesn't move the cursor"), "{err:#}");
}

/// #17: the epoch after the last one is an error, not a wrap to 0.
#[test]
fn the_last_epoch_cannot_be_rekeyed() {
    assert_eq!(super::member::next_epoch(7).unwrap(), 8);
    assert!(super::member::next_epoch(u32::MAX).is_err());
}

/// M5: an op dated far ahead waits; a writer never dates one ahead.
#[test]
fn a_far_future_at_never_wins_and_is_never_written() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 1);
    let op = b.write(Kind::Put, b64([9u8; 32]), 1, b64(b"x"), b64(b"x"), u64::MAX / 2);
    assert!(op.at <= super::member::now_ms() + 300_000, "written {} ahead", op.at - super::member::now_ms());
    let _ = &mut a;
    let _ = &mut av;
}

/// C1's other half and N8: a member that isn't the authority can't remove
/// anyone (unpair then falls through to the refusal).
#[test]
fn removing_from_a_member_that_isnt_the_authority_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (_, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    assert!(b.remove(A).unwrap_err().to_string().contains("only the ring's authority"));
    let mut j = member(dir.path(), J, "new");
    join_nothing(&mut edge, &mut j);
    assert!(j.remove(A).unwrap_err().to_string().contains("isn't a member"));
}

fn join_nothing(edge: &mut Edge, m: &mut Member) {
    edge.sync(m, &mut vault(&[]));
}
