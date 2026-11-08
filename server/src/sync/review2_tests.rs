//! The second security review of #105 (N1–N10): each finding as an attack
//! or a failure, against members through the stand-in edge of `tests.rs`.

use super::crypto::b64;
use super::member::Member;
use super::op::{self, Kind, MemberBody, Served};
use super::review_tests::ring;
use super::tests::{Edge, member, vault};
use std::collections::HashMap;

const A: &str = "d-aaaaaaaaaaaaaaaa";
const B: &str = "d-bbbbbbbbbbbbbbbb";
const M: &str = "d-dddddddddddddddd";
const X: &str = "d-1111111111111111";
const Y: &str = "d-2222222222222222";
const ROGUE: &str = "d-eeeeeeeeeeeeeeee";

/// Syncs every member `rounds` times, in order.
fn settle(edge: &mut Edge, members: &mut [(&mut Member, &mut HashMap<String, String>)], rounds: usize) {
    for _ in 0..rounds {
        for (m, v) in members.iter_mut() {
            edge.sync(m, v);
        }
    }
}

/// N1: a paired device that isn't a member pushes a member.add naming the
/// founder with its own keys, reusing the founder's public MAC. The founder
/// stays a member and its writes still count.
#[test]
fn review_n1_nobody_can_eject_a_member_by_replaying_its_grant_mac() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    edge.sync(&mut rogue, &mut vault(&[]));
    let founding = edge.ops.iter().find(|o| o.author == A && o.seq == 1).unwrap().clone();
    let fake = MemberBody { device: A.into(), ..rogue.own_body(0) };
    rogue.write(Kind::MemberAdd, founding.key.clone(), 0, op::plain_body(&fake), b64(b"not a wrap"), 0);
    edge.push(&mut rogue);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    assert_eq!(a.status(None).unwrap()["role"], "member");
    av.insert("from/a".into(), "still counts".into());
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    assert_eq!(bv.get("from/a").map(String::as_str), Some("still counts"), "B still takes the founder's writes");
}

/// N2 (and #9 with a queued rekey): a removal's rekey is queued, the push is
/// refused (the state file was older than the edge), the ops are rebased.
/// The new epoch is still the one written with, and the removed device can't
/// open the next write.
#[test]
fn review_n2_a_rebased_rekey_is_still_the_key_written_with() {
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
    a.remove(B).unwrap().unwrap();
    edge.push(&mut a);
    edge.sync(&mut a, &mut av);
    assert!(a.state.outbox.is_empty(), "rebased and sent");
    av.insert("after/removal".into(), "secret".into());
    edge.sync(&mut a, &mut av);
    assert_eq!(a.status(None).unwrap()["epoch"], 1, "the rebased rekey's key is the one written with");
    let mut bv = vault(&[]);
    edge.sync(&mut b, &mut bv);
    assert!(!bv.contains_key("after/removal"), "the removed device can't open it");
}

/// N3: A removes X while B removes Y. Neither removed device can read what
/// is written after both, and the members can.
#[test]
fn review_n3_concurrent_removals_leave_no_removed_device_with_the_write_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, X, Y]);
    let mut y = others.remove(2);
    let mut x = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut xv, mut yv) = (vault(&[]), vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut x, &mut xv), (&mut y, &mut yv)], 1);
    a.remove(X).unwrap().unwrap();
    b.remove(Y).unwrap().unwrap();
    edge.push(&mut a);
    edge.push(&mut b);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 3);
    av.insert("after/both".into(), "a".into());
    bv.insert("after/both/b".into(), "b".into());
    let mark = edge.ops.len();
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut x, &mut xv), (&mut y, &mut yv)], 3);
    assert_eq!(bv.get("after/both").map(String::as_str), Some("a"));
    assert_eq!(av.get("after/both/b").map(String::as_str), Some("b"));
    // A removed device's own code refuses to apply; what matters is whether
    // the keys it holds open what was written after.
    let after: Vec<Served> = edge.ops[mark..].iter().filter(|o| o.kind.is_value() && (o.author == A || o.author == B)).cloned().collect();
    assert!(!after.is_empty());
    for (who, m) in [("X", &x), ("Y", &y)] {
        let opened = after.iter().filter(|op| held_keys(m).iter().any(|k| super::crypto::open_value(k, &op.key, op.version, op.sealed.as_deref().unwrap(), op.wrapped_key.as_deref().unwrap()).is_ok())).count();
        assert_eq!(opened, 0, "{who}, removed, holds a key that opens {opened} write(s) made after both removals");
    }
}

/// Every ring key a member's state file holds, opened with its own
/// key-agreement key.
fn held_keys(m: &Member) -> Vec<[u8; 32]> {
    let agreement = crate::cli::edge::AgreementKey::load(&m.edge.sync.as_ref().unwrap().agreement).unwrap();
    m.state
        .ring
        .iter()
        .filter_map(|e| {
            let plain = agreement.open(&super::crypto::unb64(&e.wrapped).ok()?).ok()?;
            super::crypto::unwrapped_ring(&plain, e.epoch, &m.edge.device).map(|k| *k)
        })
        .collect()
}

/// N3: A approves M at epoch 0 while B removes Y and rekeys to epoch 1
/// without knowing M. M still gets the key members write with.
#[test]
fn review_n3_an_approval_crossing_a_rekey_still_gets_the_current_key() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, Y]);
    let mut y = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut yv, mut mv) = (vault(&[]), vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut y, &mut yv)], 1);
    let mut m = member(dir.path(), M, "phone");
    edge.sync(&mut m, &mut mv);
    super::tests::trust(&mut a, &mut m);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &mut m);
    b.remove(Y).unwrap().unwrap();
    edge.push(&mut a);
    edge.push(&mut b);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut m, &mut mv)], 3);
    bv.insert("from/b".into(), "after the rekey".into());
    settle(&mut edge, &mut [(&mut b, &mut bv), (&mut a, &mut av), (&mut m, &mut mv)], 3);
    assert_eq!(mv.get("from/b").map(String::as_str), Some("after the rekey"), "M reads a write made with the new epoch");
}

/// N4: while the vault is locked (no ring key open), nothing waiting is
/// dropped, however much there is.
#[test]
fn review_n4_nothing_is_dropped_while_no_ring_key_is_open() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, _) = ring(dir.path(), &mut edge, &[]);
    let mut av = vault(&[]);
    av.insert("k".into(), "v".into());
    edge.sync(&mut a, &mut av);
    let op = edge.ops.iter().find(|o| o.kind.is_value()).unwrap().clone();
    a.forget();
    let many: Vec<Served> = (0..5001u64).map(|i| Served { hash: format!("{i:064x}"), seq: i + 10, ..op.clone() }).collect();
    a.state.pending.extend(many);
    a.ingest(Vec::new());
    assert_eq!(a.state.pending.len(), 5001, "dropped {} while locked", 5001 - a.state.pending.len());
}

/// N5: a joiner whose first sync hasn't seen the ring's op for a path yet
/// never rolls the ring's value back with what it held before.
#[test]
fn review_n5_a_stale_joiner_never_rolls_back_a_ring_value() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[M]);
    let mut c = others.remove(0);
    let (mut av, mut cv) = (vault(&[]), vault(&[]));
    edge.sync(&mut a, &mut av);
    // C (a member) writes p; A has it.
    let held_back = edge.ops.iter().filter(|o| o.author == M).count();
    cv.insert("p".into(), "the ring's".into());
    edge.sync(&mut c, &mut cv);
    edge.sync(&mut a, &mut av);
    assert_eq!(av["p"], "the ring's");
    // B is served everything but C's ops from its write on (an edge may serve
    // an author's chain as far as it likes), until it has joined.
    let partial_sync = |edge: &mut Edge, b: &mut Member, bv: &mut HashMap<String, String>| {
        let mut partial = Edge { ops: edge.ops.iter().filter(|o| o.author != M || o.seq <= held_back as u64).cloned().collect() };
        let before = partial.ops.len();
        partial.sync(b, bv);
        edge.ops.extend(partial.ops.drain(before..));
    };
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[("p", "stale local")]);
    partial_sync(&mut edge, &mut b, &mut bv);
    super::tests::trust(&mut a, &mut b);
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &mut b);
    edge.push(&mut a);
    partial_sync(&mut edge, &mut b, &mut bv);
    assert_eq!(b.status(None).unwrap()["role"], "member");
    for _ in 0..2 {
        edge.sync(&mut b, &mut bv);
        edge.sync(&mut a, &mut av);
        edge.sync(&mut c, &mut cv);
    }
    assert_eq!(av["p"], "the ring's", "A kept the ring's value");
    assert_eq!(cv["p"], "the ring's", "C kept the ring's value");
    assert_eq!(bv["p"], "the ring's", "B took the ring's value");
}

/// N6: a device founds a "ring" with a made-up early time. The real founder
/// never gives its ring up for it; the conflict is shown.
#[test]
fn review_n6_an_early_at_never_displaces_a_founder() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut av = vault(&[("k", "v")]);
    edge.sync(&mut a, &mut av);
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    rogue.found_or_request().unwrap();
    rogue.state.outbox[0].at = 1;
    edge.push(&mut rogue);
    edge.sync(&mut a, &mut av);
    edge.sync(&mut a, &mut av);
    let status = a.status(None).unwrap();
    assert_eq!(status["role"], "member", "{status}");
    assert_eq!(status["founder"], A);
    assert_eq!(status["ring_conflicts"]["other_founders"][0]["device"], ROGUE, "{status}");
}

/// N7: the edge serves a second, different op at a seq an author already
/// has. That's a fork: shown, and the author doesn't count past it.
#[test]
fn review_n7_a_second_op_at_one_seq_is_a_fork() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let (mut av, mut bv) = (vault(&[]), vault(&[]));
    av.insert("k".into(), "one".into());
    edge.sync(&mut a, &mut av);
    edge.sync(&mut b, &mut bv);
    let real = edge.ops.iter().filter(|o| o.author == A).max_by_key(|o| o.seq).unwrap().clone();
    // A second op at the same seq, really signed by A.
    let key = a.edge.key().unwrap();
    let other = Served::from(&op::Op::sign(A, real.seq, &real.prev, real.kind, &real.key, real.version, real.sealed.clone().unwrap(), real.wrapped_key.clone().unwrap(), real.at + 1, &|m| key.sign(m)).unwrap());
    b.ingest(vec![other]);
    let status = b.status(None).unwrap();
    assert_eq!(status["forks"][0]["author"], A, "{status}");
}

/// N8: a machine that syncs but isn't a member can't "remove" anyone: it
/// says so, so unpair doesn't skip the rekey thinking it was done.
#[test]
fn review_n8_removing_from_a_machine_that_isnt_a_member_fails() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    edge.sync(&mut a, &mut vault(&[]));
    let mut b = member(dir.path(), B, "laptop");
    edge.sync(&mut b, &mut vault(&[]));
    assert!(b.remove(A).is_err(), "B isn't a member: removing must fail, not report nothing to do");
}

/// #1 with a real member: once removed, X's rekey (its key wrapped to A,
/// backing onto the ring key X still holds) is not taken.
#[test]
fn review_1_a_rekey_from_a_removed_member_is_never_taken() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, X]);
    let mut x = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut xv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut x, &mut xv)], 1);
    let (epoch, held) = x.current_key_for_test();
    a.remove(X).unwrap().unwrap();
    edge.push(&mut a);
    // X, before it sees its removal, rekeys to a key of its own for A and B.
    let evil = super::crypto::random_key();
    let next = epoch + 1;
    let id = super::ledger::ring_id(&evil, next);
    let mut wraps = std::collections::BTreeMap::new();
    for (who, m) in [(A, &a), (B, &b)] {
        let pk = super::crypto::public_key(&super::crypto::unb64(&m.own_body(0).agree_pub).unwrap()).unwrap();
        wraps.insert(who.to_owned(), b64(super::crypto::wrap_ring(&pk, next, who, &evil)));
    }
    let body = op::RekeyBody { epoch: next, id: id.clone(), wraps };
    let back = b64(super::crypto::gcm_seal(&super::crypto::wrap_key(&evil), &held, op::rekey_ad(next).as_bytes(), super::crypto::random_iv()));
    x.write(Kind::Rekey, super::crypto::member_mac(&held, &op::rekey_mac_text(X, next, &id)), u64::from(next), op::plain_body(&body), back, 0);
    edge.push(&mut x);
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    av.insert("after".into(), "for members".into());
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv)], 2);
    assert_eq!(bv.get("after").map(String::as_str), Some("for members"));
    let after: Vec<Served> = edge.ops.iter().filter(|o| o.author == A && o.kind.is_value()).cloned().collect();
    assert!(after.iter().all(|op| super::crypto::open_value(&evil, &op.key, op.version, op.sealed.as_deref().unwrap(), op.wrapped_key.as_deref().unwrap()).is_err()), "A wrote with the removed device's key");
}

/// #2 with a pin: B pins A's ring, then a fake ring grants B first. B takes
/// only A's grant.
#[test]
fn review_2_a_pinned_joiner_refuses_a_grant_from_another_ring() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let mut a = member(dir.path(), A, "mac");
    let mut av = vault(&[]);
    edge.sync(&mut a, &mut av);
    let mut b = member(dir.path(), B, "laptop");
    let mut bv = vault(&[("b/own", "v")]);
    edge.sync(&mut b, &mut bv);
    super::tests::trust(&mut a, &mut b);
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    rogue.found_or_request().unwrap();
    edge.push(&mut rogue);
    edge.pull(&mut rogue);
    super::tests::approve_unchecked(&mut rogue, B);
    edge.push(&mut rogue);
    edge.sync(&mut b, &mut bv);
    assert_eq!(b.status(None).unwrap()["role"], "requested", "the fake ring's grant isn't taken");
    edge.sync(&mut a, &mut av);
    super::tests::approve(&mut a, &mut b);
    edge.push(&mut a);
    edge.sync(&mut b, &mut bv);
    let status = b.status(None).unwrap();
    assert_eq!((status["role"].as_str(), status["founder"].as_str()), (Some("member"), Some(A)));
}

/// #4 without compaction: C, served the removal, ignores what B writes after.
#[test]
fn review_4_a_member_served_the_removal_ignores_the_removed_devices_later_writes() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B, M]);
    let mut c = others.remove(1);
    let mut b = others.remove(0);
    let (mut av, mut bv, mut cv) = (vault(&[]), vault(&[]), vault(&[]));
    settle(&mut edge, &mut [(&mut a, &mut av), (&mut b, &mut bv), (&mut c, &mut cv)], 1);
    a.remove(B).unwrap().unwrap();
    edge.push(&mut a);
    bv.insert("b/late".into(), "after its removal".into());
    let _ = b.step(&mut bv);
    edge.push(&mut b);
    settle(&mut edge, &mut [(&mut c, &mut cv)], 2);
    assert!(!cv.contains_key("b/late"));
    assert!(c.state.rejected.iter().any(|r| r.author == B), "{:?}", c.state.rejected);
}

/// #14: a device that isn't a member can make a member hold at most
/// PER_AUTHOR of its ops; the rest are let go and its cursor goes back, so
/// they come again. A member's ops are never let go.
#[test]
fn review_14_a_junk_author_is_capped_and_its_cursor_goes_back() {
    let dir = tempfile::tempdir().unwrap();
    let mut edge = Edge::default();
    let (mut a, mut others) = ring(dir.path(), &mut edge, &[B]);
    let mut b = others.remove(0);
    let mut av = vault(&[]);
    let mut rogue = member(dir.path(), ROGUE, "rogue");
    edge.sync(&mut rogue, &mut vault(&[]));
    for i in 0..60 {
        rogue.write(Kind::Put, b64([i as u8; 32]), 1, b64(b"junk"), b64(b"junk"), 0);
    }
    edge.push(&mut rogue);
    let mut bv = vault(&[]);
    for i in 0..30 {
        bv.insert(format!("b/{i}"), "v".into());
    }
    edge.sync(&mut b, &mut bv);
    a.forget();
    edge.pull(&mut a);
    let mine = a.state.pending.iter().filter(|o| o.author == B).count();
    a.roster().unwrap();
    edge.pull(&mut a);
    let junk = a.state.pending.iter().filter(|o| o.author == ROGUE).count();
    assert!(junk <= 20, "{junk} junk ops held");
    assert!(a.state.dropped > 0);
    assert!(a.state.next[ROGUE] < 61, "the cursor never passes an op let go");
    assert_eq!(a.state.pending.iter().filter(|o| o.author == B).count(), mine, "a member's ops are never let go");
    edge.sync(&mut a, &mut av);
    assert_eq!(av.len() - 1, 30, "B's 30 secrets all applied");
}

/// #17: the epoch after the last one is an error, not a wrap to 0.
#[test]
fn review_17_the_last_epoch_cannot_be_rekeyed() {
    assert_eq!(super::member::next_epoch(7).unwrap(), 8);
    assert!(super::member::next_epoch(u32::MAX).is_err());
}

/// #10: a pull whose `next` doesn't move the cursor while the edge says
/// there is more is refused, instead of looping.
#[test]
fn review_10_a_pull_that_never_moves_on_is_refused() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let server = std::thread::spawn(move || {
        let mut served = 0;
        for stream in listener.incoming().take(3) {
            let mut stream = stream.unwrap();
            // The whole request (headers, then content-length bytes) first.
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
            served += 1;
        }
        served
    });
    let dir = tempfile::tempdir().unwrap();
    let mut m = member(dir.path(), A, "mac");
    m.edge.url = url;
    let device = m.edge.key().unwrap();
    let err = Member::pull(&m.edge, &device, &Default::default()).err().expect("refused");
    assert!(format!("{err:#}").contains("doesn't move the cursor"), "{err:#}");
    drop(server);
}
