//! Applying secret ops to the vault, last write wins (docs/edge.md §5b), and
//! turning the vault's own changes into ops.
//!
//! What the vault knows about sync lives inside the vault, under the reserved
//! key `harar:sync`, so it is sealed with the vault: each path's winning op,
//! the versions that lost, and the conflict flags.

use super::crypto::sha256_hex;
use super::op::{Kind, Rank};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// The reserved vault key that holds `VaultMeta`.
pub(crate) const META_KEY: &str = "harar:sync";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct VaultMeta {
    /// The founder of the ring `paths` belong to. Joining another ring
    /// starts `paths` over.
    #[serde(default)]
    pub ring: Option<String>,
    /// Each synced path's current op.
    #[serde(default)]
    pub paths: BTreeMap<String, PathMeta>,
    /// Versions that lost to a concurrent write, kept with their values.
    #[serde(default)]
    pub history: Vec<Lost>,
    #[serde(default)]
    pub conflicts: Vec<Conflict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PathMeta {
    pub version: u64,
    pub hash: String,
    pub rank: Rank,
    pub deleted: bool,
    /// sha256 of the value it set, to tell when the vault has changed since.
    pub value_sha256: String,
    /// Every op hash seen for this path, winning or not.
    #[serde(default)]
    pub known: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Lost {
    pub path: String,
    pub version: u64,
    pub rank: Rank,
    pub hash: String,
    pub value: Option<String>,
    pub lost_to: String,
}

/// Two writes to one path that didn't see each other: which was kept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Conflict {
    pub path: String,
    pub kept: Side,
    pub lost: Side,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Side {
    pub device: String,
    pub seq: u64,
    pub at: u64,
    pub version: u64,
}

impl Side {
    fn of(rank: &Rank, version: u64) -> Side {
        Side { device: rank.author.clone(), seq: rank.seq, at: rank.at, version }
    }
}

/// An opened secret op from another member.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Incoming {
    pub hash: String,
    pub base: String,
    pub rank: Rank,
    pub version: u64,
    pub path: String,
    /// None for a delete.
    pub value: Option<String>,
}

/// A change in the vault that no op records yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Change {
    pub path: String,
    pub kind: Kind,
    pub version: u64,
    pub base: String,
    pub value: Option<String>,
}

fn reserved(key: &str) -> bool {
    key.starts_with("harar:")
}

impl VaultMeta {
    pub(crate) fn read(keys: &HashMap<String, String>) -> VaultMeta {
        keys.get(META_KEY).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default()
    }

    pub(crate) fn write(&self, keys: &mut HashMap<String, String>) {
        keys.insert(META_KEY.into(), serde_json::to_string(self).expect("sync meta serializes"));
    }

    fn known(&self, path: &str, hash: &str) -> bool {
        self.paths.get(path).is_some_and(|m| m.hash == hash || m.known.contains(hash))
    }

    /// What the vault holds that no op says yet: new paths (put), changed
    /// values (rotate) and removed paths (delete). Each change's version is
    /// one past the path's, and its base the op it replaces.
    pub(crate) fn changes(&self, keys: &HashMap<String, String>) -> Vec<Change> {
        let mut out = Vec::new();
        let mut paths: Vec<&String> = keys.keys().filter(|k| !reserved(k)).collect();
        paths.sort();
        for path in paths {
            let value = &keys[path];
            match self.paths.get(path) {
                Some(m) if !m.deleted && m.value_sha256 == sha256_hex(value) => {}
                Some(m) => out.push(Change {
                    path: path.clone(),
                    kind: if m.deleted { Kind::Put } else { Kind::Rotate },
                    version: m.version + 1,
                    base: m.hash.clone(),
                    value: Some(value.clone()),
                }),
                None => out.push(Change { path: path.clone(), kind: Kind::Put, version: 1, base: String::new(), value: Some(value.clone()) }),
            }
        }
        for (path, m) in &self.paths {
            if !m.deleted && !keys.contains_key(path) {
                out.push(Change { path: path.clone(), kind: Kind::Delete, version: m.version + 1, base: m.hash.clone(), value: None });
            }
        }
        out
    }

    /// This member's queued ops were signed again with new seqs (the chain
    /// diverged): their hashes, old to new.
    pub(crate) fn rename(&mut self, renamed: &BTreeMap<String, (String, u64)>) {
        for m in self.paths.values_mut() {
            if let Some((new, seq)) = renamed.get(&m.hash) {
                m.hash = new.clone();
                m.rank.seq = *seq;
            }
            m.known = m.known.iter().map(|h| renamed.get(h).map_or(h, |(new, _)| new).clone()).collect();
        }
    }

    /// Records this member's own op for a change it made.
    pub(crate) fn record_own(&mut self, change: &Change, hash: &str, rank: Rank) {
        let known = self.paths.remove(&change.path).map(|mut m| {
            m.known.insert(m.hash.clone());
            m.known
        });
        self.paths.insert(
            change.path.clone(),
            PathMeta {
                version: change.version,
                hash: hash.to_owned(),
                rank,
                deleted: change.value.is_none(),
                value_sha256: change.value.as_deref().map(sha256_hex).unwrap_or_default(),
                known: known.unwrap_or_default(),
            },
        );
    }

    /// Applies other members' secret ops to `keys`. A write whose base is
    /// the path's current op replaces it. Two writes that didn't see each
    /// other are a conflict: the later by (at, author, seq) is kept, the
    /// other goes to history with its value, and both are flagged. Returns
    /// the paths whose value changed.
    pub(crate) fn apply(&mut self, keys: &mut HashMap<String, String>, incoming: Vec<Incoming>) -> BTreeSet<String> {
        let mut changed = BTreeSet::new();
        let mut waiting = incoming;
        waiting.sort_by(|a, b| a.rank.cmp(&b.rank));
        // A write waits for the op it is based on when that one is in the
        // same batch, so a successor is never mistaken for a conflict.
        while !waiting.is_empty() {
            let pending: BTreeSet<String> = waiting.iter().map(|i| i.hash.clone()).collect();
            let ready = waiting.iter().position(|i| !pending.contains(&i.base)).unwrap_or(0);
            let op = waiting.remove(ready);
            if self.apply_one(keys, op.clone()) {
                changed.insert(op.path);
            }
        }
        changed
    }

    fn apply_one(&mut self, keys: &mut HashMap<String, String>, op: Incoming) -> bool {
        if self.known(&op.path, &op.hash) {
            return false;
        }
        let current = self.paths.get(&op.path).cloned();
        // The value is always the highest-ranked op seen: a successor
        // replaces the op it names only when it also ranks higher (writers
        // make sure it does); otherwise it is judged as concurrent. So the
        // end is the same whatever order ops arrive in.
        let wins = match &current {
            None => true,
            Some(cur) if cur.hash == op.base && op.rank > cur.rank => true,
            Some(cur) => {
                let wins = op.rank > cur.rank;
                let (kept, lost) = if wins { ((&op.rank, op.version), (&cur.rank, cur.version)) } else { ((&cur.rank, cur.version), (&op.rank, op.version)) };
                self.conflicts.push(Conflict { path: op.path.clone(), kept: Side::of(kept.0, kept.1), lost: Side::of(lost.0, lost.1) });
                if wins {
                    self.history.push(Lost {
                        path: op.path.clone(),
                        version: cur.version,
                        rank: cur.rank.clone(),
                        hash: cur.hash.clone(),
                        value: if cur.deleted { None } else { keys.get(&op.path).cloned() },
                        lost_to: op.hash.clone(),
                    });
                } else {
                    self.history.push(Lost { path: op.path.clone(), version: op.version, rank: op.rank.clone(), hash: op.hash.clone(), value: op.value.clone(), lost_to: cur.hash.clone() });
                    self.paths.get_mut(&op.path).expect("current").known.insert(op.hash.clone());
                }
                wins
            }
        };
        if !wins {
            return false;
        }
        let before = keys.get(&op.path).cloned();
        match &op.value {
            Some(value) => keys.insert(op.path.clone(), value.clone()),
            None => keys.remove(&op.path),
        };
        let mut known = current.map(|c| {
            let mut k = c.known;
            k.insert(c.hash);
            k
        }).unwrap_or_default();
        known.insert(op.hash.clone());
        self.paths.insert(
            op.path.clone(),
            PathMeta {
                version: op.version,
                hash: op.hash,
                rank: op.rank,
                deleted: op.value.is_none(),
                value_sha256: op.value.as_deref().map(sha256_hex).unwrap_or_default(),
                known,
            },
        );
        before != op.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rank(at: u64, author: &str, seq: u64) -> Rank {
        Rank { at, author: author.into(), seq }
    }

    fn write(hash: &str, base: &str, r: Rank, version: u64, path: &str, value: Option<&str>) -> Incoming {
        Incoming { hash: hash.into(), base: base.into(), rank: r, version, path: path.into(), value: value.map(Into::into) }
    }

    /// A member's own write, as the agent records it.
    fn own(meta: &mut VaultMeta, keys: &mut HashMap<String, String>, path: &str, value: &str, hash: &str, r: Rank) {
        keys.insert(path.into(), value.into());
        let change = meta.changes(keys).into_iter().find(|c| c.path == path).unwrap();
        meta.record_own(&change, hash, r);
    }

    #[test]
    fn a_successor_replaces_without_a_conflict_in_any_order_and_one_that_ranks_lower_is_concurrent() {
        let a1 = write("h1", "", rank(100, "d-a", 1), 1, "p", Some("one"));
        let a2 = write("h2", "h1", rank(101, "d-b", 1), 2, "p", Some("two"));
        for batch in [vec![a1.clone(), a2.clone()], vec![a2.clone(), a1.clone()]] {
            let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
            meta.apply(&mut keys, batch);
            assert_eq!(keys["p"], "two");
            assert!(meta.conflicts.is_empty());
            assert_eq!(meta.paths["p"].version, 2);
        }
        // A writer never stamps a successor below what it replaces; one that
        // does (a wrong clock, or worse) doesn't get to win by it.
        let behind = write("h3", "h1", rank(50, "d-b", 1), 2, "p", Some("behind"));
        let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
        meta.apply(&mut keys, vec![a1, behind]);
        assert_eq!(keys["p"], "one");
        assert_eq!(meta.conflicts.len(), 1);
    }

    #[test]
    fn concurrent_writes_resolve_the_same_on_both_members_and_both_flag_it() {
        // Both start from h1, then each writes offline: A at t=200, B at t=300.
        let base = write("h1", "", rank(100, "d-a", 1), 1, "p", Some("one"));
        let a_op = write("ha", "h1", rank(200, "d-a", 2), 2, "p", Some("from a"));
        let b_op = write("hb", "h1", rank(300, "d-b", 1), 2, "p", Some("from b"));

        let (mut a, mut a_keys) = (VaultMeta::default(), HashMap::new());
        a.apply(&mut a_keys, vec![base.clone()]);
        own(&mut a, &mut a_keys, "p", "from a", "ha", a_op.rank.clone());
        let (mut b, mut b_keys) = (VaultMeta::default(), HashMap::new());
        b.apply(&mut b_keys, vec![base]);
        own(&mut b, &mut b_keys, "p", "from b", "hb", b_op.rank.clone());

        a.apply(&mut a_keys, vec![b_op]);
        b.apply(&mut b_keys, vec![a_op]);
        assert_eq!((a_keys["p"].as_str(), b_keys["p"].as_str()), ("from b", "from b"), "the later write wins on both");
        for meta in [&a, &b] {
            assert_eq!(meta.conflicts.len(), 1);
            assert_eq!(meta.conflicts[0].kept.device, "d-b");
            assert_eq!(meta.conflicts[0].lost.device, "d-a");
            assert_eq!(meta.history.len(), 1);
            assert_eq!(meta.history[0].value.as_deref(), Some("from a"), "the loser is kept, with its value");
            assert_eq!(meta.paths["p"].hash, "hb");
        }
        // Nothing left over for either to send.
        assert!(a.changes(&a_keys).is_empty());
        assert!(b.changes(&b_keys).is_empty());
    }

    #[test]
    fn last_write_wins_by_at_then_author_then_seq() {
        for (x, y, winner) in [
            (rank(5, "d-a", 9), rank(6, "d-a", 1), "y"),
            (rank(5, "d-b", 1), rank(5, "d-a", 9), "x"),
            (rank(5, "d-a", 2), rank(5, "d-a", 3), "y"),
        ] {
            let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
            meta.apply(&mut keys, vec![write("hx", "", x, 1, "p", Some("x")), write("hy", "", y, 1, "p", Some("y"))]);
            assert_eq!(keys["p"], winner);
            assert_eq!(meta.conflicts.len(), 1);
        }
    }

    #[test]
    fn an_op_seen_twice_changes_nothing_and_a_delete_is_a_version_too() {
        let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
        let put = write("h1", "", rank(1, "d-a", 1), 1, "p", Some("v"));
        assert_eq!(meta.apply(&mut keys, vec![put.clone()]).len(), 1);
        assert!(meta.apply(&mut keys, vec![put]).is_empty());
        meta.apply(&mut keys, vec![write("h2", "h1", rank(2, "d-a", 2), 2, "p", None)]);
        assert!(meta.conflicts.is_empty(), "a successor that ranks higher is no conflict");
        assert!(!keys.contains_key("p"));
        assert!(meta.paths["p"].deleted);
        assert!(meta.changes(&keys).is_empty(), "a delete applied is not a change to send");
    }

    #[test]
    fn local_changes_are_puts_rotates_and_deletes_based_on_what_they_replace() {
        let (mut meta, mut keys) = (VaultMeta::default(), HashMap::new());
        keys.insert("a".to_owned(), "1".to_owned());
        keys.insert("harar:hosts".to_owned(), "{}".to_owned());
        let changes = meta.changes(&keys);
        assert_eq!(changes, vec![Change { path: "a".into(), kind: Kind::Put, version: 1, base: String::new(), value: Some("1".into()) }], "reserved keys never sync");
        meta.record_own(&changes[0], "h1", rank(1, "d-me", 1));
        keys.insert("a".into(), "2".into());
        let rotate = meta.changes(&keys);
        assert_eq!((rotate[0].kind, rotate[0].version, rotate[0].base.as_str()), (Kind::Rotate, 2, "h1"));
        meta.record_own(&rotate[0], "h2", rank(2, "d-me", 2));
        keys.remove("a");
        let delete = meta.changes(&keys);
        assert_eq!((delete[0].kind, delete[0].version, delete[0].base.as_str(), delete[0].value.clone()), (Kind::Delete, 3, "h2", None));
        meta.record_own(&delete[0], "h3", rank(3, "d-me", 3));
        assert!(meta.changes(&keys).is_empty());
        // Our own ops, pulled back, are already known.
        assert!(meta.known("a", "h1") && meta.known("a", "h3"));
    }
}
