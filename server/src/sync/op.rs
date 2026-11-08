//! A sync op as the edge stores it (docs/edge.md §5a), and what members put
//! inside one (§5b). The canonical encoding and the hash here must be the
//! edge's exactly: edge/test/sync-vectors.json holds ops both test suites check.

use super::crypto::{b64, sha256_hex, unb64};
use anyhow::{Context, Result, anyhow, bail};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) enum Kind {
    #[serde(rename = "put")]
    Put,
    #[serde(rename = "rotate")]
    Rotate,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "member.add")]
    MemberAdd,
    #[serde(rename = "member.remove")]
    MemberRemove,
    #[serde(rename = "rekey")]
    Rekey,
}

impl Kind {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Kind::Put => "put",
            Kind::Rotate => "rotate",
            Kind::Delete => "delete",
            Kind::MemberAdd => "member.add",
            Kind::MemberRemove => "member.remove",
            Kind::Rekey => "rekey",
        }
    }

    /// put, rotate and delete change a secret; the others change the ring.
    pub(crate) fn is_value(self) -> bool {
        matches!(self, Kind::Put | Kind::Rotate | Kind::Delete)
    }
}

/// An op as its author signed it and sent it: exactly the edge's fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Op {
    pub author: String,
    pub seq: u64,
    pub prev: String,
    pub kind: Kind,
    pub key: String,
    pub version: u64,
    pub sealed: String,
    pub wrapped_key: String,
    pub at: u64,
    pub sig: String,
}

/// An op as the edge serves it: as sent, with its hash and its ciphertext's
/// hashes, and without the ciphertext once compacted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Served {
    pub author: String,
    pub seq: u64,
    pub prev: String,
    pub kind: Kind,
    pub key: String,
    pub version: u64,
    pub sealed: Option<String>,
    pub wrapped_key: Option<String>,
    pub at: u64,
    pub sig: String,
    pub hash: String,
    pub sealed_sha256: String,
    pub wrapped_key_sha256: String,
    #[serde(default)]
    pub compacted: bool,
}

/// What `sig` signs and what an op's hash is of (docs/edge.md §5a).
#[allow(clippy::too_many_arguments, reason = "one argument per line of the encoding, in its order")]
pub(crate) fn canonical(author: &str, seq: u64, prev: &str, kind: Kind, key: &str, version: u64, sealed_sha256: &str, wrapped_key_sha256: &str, at: u64) -> String {
    format!("harar-op-v1\n{author}\n{seq}\n{prev}\n{}\n{key}\n{version}\n{sealed_sha256}\n{wrapped_key_sha256}\n{at}", kind.name())
}

impl Op {
    pub(crate) fn canonical(&self) -> String {
        canonical(&self.author, self.seq, &self.prev, self.kind, &self.key, self.version, &sha256_hex(&self.sealed), &sha256_hex(&self.wrapped_key), self.at)
    }

    pub(crate) fn hash(&self) -> String {
        sha256_hex(self.canonical())
    }

    /// Signs the op's fields with the author's device key (raw r || s), in
    /// one go: for tests (members write ops unsigned and sign them later).
    #[cfg(test)]
    #[allow(clippy::too_many_arguments, reason = "one argument per op field, in the edge's order")]
    pub(crate) fn sign(
        author: &str,
        seq: u64,
        prev: &str,
        kind: Kind,
        key: &str,
        version: u64,
        sealed: String,
        wrapped_key: String,
        at: u64,
        signer: &dyn Fn(&[u8]) -> Result<[u8; 64]>,
    ) -> Result<Op> {
        let mut op = Op { author: author.to_owned(), seq, prev: prev.to_owned(), kind, key: key.to_owned(), version, sealed, wrapped_key, at, sig: String::new() };
        op.sig = b64(signer(op.canonical().as_bytes())?);
        Ok(op)
    }
}

impl Served {
    /// The canonical encoding from the served fields. For an op that still
    /// has its ciphertext, the served hashes must be of that ciphertext.
    pub(crate) fn canonical(&self) -> Result<String> {
        if !self.compacted {
            let (Some(sealed), Some(wrapped)) = (&self.sealed, &self.wrapped_key) else {
                bail!("{} op {} has no ciphertext but is not compacted", self.author, self.seq);
            };
            if sha256_hex(sealed) != self.sealed_sha256 || sha256_hex(wrapped) != self.wrapped_key_sha256 {
                bail!("{} op {}'s ciphertext is not what its hashes say", self.author, self.seq);
            }
        }
        Ok(canonical(&self.author, self.seq, &self.prev, self.kind, &self.key, self.version, &self.sealed_sha256, &self.wrapped_key_sha256, self.at))
    }

    /// Checks the hash and the signature against the author's key.
    pub(crate) fn verify(&self, author_key: &VerifyingKey) -> Result<()> {
        let text = self.canonical()?;
        if sha256_hex(&text) != self.hash {
            bail!("{} op {}'s hash is not the hash of the op", self.author, self.seq);
        }
        let sig = Signature::from_slice(&unb64(&self.sig)?).map_err(|_| anyhow!("{} op {}: not a signature", self.author, self.seq))?;
        author_key.verify(text.as_bytes(), &sig).map_err(|_| anyhow!("{} op {} is not signed by its author's key", self.author, self.seq))
    }

    /// The ciphertext, for an op that still has it.
    pub(crate) fn ciphertext(&self) -> Option<(&str, &str)> {
        match (&self.sealed, &self.wrapped_key, self.compacted) {
            (Some(s), Some(w), false) => Some((s, w)),
            _ => None,
        }
    }

    /// Last-write-wins order (docs/edge.md §5a): at, then author, then seq.
    pub(crate) fn rank(&self) -> Rank {
        Rank { at: self.at, author: self.author.clone(), seq: self.seq }
    }
}

impl From<&Op> for Served {
    fn from(op: &Op) -> Served {
        Served {
            author: op.author.clone(),
            seq: op.seq,
            prev: op.prev.clone(),
            kind: op.kind,
            key: op.key.clone(),
            version: op.version,
            sealed: Some(op.sealed.clone()),
            wrapped_key: Some(op.wrapped_key.clone()),
            at: op.at,
            sig: op.sig.clone(),
            hash: op.hash(),
            sealed_sha256: sha256_hex(&op.sealed),
            wrapped_key_sha256: sha256_hex(&op.wrapped_key),
            compacted: false,
        }
    }
}

/// Where a write sits in last-write-wins order. Ordered by field: at, then
/// author id, then seq.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Rank {
    pub at: u64,
    pub author: String,
    pub seq: u64,
}

// ------------------------------------------------------------------ inside

/// Inside a put, rotate or delete's `sealed`: the path, the value (none for
/// a delete) and the hash of the op this write replaced on its author's
/// vault ("" for none), which tells a successor from a concurrent write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValueBody {
    pub path: String,
    pub value: Option<String>,
    #[serde(default)]
    pub base: String,
}

/// Inside a member.add's `sealed` (plain JSON, base64url: a member's public
/// keys aren't secret). By the device itself with no `wrapped_key`, it asks
/// to join; by a member, with the ring key wrapped to `agree_pub`, it adds
/// the device, and a device adding itself so is the ring's founder.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemberBody {
    pub device: String,
    pub name: String,
    /// The device's signing key (its pairing key), raw P-256, base64url.
    pub sign_pub: String,
    /// Its key-agreement key, raw P-256, base64url.
    pub agree_pub: String,
    /// The ring key's epoch the wrap holds (0 in a request).
    pub epoch: u32,
}

/// Inside a member.remove: the device, and its last op that still counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RemoveBody {
    pub device: String,
    pub after: u64,
}

/// Inside a rekey: the new epoch, and its ring key wrapped (ECIES) to each
/// member that remains. The op's `wrapped_key` is the previous ring key
/// sealed under the new one, so a member who has the newest key has them all.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RekeyBody {
    pub epoch: u32,
    pub wraps: BTreeMap<String, String>,
}

pub(crate) fn plain_body<T: Serialize>(body: &T) -> String {
    b64(serde_json::to_vec(body).expect("bodies serialize"))
}

pub(crate) fn read_plain_body<T: for<'de> Deserialize<'de>>(sealed: &str) -> Result<T> {
    serde_json::from_slice(&unb64(sealed)?).context("an op body")
}

/// The texts a member op's `key` is the ring MAC of. They start with the
/// vault's reserved `harar:`, which no synced path has, so none of these is
/// ever a secret's key.
pub(crate) fn add_mac_text(device: &str, epoch: u32) -> String {
    format!("harar:member|add|{device}|{epoch}")
}

pub(crate) fn remove_mac_text(device: &str, after: u64) -> String {
    format!("harar:member|remove|{device}|{after}")
}

pub(crate) fn rekey_mac_text(epoch: u32) -> String {
    format!("harar:member|rekey|{epoch}")
}

/// A join request's `key`: there is no ring key to MAC with yet.
pub(crate) fn request_key(device: &str) -> String {
    b64(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(format!("harar:member|request|{device}"))))
}

/// The associated data of a rekey's previous ring key, sealed under the new.
pub(crate) fn rekey_ad(epoch: u32) -> String {
    format!("harar-rekey|{epoch}")
}
