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
/// a delete), the hash of the op this write replaced on its author's vault
/// ("" for none), which tells a successor from a concurrent write, and the
/// head of the membership log it was written under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValueBody {
    pub path: String,
    pub value: Option<String>,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub head: String,
}

/// A device and its two public keys (raw P-256, base64url).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MemberKeys {
    pub device: String,
    pub name: String,
    /// Its signing key (its pairing key).
    pub sign_pub: String,
    /// Its key-agreement key.
    pub agree_pub: String,
}

/// A removed device, and the newest of its ops that still counts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Removed {
    pub device: String,
    pub after: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum EntryType {
    Found,
    Add,
    Remove,
    Transfer,
}

/// An entry of the membership log (docs/edge.md §5b), the plain JSON
/// (base64url) of a `member.add` (found, add, transfer) or `rekey` (remove)
/// op's `sealed`. Only the authority writes one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Entry {
    #[serde(rename = "type")]
    pub what: EntryType,
    /// Its place in the log.
    pub n: u64,
    /// The head of entry n - 1 ("" for found).
    pub prev: String,
    /// The epoch after this entry, and its key's id (`ring_id`).
    pub epoch: u32,
    pub id: String,
    /// found and add: the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member: Option<MemberKeys>,
    /// remove: the devices removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed: Vec<Removed>,
    /// transfer: the device that is authority from here on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// The epoch's key, wrapped to each device that gets it here.
    #[serde(default)]
    pub wraps: BTreeMap<String, String>,
}

/// A device's request to join: its own `member.add` of this. It certifies
/// nothing; it only lists the device, for the authority to approve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Request {
    #[serde(rename = "type")]
    pub what: RequestType,
    pub member: MemberKeys,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum RequestType {
    Request,
}

pub(crate) fn plain_body<T: Serialize>(body: &T) -> String {
    b64(serde_json::to_vec(body).expect("bodies serialize"))
}

pub(crate) fn read_plain_body<T: for<'de> Deserialize<'de>>(sealed: &str) -> Result<T> {
    serde_json::from_slice(&unb64(sealed)?).context("an op body")
}

/// A log entry's head: the hash of its `sealed` text, whatever op carries it.
pub(crate) fn head_of(sealed: &str) -> String {
    sha256_hex(format!("harar-log-v1\n{sealed}"))
}

/// A log entry op's `key`: opaque, from its head.
pub(crate) fn entry_key(head: &str) -> String {
    b64(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(format!("harar:log|{head}"))))
}

/// What a ring key's id is the MAC of, under that key.
pub(crate) fn ring_id_text(epoch: u32) -> String {
    format!("harar:member|ring-id|{epoch}")
}

/// A join request's `key`.
pub(crate) fn request_key(device: &str) -> String {
    b64(sha2::Digest::finalize(<sha2::Sha256 as sha2::Digest>::new_with_prefix(format!("harar:member|request|{device}"))))
}

/// The associated data of a rekey's previous ring key, sealed under the new.
pub(crate) fn rekey_ad(epoch: u32) -> String {
    format!("harar-rekey|{epoch}")
}
