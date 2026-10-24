//! Envelope encryption for the primary's secrets (architecture, section 7).
//!
//! Each secret version gets a fresh data key. The value is encrypted with the
//! data key; the data key is encrypted ("wrapped") with a key derived from the
//! master key. Both are bound to every column of the version's row (org, path,
//! version, whether it is a deletion, who wrote it, its txn), so changing any
//! column, or moving a ciphertext to another row, fails to open.
//! XChaCha20-Poly1305 for encryption; HMAC-SHA256 for tags.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fmt;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const VALUE_CONTEXT: &[u8] = b"harar.secret-value.v1";
const DATA_KEY_CONTEXT: &[u8] = b"harar.data-key.v1";
const HEAD_CONTEXT: &[u8] = b"harar.secret-head.v1";
const LEAF_CONTEXT: &[u8] = b"harar.secret-leaf.v1";
const STATE_CONTEXT: &[u8] = b"harar.store-state.v1";
const ANCHOR_CONTEXT: &[u8] = b"harar.store-anchor.v1";

type HmacSha256 = Hmac<Sha256>;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

/// The key everything else comes from. Lives only in the primary's memory.
/// Wrapping and tagging use separate keys derived from it.
pub struct MasterKey {
    id: String,
    wrap: Zeroizing<[u8; 32]>,
    tag: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    pub fn generate(id: impl Into<String>) -> MasterKey {
        let key = Zeroizing::new(<[u8; 32]>::from(XChaCha20Poly1305::generate_key(&mut OsRng)));
        MasterKey::from_secret(id, key.as_slice())
    }

    pub fn from_bytes(id: impl Into<String>, bytes: [u8; 32]) -> MasterKey {
        MasterKey::from_secret(id, Zeroizing::new(bytes).as_slice())
    }

    pub fn from_secret(id: impl Into<String>, secret: &[u8]) -> MasterKey {
        MasterKey {
            id: id.into(),
            wrap: Zeroizing::new(hmac(secret, &[b"harar.store-wrap-key.v1"])),
            tag: Zeroizing::new(hmac(secret, &[b"harar.store-tag-key.v1"])),
        }
    }

    /// Which master key wrapped a data key, so rotation knows what to rewrap.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.wrap.as_ref().into())
    }

    fn tag(&self, parts: &[&[u8]]) -> [u8; 32] {
        hmac(self.tag.as_ref(), parts)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey").field("id", &self.id).finish_non_exhaustive()
    }
}

/// Every column of a version's row other than the ciphertexts themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Row<'a> {
    pub org: &'a str,
    pub path: &'a str,
    pub version: u64,
    pub deleted: bool,
    pub written_by: &'a str,
    pub txn: Option<&'a str>,
}

/// What Postgres stores for one secret version. None of it decrypts alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// nonce || XChaCha20-Poly1305(data key, value)
    pub ciphertext: Vec<u8>,
    /// nonce || XChaCha20-Poly1305(wrap key, data key)
    pub wrapped_key: Vec<u8>,
    pub master_key_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Wrapped by a master key other than this one.
    WrongMasterKey,
    /// Doesn't decrypt for this row: moved, edited, or damaged.
    Tampered,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpenError::WrongMasterKey => "wrapped by a different master key",
            OpenError::Tampered => "does not decrypt for this row",
        })
    }
}

impl std::error::Error for OpenError {}

/// Appends `len || bytes`, so no two field lists encode the same.
fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn path_and_version(context: &[u8], org: &str, path: &str, version: u64) -> Vec<u8> {
    let mut out = context.to_vec();
    field(&mut out, org.as_bytes());
    field(&mut out, path.as_bytes());
    out.extend_from_slice(&version.to_be_bytes());
    out
}

fn bound_to(context: &[u8], row: &Row<'_>) -> Vec<u8> {
    let mut out = path_and_version(context, row.org, row.path, row.version);
    out.push(u8::from(row.deleted));
    field(&mut out, row.written_by.as_bytes());
    match row.txn {
        None => out.push(0),
        Some(txn) => {
            out.push(1);
            field(&mut out, txn.as_bytes());
        }
    }
    out
}

fn encrypt(cipher: &XChaCha20Poly1305, message: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(&nonce, Payload { msg: message, aad }).expect("XChaCha20-Poly1305 encrypts any length"));
    out
}

fn decrypt(cipher: &XChaCha20Poly1305, sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if sealed.len() < NONCE_LEN {
        return Err(OpenError::Tampered);
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad })
        .map(Zeroizing::new)
        .map_err(|_| OpenError::Tampered)
}

fn data_key_aad(master: &MasterKey, row: &Row<'_>) -> Vec<u8> {
    let mut aad = bound_to(DATA_KEY_CONTEXT, row);
    field(&mut aad, master.id.as_bytes());
    aad
}

pub fn seal(master: &MasterKey, row: &Row<'_>, value: &[u8]) -> Sealed {
    let data_key = Zeroizing::new(XChaCha20Poly1305::generate_key(&mut OsRng));
    let ciphertext = encrypt(&XChaCha20Poly1305::new(&data_key), value, &bound_to(VALUE_CONTEXT, row));
    let wrapped_key = encrypt(&master.cipher(), &data_key, &data_key_aad(master, row));
    Sealed { ciphertext, wrapped_key, master_key_id: master.id.clone() }
}

fn unwrap_key(master: &MasterKey, row: &Row<'_>, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if sealed.master_key_id != master.id {
        return Err(OpenError::WrongMasterKey);
    }
    let data_key = decrypt(&master.cipher(), &sealed.wrapped_key, &data_key_aad(master, row))?;
    if data_key.len() != 32 {
        return Err(OpenError::Tampered);
    }
    Ok(data_key)
}

pub fn open(master: &MasterKey, row: &Row<'_>, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let data_key = unwrap_key(master, row, sealed)?;
    let cipher = XChaCha20Poly1305::new(data_key.as_slice().into());
    decrypt(&cipher, &sealed.ciphertext, &bound_to(VALUE_CONTEXT, row))
}

/// Rewraps a version's data key under a new master key. The value's
/// ciphertext is untouched, so rotation never re-encrypts secrets. Heads and
/// the store state carry tags from the old key and must be re-tagged too.
pub fn rewrap(old: &MasterKey, new: &MasterKey, row: &Row<'_>, sealed: &Sealed) -> Result<Sealed, OpenError> {
    let data_key = unwrap_key(old, row, sealed)?;
    Ok(Sealed {
        ciphertext: sealed.ciphertext.clone(),
        wrapped_key: encrypt(&new.cipher(), &data_key, &data_key_aad(new, row)),
        master_key_id: new.id.clone(),
    })
}

/// What a version's row holds, hashed: its ciphertexts and master key id.
/// Heads are bound to it, so a version deleted and written again is a
/// different head even with the same number.
pub fn content_hash(sealed: &Sealed) -> [u8; 32] {
    let mut out = Vec::with_capacity(sealed.ciphertext.len() + sealed.wrapped_key.len() + 64);
    field(&mut out, &sealed.ciphertext);
    field(&mut out, &sealed.wrapped_key);
    field(&mut out, sealed.master_key_id.as_bytes());
    Sha256::digest(&out).into()
}

/// The stored tag on a path's head: (org, path, latest version, its content).
pub fn head_tag(master: &MasterKey, org: &str, path: &str, version: u64, content: &[u8; 32]) -> [u8; 32] {
    master.tag(&[&path_and_version(HEAD_CONTEXT, org, path, version), content])
}

/// A head's share of the store digest. Never stored, so nobody without the
/// key can pick heads whose shares cancel out.
pub fn head_leaf(master: &MasterKey, org: &str, path: &str, version: u64, content: &[u8; 32]) -> [u8; 32] {
    master.tag(&[&path_and_version(LEAF_CONTEXT, org, path, version), content])
}

/// XOR of every head's leaf: changing, adding or removing any head changes it.
pub fn xor_into(digest: &mut [u8; 32], leaf: &[u8; 32]) {
    for (byte, other) in digest.iter_mut().zip(leaf) {
        *byte ^= other;
    }
}

/// The tag on the store's state: how many writes it has seen, and its digest.
pub fn state_tag(master: &MasterKey, seq: u64, digest: &[u8; 32]) -> [u8; 32] {
    master.tag(&[STATE_CONTEXT, &seq.to_be_bytes(), digest])
}

/// The tag on the anchor file the primary keeps outside Postgres.
pub fn anchor_tag(master: &MasterKey, seq: u64) -> [u8; 32] {
    master.tag(&[ANCHOR_CONTEXT, &seq.to_be_bytes()])
}

/// Compares tags without leaking where they differ.
pub fn tags_match(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row<'a>(org: &'a str, path: &'a str, version: u64) -> Row<'a> {
        Row { org, path, version, deleted: false, written_by: "gg.addis.human.sami", txn: Some("01jbx5") }
    }

    #[test]
    fn a_sealed_value_opens_only_for_its_own_row() {
        let master = MasterKey::generate("mk-1");
        let here = row("gg.addis", "prod/site/DATABASE_URL", 7);
        let sealed = seal(&master, &here, b"postgres://real");
        assert_eq!(open(&master, &here, &sealed).unwrap().as_slice(), b"postgres://real");
        assert!(!sealed.ciphertext.windows(15).any(|w| w == b"postgres://real"));

        let elsewhere = [
            Row { version: 6, ..here },
            Row { path: "prod/site/API_KEY", ..here },
            Row { org: "com.acme", ..here },
            Row { deleted: true, ..here },
            Row { written_by: "gg.addis.agent.ava", ..here },
            Row { txn: None, ..here },
            Row { txn: Some("01jbx6"), ..here },
        ];
        for other in elsewhere {
            assert_eq!(open(&master, &other, &sealed).unwrap_err(), OpenError::Tampered, "{other:?}");
        }
        assert_eq!(open(&MasterKey::generate("mk-1"), &here, &sealed).unwrap_err(), OpenError::Tampered);
        assert_eq!(open(&MasterKey::generate("mk-2"), &here, &sealed).unwrap_err(), OpenError::WrongMasterKey);

        let mut flipped = sealed.clone();
        *flipped.ciphertext.last_mut().unwrap() ^= 1;
        assert_eq!(open(&master, &here, &flipped).unwrap_err(), OpenError::Tampered);
    }

    #[test]
    fn field_boundaries_cannot_be_shifted() {
        let a = Row { org: "gg.addis", path: "x/y", ..row("", "", 1) };
        let b = Row { org: "gg.addisx", path: "/y", ..row("", "", 1) };
        assert_ne!(bound_to(VALUE_CONTEXT, &a), bound_to(VALUE_CONTEXT, &b));
        let c = Row { written_by: "ab", txn: Some("c"), ..row("o.o", "p", 1) };
        let d = Row { written_by: "a", txn: Some("bc"), ..row("o.o", "p", 1) };
        assert_ne!(bound_to(VALUE_CONTEXT, &c), bound_to(VALUE_CONTEXT, &d));
    }

    #[test]
    fn rotation_rewraps_the_key_and_leaves_the_ciphertext_alone() {
        let old = MasterKey::generate("mk-1");
        let new = MasterKey::generate("mk-2");
        let here = row("gg.addis", "prod/a", 1);
        let sealed = seal(&old, &here, b"value");
        let rotated = rewrap(&old, &new, &here, &sealed).unwrap();
        assert_eq!(rotated.ciphertext, sealed.ciphertext);
        assert_eq!(rotated.master_key_id, "mk-2");
        assert_eq!(open(&new, &here, &rotated).unwrap().as_slice(), b"value");
        assert_eq!(open(&old, &here, &rotated).unwrap_err(), OpenError::WrongMasterKey);
    }

    #[test]
    fn tags_depend_on_the_key_and_everything_they_cover() {
        let master = MasterKey::from_bytes("mk-1", [1; 32]);
        let other = MasterKey::from_bytes("mk-1", [2; 32]);
        let content = [9; 32];
        let tag = head_tag(&master, "gg.addis", "prod/a", 3, &content);
        assert_eq!(tag, head_tag(&master, "gg.addis", "prod/a", 3, &content));
        for different in [
            head_tag(&master, "gg.addis", "prod/a", 2, &content),
            head_tag(&master, "gg.addis", "prod/b", 3, &content),
            head_tag(&master, "gg.addis", "prod/a", 3, &[8; 32]),
            head_tag(&other, "gg.addis", "prod/a", 3, &content),
            head_leaf(&master, "gg.addis", "prod/a", 3, &content),
        ] {
            assert_ne!(tag, different);
        }
        assert_ne!(state_tag(&master, 1, &[0; 32]), state_tag(&master, 2, &[0; 32]));
        assert_ne!(anchor_tag(&master, 1), state_tag(&master, 1, &[0; 32]));
        assert!(tags_match(&tag, &tag) && !tags_match(&tag, &head_tag(&master, "gg.addis", "prod/a", 2, &content)) && !tags_match(&tag, &tag[..31]));
        // A head's digest share covers its content too, so a version deleted
        // and written again never cancels out of the digest.
        assert_ne!(head_leaf(&master, "gg.addis", "prod/a", 3, &content), head_leaf(&master, "gg.addis", "prod/a", 3, &[8; 32]));
        // Two seals of the same value are different content.
        let row = row("gg.addis", "prod/a", 1);
        assert_ne!(content_hash(&seal(&master, &row, b"v")), content_hash(&seal(&master, &row, b"v")));
        // The wrap key and tag key are not the master secret or each other.
        assert_ne!(*master.wrap, [1; 32]);
        assert_ne!(*master.wrap, *master.tag);
    }
}
