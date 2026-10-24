//! Envelope encryption for the primary's secrets (architecture, section 7).
//!
//! Each secret version gets a fresh data key. The value is encrypted with the
//! data key; the data key is encrypted ("wrapped") with the master key. Both
//! are bound to the secret's org, path and version, so a ciphertext copied to
//! another row, path or version fails to open. XChaCha20-Poly1305 throughout.

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use std::fmt;
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const VALUE_CONTEXT: &[u8] = b"harar.secret-value.v1";
const DATA_KEY_CONTEXT: &[u8] = b"harar.data-key.v1";
const HEAD_CONTEXT: &[u8] = b"harar.secret-head.v1";

/// The key that wraps every data key. Lives only in the primary's memory.
pub struct MasterKey {
    id: String,
    key: Zeroizing<[u8; 32]>,
}

impl MasterKey {
    pub fn generate(id: impl Into<String>) -> MasterKey {
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        MasterKey { id: id.into(), key: Zeroizing::new(key.into()) }
    }

    pub fn from_bytes(id: impl Into<String>, bytes: [u8; 32]) -> MasterKey {
        MasterKey { id: id.into(), key: Zeroizing::new(bytes) }
    }

    /// Which master key wrapped a data key, so rotation knows what to rewrap.
    pub fn id(&self) -> &str {
        &self.id
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.key.as_ref().into())
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterKey").field("id", &self.id).finish_non_exhaustive()
    }
}

/// What Postgres stores for one secret version. None of it decrypts alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// nonce || XChaCha20-Poly1305(data key, value)
    pub ciphertext: Vec<u8>,
    /// nonce || XChaCha20-Poly1305(master key, data key)
    pub wrapped_key: Vec<u8>,
    pub master_key_id: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Wrapped by a master key other than this one.
    WrongMasterKey,
    /// Doesn't decrypt for this org, path and version: moved, edited, or damaged.
    Tampered,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            OpenError::WrongMasterKey => "wrapped by a different master key",
            OpenError::Tampered => "does not decrypt for this org, path and version",
        })
    }
}

impl std::error::Error for OpenError {}

/// `context || len(org) || org || len(path) || path || version`. Lengths make
/// the encoding unambiguous: no two (org, path) pairs encode the same.
fn bound_to(context: &[u8], org: &str, path: &str, version: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len() + org.len() + path.len() + 24);
    out.extend_from_slice(context);
    for part in [org.as_bytes(), path.as_bytes()] {
        out.extend_from_slice(&(part.len() as u64).to_be_bytes());
        out.extend_from_slice(part);
    }
    out.extend_from_slice(&version.to_be_bytes());
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

fn data_key_aad(master: &MasterKey, org: &str, path: &str, version: u64) -> Vec<u8> {
    let mut aad = bound_to(DATA_KEY_CONTEXT, org, path, version);
    aad.extend_from_slice(master.id.as_bytes());
    aad
}

pub fn seal(master: &MasterKey, org: &str, path: &str, version: u64, value: &[u8]) -> Sealed {
    let data_key = Zeroizing::new(XChaCha20Poly1305::generate_key(&mut OsRng));
    let ciphertext = encrypt(&XChaCha20Poly1305::new(&data_key), value, &bound_to(VALUE_CONTEXT, org, path, version));
    let wrapped_key = encrypt(&master.cipher(), &data_key, &data_key_aad(master, org, path, version));
    Sealed { ciphertext, wrapped_key, master_key_id: master.id.clone() }
}

fn unwrap_key(master: &MasterKey, org: &str, path: &str, version: u64, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    if sealed.master_key_id != master.id {
        return Err(OpenError::WrongMasterKey);
    }
    let data_key = decrypt(&master.cipher(), &sealed.wrapped_key, &data_key_aad(master, org, path, version))?;
    if data_key.len() != 32 {
        return Err(OpenError::Tampered);
    }
    Ok(data_key)
}

pub fn open(master: &MasterKey, org: &str, path: &str, version: u64, sealed: &Sealed) -> Result<Zeroizing<Vec<u8>>, OpenError> {
    let data_key = unwrap_key(master, org, path, version, sealed)?;
    let cipher = XChaCha20Poly1305::new(data_key.as_slice().into());
    decrypt(&cipher, &sealed.ciphertext, &bound_to(VALUE_CONTEXT, org, path, version))
}

/// Rewraps a version's data key under a new master key. The value's
/// ciphertext is untouched, so rotation never re-encrypts secrets.
pub fn rewrap(old: &MasterKey, new: &MasterKey, org: &str, path: &str, version: u64, sealed: &Sealed) -> Result<Sealed, OpenError> {
    let data_key = unwrap_key(old, org, path, version, sealed)?;
    Ok(Sealed {
        ciphertext: sealed.ciphertext.clone(),
        wrapped_key: encrypt(&new.cipher(), &data_key, &data_key_aad(new, org, path, version)),
        master_key_id: new.id.clone(),
    })
}

/// A tag over (org, path, latest version), so the primary notices when the
/// newest version disappears or a head is copied from another path.
pub fn seal_head(master: &MasterKey, org: &str, path: &str, version: u64) -> Vec<u8> {
    encrypt(&master.cipher(), &[], &bound_to(HEAD_CONTEXT, org, path, version))
}

pub fn head_is_genuine(master: &MasterKey, org: &str, path: &str, version: u64, seal: &[u8]) -> bool {
    decrypt(&master.cipher(), seal, &bound_to(HEAD_CONTEXT, org, path, version)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_value_opens_only_where_it_was_sealed() {
        let master = MasterKey::generate("mk-1");
        let sealed = seal(&master, "gg.addis", "prod/site/DATABASE_URL", 7, b"postgres://real");
        assert_eq!(open(&master, "gg.addis", "prod/site/DATABASE_URL", 7, &sealed).unwrap().as_slice(), b"postgres://real");
        assert!(!sealed.ciphertext.windows(15).any(|w| w == b"postgres://real"));

        for (org, path, version) in [("gg.addis", "prod/site/DATABASE_URL", 6), ("gg.addis", "prod/site/API_KEY", 7), ("com.acme", "prod/site/DATABASE_URL", 7)] {
            assert_eq!(open(&master, org, path, version, &sealed).unwrap_err(), OpenError::Tampered, "{org} {path} {version}");
        }
        assert_eq!(open(&MasterKey::generate("mk-1"), "gg.addis", "prod/site/DATABASE_URL", 7, &sealed).unwrap_err(), OpenError::Tampered);
        assert_eq!(open(&MasterKey::generate("mk-2"), "gg.addis", "prod/site/DATABASE_URL", 7, &sealed).unwrap_err(), OpenError::WrongMasterKey);

        let mut flipped = sealed.clone();
        *flipped.ciphertext.last_mut().unwrap() ^= 1;
        assert_eq!(open(&master, "gg.addis", "prod/site/DATABASE_URL", 7, &flipped).unwrap_err(), OpenError::Tampered);
    }

    #[test]
    fn org_and_path_boundaries_cannot_be_shifted() {
        // "gg.addis" + "x/y" and "gg.addisx" + "/y" must not bind the same.
        assert_ne!(bound_to(VALUE_CONTEXT, "gg.addis", "x/y", 1), bound_to(VALUE_CONTEXT, "gg.addisx", "/y", 1));
    }

    #[test]
    fn rotation_rewraps_the_key_and_leaves_the_ciphertext_alone() {
        let old = MasterKey::generate("mk-1");
        let new = MasterKey::generate("mk-2");
        let sealed = seal(&old, "gg.addis", "prod/a", 1, b"value");
        let rotated = rewrap(&old, &new, "gg.addis", "prod/a", 1, &sealed).unwrap();
        assert_eq!(rotated.ciphertext, sealed.ciphertext);
        assert_eq!(rotated.master_key_id, "mk-2");
        assert_eq!(open(&new, "gg.addis", "prod/a", 1, &rotated).unwrap().as_slice(), b"value");
        assert_eq!(open(&old, "gg.addis", "prod/a", 1, &rotated).unwrap_err(), OpenError::WrongMasterKey);
    }

    #[test]
    fn a_head_tag_is_tied_to_its_path_and_version() {
        let master = MasterKey::generate("mk-1");
        let tag = seal_head(&master, "gg.addis", "prod/a", 3);
        assert!(head_is_genuine(&master, "gg.addis", "prod/a", 3, &tag));
        assert!(!head_is_genuine(&master, "gg.addis", "prod/a", 2, &tag));
        assert!(!head_is_genuine(&master, "gg.addis", "prod/b", 3, &tag));
        assert!(!head_is_genuine(&MasterKey::generate("mk-1"), "gg.addis", "prod/a", 3, &tag));
    }
}
