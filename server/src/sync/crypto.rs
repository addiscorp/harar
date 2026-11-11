//! The cryptography of a sync member (docs/edge.md §5b): the ring key, a
//! secret version's data key and seal, the HMAC that names a secret on the
//! edge, and ECIES to a member's key-agreement key.
//!
//! ECIES is Apple's `ECIESEncryptionCofactorVariableIVX963SHA256AESGCM`, the
//! one `enclave.rs` uses: so a ring key wrapped here to a Mac's Secure Enclave
//! key opens there, and one wrapped on a Mac to a file key opens here.

use aes_gcm::aead::consts::U16;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, AesGcm};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use p256::elliptic_curve::rand_core::{OsRng, RngCore};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// AES-128-GCM with a 16-byte nonce, as Apple's variable-IV ECIES uses for
/// a P-256 key.
type Aes128Gcm16 = AesGcm<aes::Aes128, U16>;

/// A 32-byte symmetric key that is wiped when dropped.
pub(crate) type Key32 = Zeroizing<[u8; 32]>;

pub(crate) fn random_key() -> Key32 {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *key);
    key
}

pub(crate) fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn unb64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text).map_err(|_| anyhow!("not base64url"))
}

pub(crate) fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex(Sha256::digest(data.as_ref()))
}

/// One of the ring key's subkeys: HKDF-SHA256 (salt `harar-ring-v1`) with
/// the use as info, so names, membership MACs and wraps never share a key.
fn subkey(ring: &[u8; 32], info: &str) -> Key32 {
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(b"harar-ring-v1"), ring).expand(info.as_bytes(), &mut *out).expect("32 bytes is a valid HKDF length");
    out
}

fn hmac_b64(key: &[u8], text: &str) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(text.as_bytes());
    b64(mac.finalize().into_bytes())
}

/// A secret's `key` on the edge: HMAC-SHA256 of its path, under the ring's
/// name subkey, base64url.
pub(crate) fn name_mac(ring: &[u8; 32], path: &str) -> String {
    hmac_b64(&*subkey(ring, "harar-ring-name"), path)
}

/// A ring op's `key`: the proof its author holds the ring, under the ring's
/// member subkey.
pub(crate) fn member_mac(ring: &[u8; 32], text: &str) -> String {
    hmac_b64(&*subkey(ring, "harar-ring-member"), text)
}

/// The ring's wrap subkey: it wraps data keys, and a rekey's previous key.
pub(crate) fn wrap_key(ring: &[u8; 32]) -> Key32 {
    subkey(ring, "harar-ring-wrap")
}

const RING_WRAP: &[u8] = b"harar-ring-wrap-v1\n";

/// A ring key wrapped (ECIES) to `device`'s key-agreement key. Apple's
/// ECIES takes no associated data, so the epoch and the recipient go inside
/// the sealed text, which AES-GCM authenticates, and unwrapping checks them.
pub(crate) fn wrap_ring(recipient: &PublicKey, epoch: u32, device: &str, key: &[u8; 32]) -> Vec<u8> {
    wrap_ring_with(recipient, epoch, device, key, &SecretKey::random(&mut OsRng))
}

pub(crate) fn wrap_ring_with(recipient: &PublicKey, epoch: u32, device: &str, key: &[u8; 32], ephemeral: &SecretKey) -> Vec<u8> {
    let mut plain = Zeroizing::new(Vec::with_capacity(RING_WRAP.len() + 4 + device.len() + 1 + 32));
    plain.extend_from_slice(RING_WRAP);
    plain.extend_from_slice(&epoch.to_be_bytes());
    plain.extend_from_slice(device.as_bytes());
    plain.push(b'\n');
    plain.extend_from_slice(key);
    ecies_seal_with(recipient, &plain, ephemeral)
}

/// The ring key in an opened wrap, if it was wrapped for this epoch and device.
pub(crate) fn unwrapped_ring(plain: &[u8], epoch: u32, device: &str) -> Option<Key32> {
    let rest = plain.strip_prefix(RING_WRAP)?;
    let rest = rest.strip_prefix(epoch.to_be_bytes().as_slice())?;
    let rest = rest.strip_prefix(device.as_bytes())?;
    let rest = rest.strip_prefix(b"\n")?;
    let key: [u8; 32] = rest.try_into().ok()?;
    Some(Zeroizing::new(key))
}

/// 32 hex (128 bits) in groups of four, as a person reads and compares them.
fn grouped(hash_hex: &str) -> String {
    hash_hex.as_bytes()[..32].chunks(4).map(|c| std::str::from_utf8(c).expect("hex")).collect::<Vec<_>>().join("-")
}

/// A device's fingerprint, over its signing and key-agreement keys: what
/// `harar edge sync approve` checks.
pub(crate) fn device_fingerprint(sign_pub: &[u8], agree_pub: &[u8]) -> String {
    grouped(&sha256_hex([b"harar-device-fp-v1\n".as_slice(), sign_pub, agree_pub].concat()))
}

/// A ring's fingerprint, over its founder's two keys: what a joiner pins
/// with `harar edge sync trust` before it takes any grant.
pub(crate) fn ring_fingerprint(sign_pub: &[u8], agree_pub: &[u8]) -> String {
    grouped(&sha256_hex([b"harar-ring-fp-v1\n".as_slice(), sign_pub, agree_pub].concat()))
}

/// A fingerprint as typed: any case, dashes and spaces optional. None
/// unless it is 32 hex.
pub(crate) fn normal_fingerprint(text: &str) -> Option<String> {
    let bare: String = text.chars().filter(|c| *c != '-' && !c.is_whitespace()).collect::<String>().to_ascii_lowercase();
    (bare.len() == 32 && bare.bytes().all(|b| b.is_ascii_hexdigit())).then(|| grouped(&bare))
}

/// AES-256-GCM: `iv (12) || ciphertext || tag`, as the edge seals.
pub(crate) fn gcm_seal(key: &[u8; 32], plain: &[u8], ad: &[u8], iv: [u8; 12]) -> Vec<u8> {
    let cipher = Aes256Gcm::new(key.into());
    let sealed = cipher.encrypt((&iv).into(), Payload { msg: plain, aad: ad }).expect("AES-GCM seals any length we use");
    [iv.as_slice(), &sealed].concat()
}

pub(crate) fn gcm_open(key: &[u8; 32], sealed: &[u8], ad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 12 + 16 {
        bail!("too short to be sealed");
    }
    let cipher = Aes256Gcm::new(key.into());
    let (iv, body) = sealed.split_at(12);
    cipher
        .decrypt(iv.into(), Payload { msg: body, aad: ad })
        .map(Zeroizing::new)
        .map_err(|_| anyhow!("does not open with this key"))
}

pub(crate) fn random_iv() -> [u8; 12] {
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    iv
}

/// The associated data of a secret version's seal and its data key's wrap:
/// `harar-op|<key>|<version>`, where key is the HMAC of the path. A seal
/// moved to another op fails to open; after opening, the member checks the
/// path inside against `key`.
pub(crate) fn value_ad(key: &str, version: u64) -> String {
    format!("harar-op|{key}|{version}")
}

/// A secret version sealed for the ring: (sealed, wrapped_key), both
/// base64url. A fresh data key seals `plain`; the ring's wrap subkey wraps it.
pub(crate) fn seal_value(ring: &[u8; 32], key: &str, version: u64, plain: &[u8], ivs: Option<([u8; 32], [u8; 12], [u8; 12])>) -> (String, String) {
    let ad = value_ad(key, version);
    let (data_key, iv1, iv2) = match ivs {
        Some((k, a, b)) => (Zeroizing::new(k), a, b),
        None => (random_key(), random_iv(), random_iv()),
    };
    let sealed = gcm_seal(&data_key, plain, ad.as_bytes(), iv1);
    let wrapped = gcm_seal(&wrap_key(ring), &*data_key, ad.as_bytes(), iv2);
    (b64(sealed), b64(wrapped))
}

/// Opens what `seal_value` sealed, or fails if `ring` isn't the key.
pub(crate) fn open_value(ring: &[u8; 32], key: &str, version: u64, sealed: &str, wrapped_key: &str) -> Result<Zeroizing<Vec<u8>>> {
    let ad = value_ad(key, version);
    let raw = gcm_open(&wrap_key(ring), &unb64(wrapped_key)?, ad.as_bytes())?;
    let data_key: [u8; 32] = raw.as_slice().try_into().map_err(|_| anyhow!("a data key is 32 bytes"))?;
    let data_key = Zeroizing::new(data_key);
    gcm_open(&data_key, &unb64(sealed)?, ad.as_bytes())
}

/// The ANSI X9.63 KDF with SHA-256.
fn x963_kdf(secret: &[u8], shared_info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(len + 32));
    let mut counter: u32 = 1;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(secret);
        h.update(counter.to_be_bytes());
        h.update(shared_info);
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

/// A raw P-256 point (65 bytes, uncompressed) as a public key.
pub(crate) fn public_key(raw: &[u8]) -> Result<PublicKey> {
    if raw.len() != 65 || raw[0] != 4 {
        bail!("a public key is a raw P-256 point (65 bytes)");
    }
    PublicKey::from_sec1_bytes(raw).map_err(|_| anyhow!("not a P-256 point"))
}

pub(crate) fn raw_public(key: &PublicKey) -> Vec<u8> {
    key.to_encoded_point(false).as_bytes().to_vec()
}

/// ECIES to `recipient`: `ephemeral point (65) || ciphertext || tag (16)`.
/// The shared secret's X9.63 KDF, with the ephemeral point as shared info,
/// gives a 16-byte AES key and a 16-byte IV. (Ring keys go through
/// `wrap_ring`; this bare form is for tests.)
#[cfg(test)]
pub(crate) fn ecies_seal(recipient: &PublicKey, plain: &[u8]) -> Vec<u8> {
    ecies_seal_with(recipient, plain, &SecretKey::random(&mut OsRng))
}

pub(crate) fn ecies_seal_with(recipient: &PublicKey, plain: &[u8], ephemeral: &SecretKey) -> Vec<u8> {
    let point = raw_public(&ephemeral.public_key());
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let derived = x963_kdf(shared.raw_secret_bytes(), &point, 32);
    let cipher = Aes128Gcm16::new(derived[..16].into());
    let sealed = cipher.encrypt(derived[16..].into(), plain).expect("AES-GCM seals any length we use");
    [point, sealed].concat()
}

/// Opens `ecies_seal`'s output with the recipient's secret key (a file key;
/// a Secure Enclave key opens it in the enclave).
pub(crate) fn ecies_open(secret: &SecretKey, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < 65 + 16 {
        bail!("too short to be an ECIES seal");
    }
    let (point, body) = sealed.split_at(65);
    let ephemeral = public_key(point)?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), ephemeral.as_affine());
    let derived = x963_kdf(shared.raw_secret_bytes(), point, 32);
    let cipher = Aes128Gcm16::new(derived[..16].into());
    cipher.decrypt(derived[16..].into(), body).map(Zeroizing::new).map_err(|_| anyhow!("this key doesn't open it"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_value_opens_only_with_its_ring_key_and_in_its_own_op() {
        let ring = random_key();
        let key = name_mac(&ring, "prod/shop/STRIPE_KEY");
        let (sealed, wrapped) = seal_value(&ring, &key, 2, b"{\"value\":\"sk\"}", None);
        assert_eq!(&open_value(&ring, &key, 2, &sealed, &wrapped).unwrap()[..], b"{\"value\":\"sk\"}");
        assert!(open_value(&random_key(), &key, 2, &sealed, &wrapped).is_err(), "another ring");
        assert!(open_value(&ring, &key, 3, &sealed, &wrapped).is_err(), "another version");
        let other = name_mac(&ring, "prod/shop/OTHER");
        assert!(open_value(&ring, &other, 2, &sealed, &wrapped).is_err(), "another path");
        assert_ne!(name_mac(&ring, "a"), name_mac(&random_key(), "a"), "the name depends on the ring");
        assert_eq!(key.len(), 43);
        // The subkeys are separate: a name is never a membership MAC, and the
        // ring key itself wraps nothing.
        assert_ne!(name_mac(&ring, "x"), member_mac(&ring, "x"));
        assert!(gcm_open(&ring, &unb64(&wrapped).unwrap(), value_ad(&key, 2).as_bytes()).is_err());
    }

    #[test]
    fn a_ring_wrap_opens_only_for_its_epoch_and_recipient() {
        let me = SecretKey::random(&mut OsRng);
        let ring = random_key();
        let sealed = wrap_ring(&me.public_key(), 3, "d-aaaaaaaaaaaaaaaa", &ring);
        let plain = ecies_open(&me, &sealed).unwrap();
        assert_eq!(*unwrapped_ring(&plain, 3, "d-aaaaaaaaaaaaaaaa").unwrap(), *ring);
        assert!(unwrapped_ring(&plain, 2, "d-aaaaaaaaaaaaaaaa").is_none(), "another epoch");
        assert!(unwrapped_ring(&plain, 3, "d-bbbbbbbbbbbbbbbb").is_none(), "another recipient");
        assert!(unwrapped_ring(&*ring, 3, "d-aaaaaaaaaaaaaaaa").is_none(), "a bare key");
    }

    #[test]
    fn fingerprints_are_128_bits_read_in_groups_and_typed_any_way() {
        let fp = device_fingerprint(b"sign", b"agree");
        assert_eq!(fp.len(), 32 + 7);
        assert_ne!(fp, ring_fingerprint(b"sign", b"agree"), "a ring's isn't its founder's device fingerprint");
        assert_ne!(fp, device_fingerprint(b"sign", b"other"));
        assert_eq!(normal_fingerprint(&fp.to_uppercase().replace('-', " ")).as_deref(), Some(fp.as_str()));
        assert!(normal_fingerprint(&fp[..20]).is_none());
        assert!(normal_fingerprint("zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz").is_none());
    }

    #[test]
    fn ecies_opens_only_with_the_recipients_key_and_not_when_tampered() {
        let me = SecretKey::random(&mut OsRng);
        let ring = random_key();
        let mut sealed = ecies_seal(&me.public_key(), &*ring);
        assert_eq!(sealed.len(), 65 + 32 + 16);
        assert_eq!(&ecies_open(&me, &sealed).unwrap()[..], &ring[..]);
        assert!(ecies_open(&SecretKey::random(&mut OsRng), &sealed).is_err());
        let last = sealed.len() - 1;
        sealed[last] ^= 1;
        assert!(ecies_open(&me, &sealed).is_err());
    }

    #[test]
    fn the_x963_kdf_matches_its_definition() {
        // Two blocks: sha256(Z || 00000001 || info) || sha256(Z || 00000002 || info).
        let out = x963_kdf(b"Z", b"info", 40);
        let first = Sha256::digest([b"Z".as_slice(), &1u32.to_be_bytes(), b"info"].concat());
        let second = Sha256::digest([b"Z".as_slice(), &2u32.to_be_bytes(), b"info"].concat());
        assert_eq!(&out[..32], first.as_slice());
        assert_eq!(&out[32..], &second[..8]);
    }

    /// A ring key wrapped here to a Secure Enclave key opens in the enclave:
    /// the Rust ECIES is Apple's. The key needs no presence, so no prompt.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_wrap_made_here_opens_in_the_secure_enclave() {
        let Some(enclave) = crate::enclave::tests::test_key() else { return };
        let recipient = public_key(&enclave.public_key().unwrap()).unwrap();
        let ring = random_key();
        let sealed = ecies_seal(&recipient, &*ring);
        assert_eq!(&enclave.open(&sealed).unwrap()[..], &ring[..]);
        // And the enclave's own seal has the same shape.
        assert_eq!(enclave.seal(&*ring).unwrap().len(), sealed.len());
    }
}
