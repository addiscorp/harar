//! Getting in when there is no device to approve with (architecture, §6):
//!
//! - **Recovery codes.** Ten one-time codes, shown once when the first device
//!   is enrolled, like GitHub's and Google's. Each works once. Using one
//!   enrolls a new device; every other device is told.
//! - **The setup link.** A new primary prints a one-time link. Whoever opens it
//!   enrolls the first device. It works only while no device exists, and once.
//!
//! Only hashes are stored, inside the primary's encrypted store. A code has
//! 80 bits of randomness, so a hash can't be turned back into a code.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How many recovery codes a person gets at a time.
pub const RECOVERY_CODES: usize = 10;

/// Crockford base32, lowercase: no i, l, o or u, so codes read back without
/// confusion.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

fn hash(context: &[u8], secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(secret.as_bytes());
    B64URL.encode(hasher.finalize())
}

fn tags_match(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// A recovery code as stored: its hash, never the code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCode {
    pub hash: String,
}

/// Lowercase, without the dashes and spaces people add when they copy one.
fn normalize(code: &str) -> String {
    code.chars().filter(|c| !matches!(c, '-' | ' ')).flat_map(char::to_lowercase).collect()
}

/// A fresh set of codes, `xxxx-xxxx-xxxx-xxxx` (80 bits each), and what to
/// store. Show the codes once; store only the hashes.
pub fn new_recovery_codes() -> (Vec<String>, Vec<StoredCode>) {
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    let mut stored = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        let chars: Vec<char> = bytes.iter().map(|b| ALPHABET[usize::from(*b) % 32] as char).collect();
        let code = chars.chunks(4).map(|group| group.iter().collect::<String>()).collect::<Vec<_>>().join("-");
        stored.push(StoredCode { hash: hash(b"harar.recovery-code.v1", &normalize(&code)) });
        codes.push(code);
    }
    (codes, stored)
}

/// Uses a code: if it matches one, that one is removed and this returns
/// true. A code never works twice.
pub fn use_recovery_code(stored: &mut Vec<StoredCode>, code: &str) -> bool {
    let candidate = hash(b"harar.recovery-code.v1", &normalize(code));
    // Compare against every stored code, so the time taken says nothing
    // about which one matched.
    let mut found = None;
    for (index, code) in stored.iter().enumerate() {
        if tags_match(&code.hash, &candidate) {
            found = Some(index);
        }
    }
    match found {
        Some(index) => {
            stored.remove(index);
            true
        }
        None => false,
    }
}

/// The one-time setup link's secret, as stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupToken {
    pub hash: String,
    pub expires_at: u64,
}

/// How long a setup link works.
pub const SETUP_SECONDS: u64 = 24 * 3600;

/// A new setup secret (256 bits) for the link, and what to store.
pub fn new_setup_token(now: u64) -> (String, SetupToken) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = B64URL.encode(bytes);
    let stored = SetupToken { hash: hash(b"harar.setup-link.v1", &secret), expires_at: now + SETUP_SECONDS };
    (secret, stored)
}

/// Whether `secret` is the setup link's and still good. The caller then
/// deletes the stored token, so it never works twice, and refuses it once
/// any device exists.
pub fn setup_token_matches(stored: &SetupToken, secret: &str, now: u64) -> bool {
    now < stored.expires_at && tags_match(&stored.hash, &hash(b"harar.setup-link.v1", secret))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_recovery_code_works_once() {
        let (codes, mut stored) = new_recovery_codes();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|code| code.len() == 19 && code.split('-').count() == 4));
        assert_eq!(codes.iter().collect::<std::collections::BTreeSet<_>>().len(), RECOVERY_CODES, "all different");
        assert!(stored.iter().all(|s| !codes.iter().any(|code| s.hash.contains(code.as_str()))), "only hashes are stored");

        assert!(use_recovery_code(&mut stored, &codes[3]));
        assert!(!use_recovery_code(&mut stored, &codes[3]), "used up");
        assert_eq!(stored.len(), RECOVERY_CODES - 1);
        // Copied with spaces, without dashes, in capitals: still the code.
        let messy = codes[5].replace('-', " ").to_uppercase();
        assert!(use_recovery_code(&mut stored, &messy));
        assert!(!use_recovery_code(&mut stored, "0000-0000-0000-0000"));
        assert!(!use_recovery_code(&mut stored, ""));
        assert_eq!(stored.len(), RECOVERY_CODES - 2);
    }

    #[test]
    fn a_code_from_another_set_does_nothing() {
        let (codes, _) = new_recovery_codes();
        let (_, mut other) = new_recovery_codes();
        assert!(!use_recovery_code(&mut other, &codes[0]));
        assert_eq!(other.len(), RECOVERY_CODES);
    }

    #[test]
    fn the_setup_link_works_until_it_expires_and_only_with_its_secret() {
        let now = 1_800_000_000;
        let (secret, stored) = new_setup_token(now);
        assert!(!stored.hash.contains(&secret));
        assert!(setup_token_matches(&stored, &secret, now + 60));
        assert!(!setup_token_matches(&stored, &secret, now + SETUP_SECONDS), "expired");
        let (other, _) = new_setup_token(now);
        assert!(!setup_token_matches(&stored, &other, now + 60));
        assert!(!setup_token_matches(&stored, "", now + 60));
    }
}
