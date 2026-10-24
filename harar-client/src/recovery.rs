//! Getting in when there is no device to approve with (architecture, §6):
//!
//! - **Recovery codes.** Ten one-time codes per person, shown once when their
//!   first device is enrolled, like GitHub's and Google's. Each works once,
//!   and only for its owner. Using one enrolls a new device; every other
//!   device is told.
//! - **The setup link.** A new primary prints a one-time link for the person
//!   who will own it. Opening it enrolls their first device. It works once,
//!   only while no device exists, and is gone as soon as any device exists.
//!
//! Only hashes are stored, inside the primary's encrypted store. A code has
//! 80 bits of randomness, so a hash can't be turned back into a code.
//!
//! What the caller owes: hold the store's lock across `use_recovery_code`
//! and saving its result, and save the spent code before enrolling the new
//! device, so a code can never work twice; limit attempts; tell the person's
//! other devices; print a setup link only to the terminal, never to a log.

use crate::model::Name;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// How many recovery codes a person gets at a time.
pub const RECOVERY_CODES: usize = 10;

/// Crockford base32, lowercase.
const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// Longer input than this is never a code.
const MAX_INPUT: usize = 64;

const CODE_CONTEXT: &[u8] = b"harar.recovery-code.v1";
const SETUP_CONTEXT: &[u8] = b"harar.setup-link.v1";

fn hash(context: &[u8], secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context);
    hasher.update(secret.as_bytes());
    B64URL.encode(hasher.finalize())
}

fn tags_match(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0, |diff, (x, y)| diff | (x ^ y)) == 0
}

/// A recovery code as stored: whose it is and its hash, never the code.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCode {
    pub human: Name,
    pub hash: String,
}

/// A code as typed or pasted, reduced to its 16 characters: ASCII letters and
/// digits only (dashes, spaces, and anything a chat app pastes around them,
/// like non-breaking spaces and Unicode dashes, dropped), lowercase, and
/// Crockford's look-alikes read as what they look like (o as 0, i and l as 1).
/// None if it can't be a code.
fn normalize(code: &str) -> Option<String> {
    if code.len() > MAX_INPUT {
        return None;
    }
    let out: String = code
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| match c.to_ascii_lowercase() {
            'o' => '0',
            'i' | 'l' => '1',
            c => c,
        })
        .collect();
    (out.len() == 16).then_some(out)
}

/// A fresh set of codes for `human` (`xxxx-xxxx-xxxx-xxxx`, 80 bits each),
/// replacing any set they had: old codes stop working. Returns the codes, to
/// show once.
pub fn replace_recovery_codes(stored: &mut Vec<StoredCode>, human: &Name) -> Vec<String> {
    stored.retain(|code| &code.human != human);
    let mut codes = Vec::with_capacity(RECOVERY_CODES);
    for _ in 0..RECOVERY_CODES {
        let mut bytes = [0_u8; 16];
        OsRng.fill_bytes(&mut bytes);
        // 256 is a multiple of 32, so each character is uniform.
        let chars: Vec<char> = bytes.iter().map(|b| ALPHABET[usize::from(*b) % 32] as char).collect();
        let code = chars.chunks(4).map(|group| group.iter().collect::<String>()).collect::<Vec<_>>().join("-");
        let normal = normalize(&code).expect("a fresh code is well formed");
        stored.push(StoredCode { human: human.clone(), hash: hash(CODE_CONTEXT, &normal) });
        codes.push(code);
    }
    codes
}

/// Uses one of `human`'s codes: if `code` is one, it is removed and this
/// returns true. A code never works twice, and never for anyone else.
pub fn use_recovery_code(stored: &mut Vec<StoredCode>, human: &Name, code: &str) -> bool {
    let Some(normal) = normalize(code) else { return false };
    let candidate = hash(CODE_CONTEXT, &normal);
    // Compare against every stored code, so the time taken says nothing
    // about which one matched.
    let mut found = None;
    for (index, stored) in stored.iter().enumerate() {
        if tags_match(&stored.hash, &candidate) && &stored.human == human {
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

/// The one-time setup link's secret, as stored: whose first device it
/// enrolls, its hash, and when it stops working.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupToken {
    pub human: Name,
    pub hash: String,
    pub expires_at: u64,
}

/// How long a setup link works.
pub const SETUP_SECONDS: u64 = 24 * 3600;

/// A new setup secret (256 bits) for `human`'s first device, and what to
/// store in the primary's single setup slot.
pub fn new_setup_token(human: &Name, now: u64) -> (String, SetupToken) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let secret = B64URL.encode(bytes);
    let stored = SetupToken { human: human.clone(), hash: hash(SETUP_CONTEXT, &secret), expires_at: now + SETUP_SECONDS };
    (secret, stored)
}

/// Redeems the setup link. The slot is emptied whatever happens once a device
/// exists or the link has expired, and on success, so it never works twice
/// and never after the first device. Returns whose first device to enroll.
pub fn redeem_setup_token(slot: &mut Option<SetupToken>, secret: &str, devices_exist: bool, now: u64) -> Option<Name> {
    let token = slot.as_ref()?;
    if devices_exist || now >= token.expires_at {
        *slot = None;
        return None;
    }
    if !tags_match(&token.hash, &hash(SETUP_CONTEXT, secret)) {
        return None;
    }
    slot.take().map(|token| token.human)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(text: &str) -> Name {
        text.parse().unwrap()
    }

    #[test]
    fn each_recovery_code_works_once_and_only_for_its_owner() {
        let sami = name("gg.addis.human.sami");
        let eve = name("gg.addis.human.eve");
        let mut stored = Vec::new();
        let codes = replace_recovery_codes(&mut stored, &sami);
        let eves = replace_recovery_codes(&mut stored, &eve);
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert!(codes.iter().all(|code| code.len() == 19 && code.split('-').count() == 4));
        assert_eq!(codes.iter().collect::<std::collections::BTreeSet<_>>().len(), RECOVERY_CODES, "all different");
        for code in &codes {
            let normal = normalize(code).unwrap();
            assert!(stored.iter().all(|s| s.hash != normal && !s.hash.contains(&normal)), "only hashes are stored");
        }

        assert!(!use_recovery_code(&mut stored, &eve, &codes[0]), "sami's code isn't eve's");
        assert!(use_recovery_code(&mut stored, &sami, &codes[3]));
        assert!(!use_recovery_code(&mut stored, &sami, &codes[3]), "used up");
        assert!(use_recovery_code(&mut stored, &eve, &eves[0]));
        assert_eq!(stored.len(), 2 * RECOVERY_CODES - 2);
    }

    #[test]
    fn codes_read_back_the_way_people_copy_them() {
        let sami = name("gg.addis.human.sami");
        let mut stored = Vec::new();
        let codes = replace_recovery_codes(&mut stored, &sami);
        // Spaces for dashes, capitals.
        assert!(use_recovery_code(&mut stored, &sami, &codes[0].replace('-', " ").to_uppercase()));
        // Pasted from a chat app: non-breaking spaces and Unicode dashes.
        let pasted = codes[1].replace('-', "\u{2011}").replace('a', "a\u{00a0}");
        assert!(use_recovery_code(&mut stored, &sami, &pasted));
        // Not codes at all.
        for junk in ["", "0000-0000-0000-0000", "\u{212a}", &"a".repeat(100), &codes[2][..10]] {
            assert!(!use_recovery_code(&mut stored, &sami, junk), "{junk:?}");
        }
    }

    #[test]
    fn crockford_look_alikes_read_as_what_they_look_like() {
        // A fixed code with 0s and 1s, so the check never passes by luck.
        assert_eq!(normalize("10O1-lI00-0000-1111").as_deref(), Some("1001110000001111"));
        assert_eq!(normalize("ABCD-0123-EFGH-4567"), normalize("abcd o123 efgh 4567"));
    }

    #[test]
    fn a_new_set_replaces_the_old_one() {
        let sami = name("gg.addis.human.sami");
        let mut stored = Vec::new();
        let old = replace_recovery_codes(&mut stored, &sami);
        let new = replace_recovery_codes(&mut stored, &sami);
        assert_eq!(stored.len(), RECOVERY_CODES);
        assert!(!use_recovery_code(&mut stored, &sami, &old[0]), "old codes stop working");
        assert!(use_recovery_code(&mut stored, &sami, &new[0]));
    }

    #[test]
    fn the_hash_format_is_pinned() {
        // Computed separately (Python: sha256(b"harar.recovery-code.v1" +
        // b"abcd0123efgh4567"), base64url without padding), so stored codes
        // keep working across versions and other tools can check them.
        assert_eq!(hash(CODE_CONTEXT, &normalize("ABCD-0123-EFGH-4567").unwrap()), KNOWN_CODE_HASH);
    }

    const KNOWN_CODE_HASH: &str = "Bf2pUjbdfcvNEagMbUV6UtN9pO0INCjlxJmzjLNqT6M";

    #[test]
    fn the_setup_link_works_once_for_its_person_and_never_once_a_device_exists() {
        let sami = name("gg.addis.human.sami");
        let now = 1_800_000_000;
        let (secret, token) = new_setup_token(&sami, now);
        assert!(!token.hash.contains(&secret));

        let mut slot = Some(token.clone());
        assert_eq!(redeem_setup_token(&mut slot, "wrong", false, now + 60), None);
        assert!(slot.is_some(), "a wrong guess doesn't spend it");
        assert_eq!(redeem_setup_token(&mut slot, &secret, false, now + 60), Some(sami.clone()));
        assert!(slot.is_none(), "spent");
        assert_eq!(redeem_setup_token(&mut slot, &secret, false, now + 61), None);

        let mut late = Some(token.clone());
        assert_eq!(redeem_setup_token(&mut late, &secret, false, now + SETUP_SECONDS), None);
        assert!(late.is_none(), "an expired link is cleared");

        let mut after = Some(token);
        assert_eq!(redeem_setup_token(&mut after, &secret, true, now + 60), None);
        assert!(after.is_none(), "once a device exists the link is gone for good");
    }
}
