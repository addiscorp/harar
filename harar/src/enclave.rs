//! Secure Enclave keys on macOS (Apple silicon, and Intel Macs with a T2 chip).
//!
//! The key is created in the Secure Enclave but not stored in the keychain:
//! keychain-stored enclave keys require a code-signed binary with keychain
//! entitlements. Instead the enclave hands back an encrypted handle
//! (`kSecAttrTokenOID`) that only this Mac's enclave can turn back into the key,
//! and harar stores that handle itself. This is how CryptoKit's
//! `SecureEnclave.P256` keys persist.
//!
//! Data is sealed to the key with Apple's ECIES (cofactor ECDH, X9.63 SHA-256
//! KDF, AES-GCM); opening it needs the enclave.

use anyhow::{Context, Result, anyhow};
use core_foundation::base::{CFType, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::error::CFErrorRef;
use security_framework::access_control::SecAccessControl;
use security_framework::key::{Algorithm, GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework_sys::access_control::{
    kSecAccessControlPrivateKeyUsage, kSecAccessControlUserPresence,
};
use security_framework_sys::item::{
    kSecAttrKeyClass, kSecAttrKeyClassPrivate, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
};

/// `errSecInteractionNotAllowed`: the Secure Enclave refuses while the Mac's
/// screen is locked.
const INTERACTION_NOT_ALLOWED: isize = -25308;

fn enclave_error(action: &str, err: core_foundation::error::CFError) -> anyhow::Error {
    if err.code() == INTERACTION_NOT_ALLOWED {
        anyhow!("{action}: the Secure Enclave refuses while the screen is locked; unlock the Mac and try again")
    } else {
        anyhow!("{action}: {err}")
    }
}

const ECIES: Algorithm = Algorithm::ECIESEncryptionCofactorVariableIVX963SHA256AESGCM;
/// `kSecAttrTokenOID`, which security-framework-sys does not export.
const TOKEN_OID: &str = "toid";

/// Whether using the key needs the person at the Mac.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// Touch ID where there is a sensor, otherwise the login password or an
    /// Apple Watch.
    Required,
    /// No prompt. Only for tests and the availability probe.
    NotRequired,
}

pub struct EnclaveKey {
    key: SecKey,
}

impl EnclaveKey {
    pub fn create(presence: Presence) -> Result<Self> {
        let flags = match presence {
            Presence::Required => kSecAccessControlPrivateKeyUsage | kSecAccessControlUserPresence,
            Presence::NotRequired => kSecAccessControlPrivateKeyUsage,
        };
        let access = SecAccessControl::create_with_flags(flags)
            .map_err(|err| anyhow!("create Secure Enclave access control: {err}"))?;
        let mut options = GenerateKeyOptions::default();
        options
            .set_key_type(KeyType::ec_sec_prime_random())
            .set_size_in_bits(256)
            .set_token(Token::SecureEnclave)
            .set_access_control(access);
        let key = SecKey::new(&options).map_err(|err| enclave_error("create Secure Enclave key", err))?;
        Ok(Self { key })
    }

    /// Recreates the key from the handle `handle()` returned, on the same Mac.
    pub fn from_handle(handle: &[u8]) -> Result<Self> {
        // SAFETY: the kSecAttr* constants are static CFStrings owned by Security.framework.
        let pairs = unsafe {
            [
                (
                    CFString::wrap_under_get_rule(kSecAttrTokenID),
                    CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyClass),
                    CFString::wrap_under_get_rule(kSecAttrKeyClassPrivate).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeyType),
                    CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                    CFNumber::from(256).into_CFType(),
                ),
                (CFString::new(TOKEN_OID), CFData::from_buffer(handle).into_CFType()),
            ]
        };
        let attributes = CFDictionary::from_CFType_pairs(&pairs);
        let empty = CFData::from_buffer(&[]);
        let mut error: CFErrorRef = std::ptr::null_mut();
        // SAFETY: both CF objects are valid for the call; ownership of the
        // returned key and error follows the Create rule.
        let key = unsafe {
            security_framework_sys::key::SecKeyCreateWithData(
                empty.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
                &mut error,
            )
        };
        if key.is_null() {
            // SAFETY: on failure SecKeyCreateWithData returns an owned CFError.
            let error = unsafe { core_foundation::error::CFError::wrap_under_create_rule(error) };
            return Err(anyhow!("restore Secure Enclave key from handle: {error}"));
        }
        // SAFETY: a non-null result is an owned SecKeyRef.
        Ok(Self { key: unsafe { SecKey::wrap_under_create_rule(key) } })
    }

    /// The enclave-encrypted handle. Useless on any other Mac.
    pub fn handle(&self) -> Result<Vec<u8>> {
        let attributes = self.key.attributes();
        let name = CFString::new(TOKEN_OID);
        let value = attributes
            .find(name.as_CFTypeRef())
            .ok_or_else(|| anyhow!("Secure Enclave key has no token handle"))?;
        // SAFETY: values in a key's attribute dictionary are CF objects it retains.
        let value = unsafe { CFType::wrap_under_get_rule(*value) };
        let data = value
            .downcast::<CFData>()
            .ok_or_else(|| anyhow!("Secure Enclave token handle is not data"))?;
        Ok(data.bytes().to_vec())
    }

    /// Uncompressed P-256 public key (65 bytes).
    pub fn public_key(&self) -> Result<Vec<u8>> {
        let public = self
            .key
            .public_key()
            .ok_or_else(|| anyhow!("Secure Enclave key has no public key"))?;
        let data = public
            .external_representation()
            .ok_or_else(|| anyhow!("export Secure Enclave public key"))?;
        Ok(data.bytes().to_vec())
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let public = self
            .key
            .public_key()
            .ok_or_else(|| anyhow!("Secure Enclave key has no public key"))?;
        public
            .encrypt_data(ECIES, plaintext)
            .map_err(|err| anyhow!("seal to Secure Enclave key: {err}"))
    }

    /// Asks for presence first when the key was created with `Presence::Required`.
    pub fn open(&self, sealed: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        self.key
            .decrypt_data(ECIES, sealed)
            .map(zeroize::Zeroizing::new)
            .map_err(|err| enclave_error("open with Secure Enclave key", err))
    }
}

/// Whether this Mac has a Secure Enclave harar can use. Creates a throwaway
/// key that needs no presence, so it never prompts.
pub fn available() -> bool {
    EnclaveKey::create(Presence::NotRequired)
        .and_then(|key| key.handle())
        .context("probe")
        .is_ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A test key, or `None` on a runner that declares it has no Secure
    /// Enclave (`HARAR_TEST_NO_ENCLAVE=1`, e.g. a macOS VM). Declaring it is
    /// checked, so a missing enclave never passes silently.
    pub(crate) fn test_key() -> Option<EnclaveKey> {
        if std::env::var_os("HARAR_TEST_NO_ENCLAVE").is_some() {
            assert!(!available(), "HARAR_TEST_NO_ENCLAVE is set but this Mac has a Secure Enclave");
            return None;
        }
        Some(EnclaveKey::create(Presence::NotRequired).expect("this Mac has no usable Secure Enclave; set HARAR_TEST_NO_ENCLAVE=1 only on runners without one"))
    }

    #[test]
    fn sealed_data_opens_only_with_the_same_key() {
        let (Some(key), Some(other)) = (test_key(), test_key()) else { return };
        let sealed = key.seal(b"vault key").unwrap();

        assert_eq!(key.open(&sealed).unwrap().as_slice(), b"vault key");
        assert!(other.open(&sealed).is_err());
    }

    #[test]
    fn handle_restores_the_same_key() {
        let Some(key) = test_key() else { return };
        let sealed = key.seal(b"vault key").unwrap();
        let handle = key.handle().unwrap();
        let public = key.public_key().unwrap();
        drop(key);

        let restored = EnclaveKey::from_handle(&handle).unwrap();
        assert_eq!(restored.public_key().unwrap(), public);
        assert_eq!(restored.open(&sealed).unwrap().as_slice(), b"vault key");
    }

    #[test]
    fn garbage_handle_is_rejected() {
        if test_key().is_none() {
            return;
        }
        let key = EnclaveKey::from_handle(&[7u8; 324]);
        assert!(key.is_err() || key.unwrap().public_key().is_err());
    }

    #[test]
    fn tampered_seal_is_rejected() {
        let Some(key) = test_key() else { return };
        let mut sealed = key.seal(b"vault key").unwrap();
        let last = sealed.len() - 1;
        sealed[last] ^= 1;

        assert!(key.open(&sealed).is_err());
    }

    #[test]
    fn private_key_cannot_be_exported() {
        let Some(key) = test_key() else { return };

        assert!(key.key.external_representation().is_none());
        assert_eq!(key.public_key().unwrap().len(), 65);
    }

    #[test]
    fn presence_required_key_is_created_and_sealed_to_without_a_prompt() {
        if test_key().is_none() {
            return;
        }
        // Creating the key and sealing to its public half never need the
        // person; only open() does, so this test cannot prompt.
        let key = EnclaveKey::create(Presence::Required).unwrap();
        assert!(!key.seal(b"vault key").unwrap().is_empty());
        assert!(!key.handle().unwrap().is_empty());
    }
}
