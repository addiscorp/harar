use crate::VaultClaims;
use crate::attestation::{rs256_jwt_from_signature, rs256_signing_input};
use anyhow::{Context as AnyhowContext, Result, anyhow, bail};
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Mutex;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, RsaSchemeAlgorithm};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::interface_types::session_handles::AuthSession;
use tss_esapi::structures::{
    HashScheme, MaxBuffer, RsaExponent, RsaScheme, Signature, SignatureScheme,
};
use tss_esapi::utils::create_unrestricted_signing_rsa_public;
use tss_esapi::{Context, TctiNameConf};

pub struct TpmProvider {
    inner: Mutex<TpmState>,
}

struct TpmState {
    context: Context,
    key_handle: KeyHandle,
}

impl TpmProvider {
    pub fn new() -> Result<Self> {
        let tcti = load_tcti()?;
        let mut context = Context::new(tcti).context("initialize TPM ESAPI context")?;
        let key_handle = create_primary_signing_key(&mut context)?;

        Ok(Self {
            inner: Mutex::new(TpmState {
                context,
                key_handle,
            }),
        })
    }

    pub fn mint_jwt(&self, claims: &VaultClaims) -> Result<String> {
        let signing_input = rs256_signing_input(claims)?;
        let signature = self.sign_rs256(signing_input.as_bytes())?;
        Ok(rs256_jwt_from_signature(&signing_input, &signature))
    }

    fn sign_rs256(&self, signing_input: &[u8]) -> Result<Vec<u8>> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| anyhow!("TPM provider mutex poisoned"))?;

        let key_handle = state.key_handle;
        let scheme = SignatureScheme::RsaSsa {
            hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
        };
        let input =
            MaxBuffer::try_from(signing_input.to_vec()).context("convert JWT signing input")?;
        let signature = state
            .context
            .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
                let (digest, validation) =
                    ctx.hash(input, HashingAlgorithm::Sha256, Hierarchy::Owner)?;
                ctx.sign(key_handle, digest, scheme, validation)
            })
            .context("sign JWT digest with TPM key")?;

        match signature {
            Signature::RsaSsa(rsa) => Ok(rsa.signature().value().to_vec()),
            other => bail!(
                "TPM returned unsupported signature type {:?}",
                other.algorithm()
            ),
        }
    }
}

fn load_tcti() -> Result<TctiNameConf> {
    if let Ok(value) = std::env::var("TSS2_TCTI") {
        return TctiNameConf::from_str(&value).context("parse TSS2_TCTI");
    }

    TctiNameConf::from_environment_variable()
        .context("read TPM TCTI from TSS2_TCTI, TPM2TOOLS_TCTI, TCTI, or TEST_TCTI")
}

fn create_primary_signing_key(context: &mut Context) -> Result<KeyHandle> {
    let rsa_scheme = RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
        .context("create TPM RSASSA/SHA256 scheme")?;
    let public = create_unrestricted_signing_rsa_public(
        rsa_scheme,
        RsaKeyBits::Rsa2048,
        RsaExponent::default(),
    )
    .context("create TPM RSA signing public template")?;

    let result = context
        .execute_with_sessions((Some(AuthSession::Password), None, None), |ctx| {
            ctx.create_primary(Hierarchy::Owner, public, None, None, None, None)
        })
        .context("create TPM primary signing key in owner hierarchy")?;
    Ok(result.key_handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResolvedWorkload;
    use jsonwebtoken::{Algorithm, decode_header};

    #[test]
    #[ignore = "requires swtpm or a hardware TPM; see README.md"]
    fn mints_rs256_jwt_with_tpm() {
        let provider = TpmProvider::new().expect("TPM provider");
        let claims = VaultClaims {
            sub: "prod/deka.gg".to_string(),
            scope: "vault:read:prod/deka.gg/*".to_string(),
            iat: 1_779_420_000,
            exp: 1_779_420_060,
        };

        let token = provider.mint_jwt(&claims).expect("mint TPM JWT");
        let header = decode_header(&token).expect("decode header");

        assert_eq!(header.alg, Algorithm::RS256);
    }

    #[test]
    #[ignore = "requires swtpm or a hardware TPM; see README.md"]
    fn attestation_provider_uses_tpm_when_selected() {
        unsafe {
            std::env::set_var("TANA_VAULT_AGENT_ATTESTATION", "tpm");
        }
        let provider = crate::attestation::AttestationProvider::load(std::path::Path::new("/tmp"))
            .expect("load TPM attestation provider");
        let workload = ResolvedWorkload {
            identity: "prod/deka.gg".to_string(),
            namespace: "prod/deka.gg".to_string(),
        };

        let token = provider.mint_jwt(&workload, 1_779_420_000).expect("jwt");
        let header = decode_header(&token).expect("decode header");

        assert_eq!(header.alg, Algorithm::RS256);
    }
}
