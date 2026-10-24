//! An SSH agent (draft-miller-ssh-agent) serving Ed25519 keys kept in the
//! vault under `ssh/<name>`. `ssh`, `git` and `ssh-keygen -Y sign` talk to it
//! through `SSH_AUTH_SOCK` / `IdentityAgent`.
//!
//! It runs inside `harar agent` and shares its rules: only the owner, and
//! every terminal session approved once.

use crate::agent::{Vault, session_of};
use crate::common::peer_credentials;
use anyhow::{Context, Result, anyhow};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

pub const KEY_PREFIX: &str = "ssh/";
const KEY_TYPE: &str = "ssh-ed25519";
const MAX_MESSAGE: usize = 256 * 1024;

const FAILURE: u8 = 5;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;

/// What the vault stores for one SSH key.
#[derive(Debug, Serialize, Deserialize)]
pub struct StoredKey {
    #[serde(rename = "type")]
    pub kind: String,
    /// The 32-byte Ed25519 seed, base64.
    pub seed: String,
    pub comment: String,
}

impl StoredKey {
    pub fn generate(comment: String) -> Self {
        let key = harar_client::generate_signing_key();
        Self {
            kind: KEY_TYPE.to_string(),
            seed: BASE64.encode(key.to_bytes()),
            comment,
        }
    }

    fn signing_key(&self) -> Result<SigningKey> {
        if self.kind != KEY_TYPE {
            return Err(anyhow!("unsupported SSH key type {}", self.kind));
        }
        let seed: [u8; 32] = BASE64
            .decode(&self.seed)?
            .try_into()
            .map_err(|_| anyhow!("SSH key seed must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&seed))
    }

    /// The public key blob (`string "ssh-ed25519", string key`).
    pub fn public_blob(&self) -> Result<Vec<u8>> {
        let mut blob = Vec::new();
        put_string(&mut blob, KEY_TYPE.as_bytes());
        put_string(&mut blob, self.signing_key()?.verifying_key().as_bytes());
        Ok(blob)
    }

    /// The `authorized_keys` line.
    pub fn public_line(&self) -> Result<String> {
        Ok(format!("{KEY_TYPE} {} {}", BASE64.encode(self.public_blob()?), self.comment))
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let signature = self.signing_key()?.sign(data);
        let mut blob = Vec::new();
        put_string(&mut blob, KEY_TYPE.as_bytes());
        put_string(&mut blob, &signature.to_bytes());
        Ok(blob)
    }
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn string(&mut self) -> Result<&'a [u8]> {
        if self.0.len() < 4 {
            return Err(anyhow!("truncated SSH agent message"));
        }
        let (len, rest) = self.0.split_at(4);
        let len = u32::from_be_bytes(len.try_into().expect("4 bytes")) as usize;
        if rest.len() < len {
            return Err(anyhow!("truncated SSH agent message"));
        }
        let (value, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(value)
    }
}

/// The keys in the vault, skipping entries that aren't valid SSH keys.
fn keys(entries: &std::collections::HashMap<String, String>) -> Vec<StoredKey> {
    let mut named: Vec<(&String, StoredKey)> = entries
        .iter()
        .filter(|(name, _)| name.starts_with(KEY_PREFIX))
        .filter_map(|(name, value)| Some((name, serde_json::from_str(value).ok()?)))
        .collect();
    named.sort_by(|a, b| a.0.cmp(b.0));
    named.into_iter().map(|(_, key)| key).collect()
}

/// Answers one agent message. `entries` is called only when a key is needed,
/// so it is what asks for approval.
pub fn answer(
    message: &[u8],
    entries: impl FnOnce() -> Result<Vec<StoredKey>>,
) -> Vec<u8> {
    let reply = match message.split_first() {
        Some((&REQUEST_IDENTITIES, _)) => entries().and_then(|keys| {
            let mut out = vec![IDENTITIES_ANSWER];
            out.extend_from_slice(&(keys.len() as u32).to_be_bytes());
            for key in &keys {
                put_string(&mut out, &key.public_blob()?);
                put_string(&mut out, key.comment.as_bytes());
            }
            Ok(out)
        }),
        Some((&SIGN_REQUEST, body)) => (|| {
            let mut reader = Reader(body);
            let blob = reader.string()?;
            let data = reader.string()?;
            let keys = entries()?;
            let key = keys
                .iter()
                .find(|key| key.public_blob().is_ok_and(|b| b == blob))
                .ok_or_else(|| anyhow!("no such key"))?;
            let mut out = vec![SIGN_RESPONSE];
            put_string(&mut out, &key.sign(data)?);
            Ok(out)
        })(),
        _ => Err(anyhow!("unsupported request")),
    };
    reply.unwrap_or_else(|_| vec![FAILURE])
}

pub(crate) async fn serve(listener: UnixListener, vault: Arc<Mutex<Vault>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let vault = Arc::clone(&vault);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, vault).await {
                eprintln!("harar ssh agent connection error: {err:#}");
            }
        });
    }
}

async fn handle_connection(mut stream: UnixStream, vault: Arc<Mutex<Vault>>) -> Result<()> {
    let peer = peer_credentials(&stream)?;
    let session = session_of(peer.pid);
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).await.is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_MESSAGE {
            return Err(anyhow!("SSH agent message of {len} bytes is too large"));
        }
        let mut message = vec![0u8; len];
        stream.read_exact(&mut message).await.context("read SSH agent message")?;
        let vault = Arc::clone(&vault);
        let peer = peer.clone();
        // Approving can wait on the person, so keep it off the async workers.
        let reply = tokio::task::spawn_blocking(move || {
            answer(&message, || {
                let mut vault = vault.lock().expect("agent state lock");
                let entries = vault
                    .entries_for(&peer, session, Instant::now())
                    .map_err(|err| anyhow!("{err:#}"))?;
                Ok(keys(entries))
            })
        })
        .await?;
        let mut framed = (reply.len() as u32).to_be_bytes().to_vec();
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};

    fn sign_request(blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut message = vec![SIGN_REQUEST];
        put_string(&mut message, blob);
        put_string(&mut message, data);
        message.extend_from_slice(&0u32.to_be_bytes());
        message
    }

    #[test]
    fn lists_keys_with_their_comments() {
        let key = StoredKey::generate("sami@imac".into());
        let blob = key.public_blob().unwrap();
        let reply = answer(&[REQUEST_IDENTITIES], || Ok(vec![key]));

        assert_eq!(reply[0], IDENTITIES_ANSWER);
        assert_eq!(&reply[1..5], &1u32.to_be_bytes());
        let mut reader = Reader(&reply[5..]);
        assert_eq!(reader.string().unwrap(), blob.as_slice());
        assert_eq!(reader.string().unwrap(), b"sami@imac");
    }

    #[test]
    fn signs_with_the_requested_key_and_the_signature_verifies() {
        let key = StoredKey::generate("k".into());
        let verifying = key.signing_key().unwrap().verifying_key();
        let blob = key.public_blob().unwrap();
        let reply = answer(&sign_request(&blob, b"commit abc"), || Ok(vec![StoredKey::generate("other".into()), key]));

        assert_eq!(reply[0], SIGN_RESPONSE);
        let mut outer = Reader(&reply[1..]);
        let mut sig = Reader(outer.string().unwrap());
        assert_eq!(sig.string().unwrap(), KEY_TYPE.as_bytes());
        let signature = Signature::from_slice(sig.string().unwrap()).unwrap();
        assert!(verifying.verify(b"commit abc", &signature).is_ok());
    }

    #[test]
    fn unknown_key_unsupported_request_or_refusal_fail() {
        let key = StoredKey::generate("k".into());
        let stranger = StoredKey::generate("x".into()).public_blob().unwrap();
        assert_eq!(answer(&sign_request(&stranger, b"d"), || Ok(vec![key])), vec![FAILURE]);
        assert_eq!(answer(&[17, 0, 0], || panic!("must not touch keys")), vec![FAILURE]);
        assert_eq!(answer(&[REQUEST_IDENTITIES], || Err(anyhow!("not approved"))), vec![FAILURE]);
        assert_eq!(answer(&[SIGN_REQUEST, 0, 0], || panic!("parse fails first")), vec![FAILURE]);
    }

    #[test]
    fn public_line_is_openssh_format() {
        let line = StoredKey::generate("me@host".into()).public_line().unwrap();
        let parts: Vec<_> = line.split(' ').collect();
        assert_eq!(parts[0], "ssh-ed25519");
        assert_eq!(BASE64.decode(parts[1]).unwrap().len(), 4 + 11 + 4 + 32);
        assert_eq!(parts[2], "me@host");
    }
}
