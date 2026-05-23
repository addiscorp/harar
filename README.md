# Gild Vault Runtime Notes

## Recovery passphrases

Do not pass disaster-recovery passphrases on argv or through environment variables. The daemon reads a recovery passphrase from `GILD_VAULT_RECOVERY_PASSPHRASE_FD`, from `GILD_VAULT_RECOVERY_PASSPHRASE_FILE`, or from the default root-only file at `/var/lib/gild-vault/recovery.passphrase`. Passphrase files must be mode `0600`; when the daemon runs as root they must also be owned by root.

The passphrase artifact is stored separately at `recipients/recovery.age`. Hardware/public-recipient wrapping remains at `recipients/db-key.age`.

## Breakglass tokens

Normal vault tokens must bind a bearer hash to peer credentials with `uid` and optional `gid`. Tokens without peer credentials are rejected before request handling.

Breakglass access must be explicit with `key_type: "breakglass"`. It is intended for emergency local recovery when Unix peer credentials cannot be established. Every successful breakglass authentication writes a `breakglass_auth` audit row.

## Memory hardening

The daemon fails closed if core dumps cannot be disabled or if the DB key cannot be locked in memory. Key locking prefers `sodium_mlock` when libsodium is available and falls back to libc `mlock` otherwise. `--allow-pageable-key` exists only for local development hosts that cannot grant memory locking.

## Agent JWT verification

The `/v1/secret/<key>` endpoint is for `tana-vault-agent` callers. It accepts only `Authorization: Bearer <jwt>` and verifies:

- `HS256` for the `hs256-dev` provider, using the same `/etc/tana-vault-agent/dev-key` file by default.
- `RS256` for the `tpm` provider, using a pre-shared PEM public key or a configured public-key URL from the agent attestation endpoint.

Required claims are `iss`, `sub`, `aud`, `scope`, and `exp`. `aud` must be `vault.tana.gg`; `iss` must match a configured agent; `sub` must match a configured workload; and `scope` must include `vault:read:<workload namespace>/*`. The legacy `/secret/<namespace>/<key>` admin/service API continues to use uid-bound bearer tokens.

Manual TPM path until swtpm automation lands:

1. Start `tana-vault-agent` with `TANA_VAULT_AGENT_ATTESTATION=tpm` and expose its public key through `/v1/attestation/pubkey`, or copy that PEM into `jwt.agents[].public_key_pem`.
2. Configure `gild-vault` with a `jwt.agents` entry for the TPM issuer and `provider = "tpm"`, plus a `jwt.workloads` entry mapping the JWT `sub` to the vault namespace.
3. Fetch a known secret through `tana-vault-agent` and confirm a valid RS256 token returns `200`, then tamper with the token or audience and confirm `401` plus a `vault auth failure` log line.
