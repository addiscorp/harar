# Gild Vault Runtime Notes

## Recovery passphrases

Do not pass disaster-recovery passphrases on argv or through environment variables. The daemon reads a recovery passphrase from `GILD_VAULT_RECOVERY_PASSPHRASE_FD`, from `GILD_VAULT_RECOVERY_PASSPHRASE_FILE`, or from the default root-only file at `/var/lib/gild-vault/recovery.passphrase`. Passphrase files must be mode `0600`; when the daemon runs as root they must also be owned by root.

The passphrase artifact is stored separately at `recipients/recovery.age`. Hardware/public-recipient wrapping remains at `recipients/db-key.age`.

## Breakglass tokens

Normal vault tokens must bind a bearer hash to peer credentials with `uid` and optional `gid`. Tokens without peer credentials are rejected before request handling.

Breakglass access must be explicit with `key_type: "breakglass"`. It is intended for emergency local recovery when Unix peer credentials cannot be established. Every successful breakglass authentication writes a `breakglass_auth` audit row.

## Memory hardening

The daemon fails closed if core dumps cannot be disabled or if the DB key cannot be locked in memory. Key locking prefers `sodium_mlock` when libsodium is available and falls back to libc `mlock` otherwise. `--allow-pageable-key` exists only for local development hosts that cannot grant memory locking.
