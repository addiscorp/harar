# gild-vault

Privileged host-local secret daemon for Gild workloads.

The daemon listens on a Unix socket, authorizes each connection with
`SO_PEERCRED`, stores secrets in memory, and writes age-encrypted persistent
state to `/var/lib/gild-vault/keys.age`. The file-backed master identity lives
at `/etc/gild/vault-master.key`; initialize it with `gild vault init` before
starting the daemon.

Replication endpoints also require a shared bearer token in
`/etc/gild/vault-replication-token` by default. The daemon reads
`GILD_VAULT_REPLICATION_TOKEN_FILE` to override that path. Initialize the
authoritative node with:

```bash
gild vault init-replication-token
```

The token file is mode `0400` and owned by `gild-vault` on the authoritative.
Copy the same file to each replica during provisioning, then set owner
`gild-vault-replica` and mode `0400` on the replica. Every `/replication/*`
request must come from the `gild-vault-replica` Unix peer and include
`Authorization: Bearer <token>`.

Replication metadata is persisted beside the encrypted key envelope:
`keys.replication.json` stores the fencing epoch, monotonic version, and
demoted/fenced state; `keys.replication.log` stores durable put entries and
delete tombstones for replica catch-up.

## Replication Recovery

Automatic replica promotion bumps the epoch by 1000 before accepting writes.
When an authoritative node starts with `--upstream-url` or `GILD_VAULT_UPSTREAM`,
it checks the peer heartbeat before accepting writes. If the peer epoch is
higher than the local epoch, the node stays up for local reads, sets its fenced
flag, and refuses put/delete requests until an operator explicitly resets the
fence. If the peer cannot be reached during this boot-time check, the daemon
fails open, logs and audits `peer_unreachable_fail_open`, and accepts writes.
Single-node authoritative mode skips the check when no upstream is configured.

Manual split-brain recovery:

1. Confirm which node has the canonical vault contents.
2. Run `gild vault force-authoritative` on that node.
3. Restart that node's `gg.tana.gild-vault.service`.
4. Start every other node as a replica pointed at the canonical node so it
   demotes and re-syncs before serving.

## Protocol

Each connection sends one JSON request and receives one JSON response:

```json
{"op":"health"}
{"op":"get","key":"ANTHROPIC_API_KEY"}
{"op":"put","key":"FOO","value":"bar"}
{"op":"list"}
{"op":"delete","key":"FOO"}
```

The default socket is `/run/gild-vault.sock`. Override it with
`GILD_VAULT_SOCKET` or `--socket`.
