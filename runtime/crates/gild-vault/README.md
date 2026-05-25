# gild-vault

Privileged host-local secret daemon for Gild workloads.

The daemon listens on a Unix socket, authorizes each connection with
`SO_PEERCRED`, stores secrets in memory, and writes age-encrypted persistent
state to `/var/lib/gild-vault/keys.age`. The file-backed master identity lives
at `/etc/gild/vault-master.key`; initialize it with `gild vault init` before
starting the daemon.

Replication metadata is persisted beside the encrypted key envelope:
`keys.replication.json` stores the fencing epoch, monotonic version, and
demoted/fenced state; `keys.replication.log` stores durable put entries and
delete tombstones for replica catch-up.

## Replication Recovery

Automatic replica promotion bumps the epoch by 1000 before accepting writes.
If an older authoritative later sees a higher upstream epoch, it demotes,
sets its fenced flag, and refuses writes until an operator explicitly resets
the fence.

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
