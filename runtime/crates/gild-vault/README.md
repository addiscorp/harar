# gild-vault

Privileged host-local secret daemon for Gild workloads.

The daemon listens on a Unix socket, authorizes each connection with
`SO_PEERCRED`, stores secrets in memory, and writes a tmpfs mirror to
`/run/gild-vault/keys.json`. The tmpfs mirror is intentionally not persistent
storage; TPM-sealed storage and lease lifetimes are future work.

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
