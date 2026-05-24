# gild-vault-proxy

HTTP proxy for `gild-vault` management calls used by Tana admin tooling.

## Configuration

- `VAULT_PROXY_TOKEN` or `VAULT_PROXY_TOKEN_FILE` configures the bearer token
  accepted by the proxy.
- `VAULT_SOCKET` configures the Unix socket used to reach `gild-vault`.
  It defaults to `/run/gild-vault/sock`, matching the deployed
  `gg.tana.gild-vault.service` runtime directory convention. `GILD_VAULT_SOCKET`
  is accepted as a compatibility fallback when `VAULT_SOCKET` is unset.
- `VAULT_PROXY_PORT` defaults to `9444`.
- `VAULT_PROXY_BIND` overrides the bind address. Without it, the proxy binds to
  the host Tailscale IPv4 address when available, otherwise `127.0.0.1`.

At startup the proxy calls `gild-vault` health on the configured socket before
binding its TCP listener. If the daemon is unreachable, startup fails with an
error that includes the socket path.
