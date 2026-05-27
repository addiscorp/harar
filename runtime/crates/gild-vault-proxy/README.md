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
- `--bind 0.0.0.0:9444` serves the existing plain HTTP bearer-token mode.
- `--tls-bind 0.0.0.0:9445 --tls-ca /etc/gild/vault-proxy-ca.pem
  --tls-cert /etc/gild/vault-proxy.pem --tls-key /etc/gild/vault-proxy.key`
  serves HTTPS and requires a client certificate signed by the configured CA.
  Bearer authorization still applies after the mTLS handshake.
- `VAULT_PROXY_AUDIT_LOG` defaults to `/var/log/gild-vault-proxy-audit.log`.
  TLS audit records include `tls_client_cn`.
- `VAULT_PROXY_PEERS` is an optional comma-separated list of peer proxy base
  URLs, also configurable with repeated `--peer <url>`. When the local vault
  socket becomes unhealthy, the proxy polls peers once per second, selects the
  healthy peer with the highest vault epoch, and routes vault traffic there.

At startup the proxy calls `gild-vault` health on the configured socket before
binding its TCP listener. If the daemon is unreachable, startup fails with an
error that includes the socket path.

## CA bootstrap

Initialize the local CA:

```bash
gild vault ca init
```

Issue a per-machine client certificate and key bundle:

```bash
gild vault ca issue storefront-droplet-do-01
```

The installer keeps bearer-only mode by default. Re-run
`infra/install-gild-vault-proxy.sh --with-mtls` to generate the local CA, create
the proxy server certificate, and switch the systemd unit to the mTLS listener.
