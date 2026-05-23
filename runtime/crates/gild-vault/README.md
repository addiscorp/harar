# gild-vault

Host-local secrets proxy for Tana services. Workloads connect over
`/run/tana-vault.sock`; the agent identifies the caller with `SO_PEERCRED`,
maps it through `/etc/tana-vault-agent/workloads.toml`, and forwards allowed
secret reads to the vault upstream with a short-lived JWT.

## Attestation providers

Select the JWT signing provider with `TANA_VAULT_AGENT_ATTESTATION`.

| Value | Use | Notes |
| --- | --- | --- |
| `hs256-dev` | local development | Default for backward compatibility. Reads `/etc/tana-vault-agent/dev-key`. |
| `tpm` | Linux hosts with TPM 2.0 | Requires a binary built with `--features tpm` and access to `/dev/tpmrm0` or `/dev/tpm0`. |

The TPM provider uses `tss-esapi` to initialize an ESAPI context from
`TSS2_TCTI` (also accepts the `tss-esapi` defaults `TPM2TOOLS_TCTI`, `TCTI`, and
`TEST_TCTI`), creates an unrestricted RSA signing primary key in the owner
hierarchy, caches the handle in-process, and signs JWTs as `RS256`. The private
key never leaves the TPM.

## demon setup

Build the agent with TPM support on the Linux host:

```sh
cargo build --release -p gild-vault --features tpm
sudo install -m 0755 target/release/tana-vault-agent /usr/local/bin/tana-vault-agent
```

Install `tpm2-tss` and make sure the service can access the TPM resource
manager:

```sh
sudo usermod -aG tss root
sudo test -c /dev/tpmrm0 || sudo test -c /dev/tpm0
```

Set the provider in a systemd drop-in on demon:

```ini
# /etc/systemd/system/gg.tana.vault-agent.service.d/10-attestation.conf
[Service]
Environment=TANA_VAULT_AGENT_ATTESTATION=tpm
Environment=TSS2_TCTI=device:/dev/tpmrm0
SupplementaryGroups=tss
DeviceAllow=/dev/tpmrm0 rw
DeviceAllow=/dev/tpm0 rw
```

Then reload and restart:

```sh
sudo systemctl daemon-reload
sudo systemctl restart gg.tana.vault-agent
```

## TPM simulator tests

The TPM-backed tests are ignored by default because they need either real TPM
hardware or `swtpm`.

Install runtime dependencies:

```sh
sudo apt-get install -y swtpm tpm2-tools tpm2-abrmd libtss2-dev
```

Start a simulator:

```sh
mkdir -p /tmp/tana-vault-agent-swtpm
swtpm socket \
  --tpm2 \
  --tpmstate dir=/tmp/tana-vault-agent-swtpm \
  --ctrl type=tcp,port=2322 \
  --server type=tcp,port=2321 \
  --flags startup-clear
```

Run the TPM tests in another shell:

```sh
export TSS2_TCTI="swtpm:host=127.0.0.1,port=2321"
cargo test --release -p gild-vault --features tpm -- --ignored tpm
```

Default tests do not require TPM libraries:

```sh
cargo test --release -p gild-vault
```
