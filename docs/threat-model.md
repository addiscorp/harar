# harar threat model

What harar protects, from whom, and where it stops. Each threat names the
control that answers it and the test or phase that proves it. A control with
no proof yet is marked **planned**.

## Assets

| Asset | Where it lives |
|---|---|
| Secret values (API keys, database URLs, SSH keys) | encrypted store; process memory while in use |
| Vault key | wrapped at rest; locked memory while unlocked |
| Issuer signing keys | issuer host, encrypted at rest |
| Admin credentials for providers (used for exchange) | vault, readable only by the issuer |
| Audit log | issuer and agent hosts, append-only |

## Trust boundaries

1. The user's login session ↔ other users and processes on the same machine.
2. A process on a host ↔ the host's agent (Unix socket, kernel-reported caller).
3. A VM ↔ its host (vsock; the VM is untrusted).
4. A host ↔ the issuer (network; hardware-backed host key).
5. A device ↔ the sync server (network; server is untrusted for contents).

## Attackers

- **A1 Malicious package**: code running as the user, for example an install
  script.
- **A2 Prompt-injected agent**: an agent that follows instructions from data it
  read.
- **A3 Compromised VM**: full control of everything inside an agent's VM.
- **A4 Stolen disk or backup**: offline copy of a machine's files.
- **A5 Lost or stolen device**: the powered machine itself.
- **A6 Network attacker**: can read and change traffic between hosts.
- **A7 Compromised sync server or storage provider.**

## Threats and controls

| # | Threat | Control | Proof |
|---|---|---|---|
| T1 | A1 sweeps `.env`, `~/.npmrc`, `~/.config/*`, `~/.ssh` for tokens | Files hold references; values never written to disk; CLI plugins remove tools' token files; SSH keys live in the agent | planned: phase 2 done-when (no plaintext tokens left on the iMac) |
| T2 | A1 reads secrets of a command already started with `harar run` | Not preventable inside that process. Limited by scoping values per command and per environment, and by short-lived tokens instead of static keys | accepted risk, see Limits |
| T3 | A1 asks the user agent for secrets directly | Agent identifies the calling process and requires approval per terminal session; approvals time out on idle | planned: #5 |
| T4 | Another local user connects to an agent socket | Kernel-reported uid checked on every connection; socket mode 0600 / group-restricted | `peer_credentials_name_the_connecting_process`; real-topology tests (Linux) |
| T5 | A secret passed as a command-line argument leaks via `ps` or shell history | CLI refuses secret values in argv; reads them from stdin, a file descriptor or a prompt | `credential_commands_reject_secret_values_in_argv` |
| T6 | A4 copies the store and the wrapped vault key | Vault key wrapped to a Secure Enclave or TPM key that cannot leave the device; recovery copy wrapped to an offline passphrase | planned: #4 |
| T7 | A4 reads the unlocked key from swap or a core dump | Key held in `mlock`ed memory; core dumps disabled; daemon refuses to start if either fails | planned: port from the TS vault |
| T8 | A5 uses the stolen, powered device | Every unlock needs user presence (Touch ID, password or Watch); the Secure Enclave refuses entirely while the screen is locked; agent locks on idle (screen-lock locking planned); `harar device remove` revokes the device and rotates the vault key | #14 (enclave, verified on a locked T2 iMac), #15 (idle lock, approvals) |
| T9 | A2/A3 exfiltrates a provider key held by the agent | Real keys never enter the VM; placeholders only work through the broker, from that VM, for that session | planned: phase 3 |
| T10 | A2/A3 sends data to an attacker's host | Broker allows only hosts on the secret's allowlist; everything else is blocked, logged and alerted | planned: phase 3 |
| T11 | A3 claims to be another VM or service | VM identity comes from the host over vsock, not from anything the VM says; service identity from the kernel uid | planned: phase 3 |
| T12 | A stolen identity token is replayed | Audience-bound, 5-minute lifetime, `jti`; high-value scopes check revocation on every call | partly: mint, verify and revoke exist; ES256 and revocation checks planned |
| T13 | A sub-agent gets more than its parent | Token exchange only narrows scope and lifetime; revoking a parent revokes its children | planned: phase 3 |
| T14 | An agent approves its own request | Approvals arrive outside the agent's reach (Mac notification with user presence); a chat message is never an approval | planned: D8 |
| T15 | A6 tampers with tokens or secrets in transit | TLS between hosts; tokens signed; secrets end-to-end encrypted between devices | partly |
| T16 | A7 reads or rolls back synced data | Server holds only ciphertext; manifests are signed and chained so rollback and deletion are detected | partly: manifest chain in the TS vault, to port |
| T17 | Issuer signing key is stolen | Key encrypted at rest on the issuer; rotation publishes a new key and drops the old after the longest token lifetime | planned |
| T18 | A user loses every device and the recovery passphrase | Not recoverable by design. Encrypted backups are useless without a recipient | accepted |

## Limits

- **A process you started with secrets can leak them.** harar narrows what each
  process gets and for how long; it cannot stop a process from misusing what it
  was given.
- **Root on a host can read that host's memory.** Hardware keys keep the vault
  key from being copied off the machine, not from being used while the machine
  is compromised.
- **The software tier is weaker.** Intel Macs without T2 and Linux without a TPM
  keep the vault key wrapped to a passphrase only. `harar status` says so and
  rules can refuse those devices.
- **Out of scope for v1**: browser autofill, phishing of website passwords,
  Windows.
