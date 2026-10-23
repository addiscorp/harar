# harar design

harar is a free, open-source vault for developers and the agents they run. It
does three jobs:

1. **Keeps secrets off disk.** Files and environments hold `harar://`
   references; real values exist only inside the process that needs them, for
   as long as it runs.
2. **Keeps real credentials out of agent sandboxes.** An agent in a VM holds a
   placeholder; harar swaps in the real credential on the way out, outside the
   VM.
3. **Is the OIDC issuer between our services.** A service never holds another
   service's password. It gets a short-lived signed token that says who it is,
   and the receiver checks it against harar's public keys.

The threat model is in [threat-model.md](threat-model.md).

## Decisions

| | Decision |
|---|---|
| D1 | Works with no account. Sync signs in to a provider through standard OIDC (device-code flow). First provider: Simien ID at `id.simien.dev` once it exists. |
| D2 | Sync is end-to-end encrypted. The sync server stores only encrypted blobs. |
| D3 | The repository stays private until a security review. |
| D4 | Shared CLI scaffolding lives in addiscorp. harar currently has no dependency on it. |
| D5 | The old vault data on demon (`/var/lib/gild-vault`) is left untouched until its tokens are rotated. |
| D6 | Developer secrets first. No browser autofill in v1. |
| D7 | Issuer: `https://id.simien.dev`. Configurable until that exists. |
| D8 | Approvals reach the user as a Mac notification first. A chat message alone is never an approval. |

Standing rules:

- Rust only. The TypeScript vault on `reference/ts-vault` is reference
  material for the port, never built on.
- No homemade cryptography. `age`, XChaCha20-Poly1305, Ed25519, P-256 (ES256)
  and the platforms' key stores only.
- Every phase ends with something in real use.

## Pieces

| Piece | Runs as | Job |
|---|---|---|
| `harar` CLI | the user | every command below |
| user agent | one per user, started by launchd (macOS) or systemd `--user` (Linux) | holds the unlocked vault key in locked memory; approves terminals; SSH agent |
| host agent | one per host, system service | identifies local services by OS user; signs token requests with the host's hardware key |
| issuer + vault server (`harar serve`) | system service | stores secrets, issues tokens, publishes the discovery document and JWKS, replicates |
| broker (`harar proxy`) | system service on agent hosts | swaps placeholders for real credentials on outbound requests |

Callers reach an agent over a Unix socket. The agent identifies the caller
from the kernel: `SO_PEERCRED` on Linux, `getpeereid` + `LOCAL_PEERPID` on
macOS. Callers never present a password to their own machine's agent.

## Keys at rest

The store is encrypted under a random vault key. The vault key is stored only
wrapped:

- **macOS with a Secure Enclave** (Apple silicon, Intel with T2): wrapped to a
  P-256 key created in the Secure Enclave through the Security framework with a
  user-presence access control. Approval is Touch ID where there is a sensor,
  otherwise the login password or an Apple Watch. The key cannot be exported.
- **Linux**: wrapped to a TPM-bound key where a TPM exists, otherwise to a
  passphrase.
- **Intel Macs without T2**: wrapped to a passphrase, with the wrapped key in
  the login Keychain. `harar status` reports this as the software tier, and
  rules can refuse it.
- **Recovery**: a second copy wrapped to a recovery passphrase the user keeps
  offline. Never stored next to the hardware-wrapped copy.

Each device is a separate recipient of the vault key. Adding a device means an
existing device re-wraps the vault key to the new one. Removing a device
rotates the vault key.

## Identity (OIDC)

harar issues JSON Web Tokens and publishes
`<issuer>/.well-known/openid-configuration` and a JWKS. It signs with ES256,
which cloud providers accept, alongside today's Ed25519.

Who proves what:

- **Hosts** prove themselves with a hardware key (TPM, or Secure Enclave
  including T2) registered once with `harar host enroll` and approved by an
  admin.
- **Services on a host** are named by the host agent from the OS user calling
  its socket (`svc:gild@demon`).
- **VMs** are named by the gild host that started them. The VM asks over
  vsock; the host knows which VM is asking, so a VM cannot claim to be another.
- **Runs** carry the facts gild registered when it started them: repository,
  commit, workflow file, branch, environment, who started it.
- **Delegation** uses the `act` claim. A service acting for an agent acting for
  a person carries the whole chain, and receivers authorize against it.

Lifetimes: 5 minutes for service calls, at most the length of a run, never more
than one hour.

Three ways a caller gets access:

1. **Direct.** The receiver trusts harar's issuer (our own services, clouds
   with OIDC federation, trusted publishing).
2. **Exchange.** harar uses an admin credential only it holds to create a
   short-lived, narrowly scoped credential at the provider, and deletes it when
   the session ends.
3. **Broker.** For providers that only accept a fixed key. The caller holds a
   placeholder; the broker swaps in the real key for allowlisted hosts and
   blocks and logs everything else.

## Scenarios

The plan page walks through twelve: gild calling simien for an agent; an agent
in a VM needing a token (direct, broker, not-yet-granted); an agent-started
run that builds and deploys; a deployed app reading secrets; local
development; a new host joining; sub-agents; a provider without OIDC; key
rotation; a rogue agent; a lost laptop; the server being down.

## Commands

Names in the first two rows exist (#14–#21). The rest are proposed; `mint` becomes `token`.

| Group | Commands |
|---|---|
| Master key | `key init [--file-tier]` `key status` `key recover` |
| Your vault | `agent` `agent plist` `unlock` `lock` `status` `get` `put` `list` `delete` `run` `import` `inject` `plugin init/run/list` `ssh keygen` `ssh list` |
| Devices | `device add` `device list` `device remove` |
| Identity tokens | `token` `exchange` `verify` `keys rotate` `keys list` |
| Fleet | `host enroll` `host approve` `host list` `workload add` `workload list` |
| Rules | `policy allow` `policy deny` `policy show` `policy test` `env rule` `secret grant` |
| Approvals | `request` `approvals list` `approvals approve` `approvals deny` |
| Sessions | `session list` `session tree` `session revoke` `env` |
| Short-lived provider keys | `dynamic add` `token --dynamic` |
| Audit and recovery | `audit` `restore` `status --fleet` |
| Servers | `serve` `proxy` `agent` |

## Phases

0. This document and the threat model.
1. Build from crates.io on macOS and Linux, harar names, CI.
2. The personal vault on the Mac: Secure Enclave key, user agent, `run`,
   `import`, `inject`, CLI plugins, SSH agent. Done when no plaintext tokens
   are left on the T2 iMac.
3. Identity and broker: ES256 issuer, host enrollment, VM identity, rules,
   approvals, broker. Done when an agent finishes a task with no real token in
   its environment.
4. Sync and teams.
5. Simien: platform secrets and sandbox credentials.
