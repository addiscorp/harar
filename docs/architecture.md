# harar architecture

This is the design harar is built to. Code that disagrees with it is a bug in
one or the other; fix whichever is wrong in the same PR.

## 1. Concepts

| Concept | What it is | Example |
|---|---|---|
| **org** | The top boundary. Each org has its own **primary**: its own policy, vault, issuer and keys. | `gg.addis`, `com.acme` |
| **actor** | Who is responsible for a request. An agent always acts for someone; it is never its own root. | `gg.addis.human.sami`, `gg.addis.agent.ava`, `gg.addis.service.gild` |
| **user** | An app's end user: a consumer of what the org runs, never an authority in it (section 3a). | `com.acme.user.u-8f3a9c2e` |
| **zone** | Where code runs. Zones nest (machine → VM → container → process), and each has its own identity. | `gg.addis.zone.demon`, `gg.addis.zone.vm-01jbx4k2` |
| **broker** | The harar process on one machine. It proves the machine's identity to the primary, registers the zones it starts, tells the primary which zone is calling, and proxies outbound calls. | `gg.addis.broker.demon` |
| **role** | A named set of permissions: verbs on resources. | `gg.addis.role.site-runtime` |
| **profile** | What kind of zone a broker may start, and the label the primary matches bindings against. | `gg.addis.profile.build-vm` |
| **trust** | A rule that accepts tokens from another issuer (GitHub Actions, another harar org) for specific claims. | GitHub's issuer, `repo = addiscorp/site` |

The **primary** is `harar serve` for one org: policy, vault, issuer, audit. It
is the most locked-down machine the org owns.

## 2. Names

Every identity is a reverse-DNS name:

```
<org>.<kind>.<local>
gg.addis.agent.ava
```

- `org` is two or more labels, the org's domain reversed (`addis.gg` → `gg.addis`).
- `kind` is one of `human`, `user`, `agent`, `service`, `broker`, `zone`, `role`, `profile`.
  `human` is a member of the org; `user` is someone using its apps.
  These words are reserved and are never an org label.
- `local` is one label.
- A label is `[a-z0-9-]`, 1–63 characters, not starting or ending with `-`.
  The whole name is at most 253 characters.
- Short-lived zones get an id that is never reused: `vm-`, `ct-`, `sb-`, `run-`
  followed by a ULID. A reused name would hand a new zone an old zone's history.
- **A name never grants anything by its shape.** Zone names are flat; a zone's
  parent is a field, not a prefix. Patterns in bindings (`gg.addis.agent.*`) match
  one kind in one org only.

An org owns its name by a DNS TXT record on its domain that names its issuer
URL. That record is how another org finds the issuer when it decides to trust it.

## 3. The request rule

A request is allowed when **all** of these hold:

1. The token was signed by the org that owns the resource, or by an issuer that
   org trusts for exactly these claims (section 10).
2. Some **binding** in that org matches the request's actor and zone, and its
   role allows the verb on the resource.
3. If the actor acts for someone (`act` chain), the request also fits inside the
   **session** that someone started for it. A session only narrows; it never adds.
4. Every zone and session involved is live: registered, not expired, not revoked,
   and every parent is live too.

```
binding: actor pattern × zone pattern → role
role:    [ verb resource-pattern, … ]
```

Verbs: `read` and `write` (secrets), `token` (identity tokens for an audience
and scope), `launch` (start a zone of a profile), `approve` (an approval class).

```
role gg.addis.role.site-runtime
  read  secret prod/site/*
  token https://api.simien.dev deploy:site

binding  actor gg.addis.service.site  zone gg.addis.zone.demon  → gg.addis.role.site-runtime
binding  actor gg.addis.agent.*       zone profile:gg.addis.profile.build-vm → gg.addis.role.build
```

One function, `model::decide`, implements this rule. Everything that decides
(the primary, brokers) calls it; nothing reimplements it.

## 3a. App users

- A user has no power by default: with no binding, they get nothing.
- Whatever a binding says, a user only ever gets **tokens for the org's apps**.
  `decide` refuses them `read`, `write`, `launch` and `approve`, so no policy
  mistake can hand an app's customer the vault, a machine or an approval.
- Users are not rows in policy. The app's sign-in issues their tokens, and one
  binding (`com.acme.user.*`) gives every user the same role.
- Power over the things the app offers them (their project, their documents)
  lives in the app: scopes in their token (`project:p-123:admin`) and row-level
  security in the app's Postgres (`owner = harar.actor()`, section 9).

## 4. Zones and launch profiles (no inheritance)

- A **machine** zone proves itself with its host key (TPM, Secure Enclave, or a
  0400 key file reported as software). A human approves it once, at enrollment.
- A **child** zone (VM, container, sandbox) is registered by the broker that
  started it. The broker may only register profiles its own role allows it to
  `launch`. It may narrow the profile (shorter life, fewer audiences), never widen it.
- **A child zone's permissions come only from bindings that match its profile.**
  Nothing flows from the parent machine, the broker, or the session that asked for it.
- The broker's only power over a child is to attest "the caller on CID 7 / this
  socket is that zone". A zone is only as honest as its parent; the launch
  allowance bounds what a dishonest parent can do.
- Transports: VMs over vsock (the hypervisor reports the CID); containers and
  sandboxes over a socket the broker creates for that zone alone. A zone never
  receives a long-lived token.

## 5. Tokens

Identity tokens are JWTs signed with ES256 (default) or EdDSA. Receivers find
the keys at `<issuer>/.well-known/openid-configuration` → `jwks_uri`.

| Claim | Meaning |
|---|---|
| `iss` | The org's issuer URL |
| `sub` | The actor |
| `act` | Who the actor acts for, nested (RFC 8693) |
| `zone` | The zone the request came from |
| `via` | The broker that vouched for the zone |
| `org` | The org name |
| `aud`, `scope` | One audience; space-separated scopes |
| `iat`, `exp` | Default life 5 minutes, never more than 1 hour |
| `jti` | Unique id |
| `txn` | The transaction id that follows a request across services (section 8) |

## 6. Approvals and policy changes

- Policy changes are **propose → approve → apply**. Each applied change is a new
  `policy_version`, signed by its approver and chained to the previous version.
- Approvals belong to **classes** (`policy.widen`, `deploy.production`,
  `broker.request`, …). Narrowing (removing access, revoking a machine) never
  waits: it applies at once, so access can always be cut off.
- A person approves with one of their **approver devices**: a key that lives in
  hardware they carry and signs only after Face ID, Touch ID or a PIN. Being
  logged in as an OS user is never an approval.
- An approval is a signature over the exact request and the device's own id
  (`approvals::ApprovalRequest::challenge`, a fixed binary encoding pinned by
  known answers), so it can't be replayed onto anything else. The device shows
  text computed from those same fields.
- Device kinds, all the same to the primary:
  - **phone**: the Vault in the Simien app (iOS Secure Enclave, Android
    StrongBox), with push notifications;
  - **passkey** (WebAuthn): the primary's approval page, one credential per
    ceremony, with the full WebAuthn checks;
  - **Mac**: a Secure Enclave key made for approving, separate from the
    agent's own key.

### Reserved classes: only a person
Only a person, on their own device, approves what could take over or blind the
whole system (`approvals::RESERVED_CLASSES`, matched on whole segments):
1. `device.*`: adding or removing approver devices;
2. `approvals.*`: changing who may approve what, including a coordinator's
   powers and which classes it may approve;
3. `audit.*`: turning off or removing the audit trail;
4. `trust.*`: trusting another org or issuer;
5. `keys.*`: rotating the master key or the signing keys;
6. `recovery.*`, `setup.*`, `hosts.*`, `issuer.*`, `store.*`,
   `policy.rollback`: things that stand in for a device, join the trust root,
   or could undo every narrowing at once.

Also reserved, whatever the class says: **any change that gives anyone approver
rights** (`grants_approval`, or `Action::Approve`), and any malformed class. A
reserved class needs the primary's `reserved_devices` count of distinct keys
(1 to start; 2 once every approver has two devices), and never a synced passkey.

### A coordinator
A coordinator agent (a "CTO") may approve the classes a person switched on for
it (say `deploy.*`, `policy.widen`), including widening other agents' reach, so
orchestration isn't held up. The safety is in the blast radius and the record:
- **It can never make another approver, nor widen one**: granting approver
  rights is reserved, and a coordinator refuses anything that widens any name
  holding `approve`. So coordinators can't promote each other, and only a
  person widens what any approver holds.
- **Every request says whose reach it widens** (`Reach`: nobody, these
  actors, anything these patterns match, or unknown). It's signed and shown.
  A coordinator never approves an unknown reach, or one that touches itself or
  anything that started it, by name or by a pattern that matches it.
- Nothing it acts through: it never widens, or approves a request from, what
  started it, whom it acts for, or anything it started, nor a sibling under
  the same agent.
- A device enrolled with a recovery code waits a day before it may approve
  reserved classes (it can deny at once), so a stolen code isn't instant full
  control.
- A name that holds no `approve` today can be widened by a coordinator; if a
  person later makes it an approver, it keeps that reach.
- Classes it wasn't given, misspelled ones included, fail closed.
- The primary adds: every coordinator approval audited with its lineage, a
  daily digest to the person, optional rate limits per class, and revoking its
  delegation from any device taking effect at once.

A fresh primary starts with no coordinator; enabling one is an `approvals.*`
change, a person's alone. `policy.widen` by a person needs one device and may
use a synced passkey: the person's choice for now.

### Getting in without a device
- **A new primary prints a one-time setup link** to the terminal, never to a
  log, for the person who will own it. Opening it enrolls their first device.
  It works once, for 24 hours, and is gone as soon as any device exists.
- **Recovery codes.** Enrolling a first device shows ten one-time codes, to
  keep in a password manager or print. Each works once, only for its owner;
  using one enrolls a new device, and every other device is told. A new set
  replaces the old one, and making one is a reserved `recovery.*` change.
- **In an org, an admin can recover a member**, as in any workspace.
- A phone approves; it never holds the vault's master key. Servers unlock
  without anyone present, so the vault's keys stay on the primary.

## 7. Storage

Your Mac keeps its encrypted vault file. The primary stores everything in Postgres.

**The key ladder:**

1. Hardware key: inside the TPM or Secure Enclave, never readable. Unseals 2.
2. Master key: 32 random bytes, on disk only sealed by 1, in memory while unlocked.
3. Data key: 32 random bytes per secret version, stored wrapped by 2.
4. The secret: encrypted by its data key.

Encryption is XChaCha20-Poly1305. The associated data is `org | path | version`,
so a ciphertext moved to another row, or an old version restored in place of a
new one, fails to decrypt or is detected.

**Postgres holds ciphertext, never a key that decrypts it.** harar encrypts
before writing and decrypts after reading.

| Table | Holds |
|---|---|
| `harar.secrets` | `org, path, version, ciphertext, wrapped_key, master_key_id, written_by, written_at, txn` |
| `harar.secret_heads` | The latest version of each path, signed by the primary (rollback detection) |
| `harar.actors`, `harar.zones`, `harar.profiles`, `harar.roles`, `harar.bindings`, `harar.trust` | Policy, in plain form |
| `harar.policy_versions` | Every applied change: diff, approver, signature, previous hash |
| `harar.sessions`, `harar.runs`, `harar.approvals`, `harar.replay` | Short-lived state, with expiry |
| `harar.audit` | Section 8 |

- The primary connects over the local socket with peer authentication, as the
  `harar` OS user. No password.
- The primary keeps policy in memory and decides locally. Postgres is the record
  and the query layer, not the per-request decision path.
- If Postgres is unreachable, reads continue from memory and audit events queue
  locally, signed. Approvals and policy changes are refused until it is back.

## 8. Audit

Every decision, allowed or refused, is one row in `harar.audit`:

```
seq, at, txn, org, actor, act_for, zone, via, action, resource,
decision, by_role, policy_version, reason, prev_hash, hash
```

- `hash = sha256(prev_hash || canonical row)`. Changing or deleting a row breaks
  every later hash.
- The primary signs a checkpoint (latest `seq` and `hash`) every minute and copies
  it off the machine. `harar.verify_chain()` checks the table against them.
- `txn` is a ULID created at the first hop and carried in the token's `txn` claim
  and the `harar-txn` header, so one deploy can be followed from gild through
  harar to simien.
- Relationships (who vouched for whom, which session started which zone, which
  tokens a zone got) are mirrored into zega through pg_zega.

## 9. pg_harar

A Postgres extension (Rust, pgrx), in `addiscorp/pg_harar`. It holds **public
keys only**; it never decrypts anything.

- `harar.authenticate(token)` checks a harar token with the org's public keys
  (the same verification function harar itself uses) and sets the request's
  identity for the transaction.
- `harar.org()`, `harar.actor()`, `harar.zone()`, `harar.act_for()` for row-level
  security policies.
- `harar.audit` is append-only at the database level: updates and deletes are
  refused, and each insert's `prev_hash` and `hash` are computed by the extension.
  `harar.verify_chain()` reports the first broken row.
- Statements run under a harar identity can be recorded in the same trail with
  the request's `txn`.
- A `harar.sealed` column type for app data: ciphertext only, excluded from zega
  sync.
- Shipped as an image on top of `addiscorp/pg_zega`.

## 10. Trust between orgs

`harar.trust` rows accept another issuer's tokens:

```
issuer   https://token.actions.githubusercontent.com
match    repository = addiscorp/site, workflow_ref = addiscorp/site/.github/workflows/deploy.yml@refs/heads/main
as       actor gg.addis.service.ci-site  zone gg.addis.zone.github-actions
```

The matched token becomes that actor and zone; bindings decide the rest. Two
harar orgs trust each other the same way, for named claims only. A customer org's
primary is its own root; Addis services accept its tokens only through trust rows.

## 11. From the current code

The primary runs on this model only (#56): `harar serve --org`, `harar policy`
and `harar token` decide by actors, zones and bindings, and the old workload,
grant, mint, proxy and setup commands are gone.

| Before | Now |
|---|---|
| Mac agent, Secure Enclave master key, `run`, `import`, `inject`, plugins, SSH (#14–#21, merged) | Kept as is: the personal vault |
| Issuer, JWKS, token verification (#30) | Kept; claims extended per section 5 |
| Workloads and grants (`harar:identity`, #30/#31) | Replaced by actors, roles and bindings |
| Sessions and token exchange (#31) | Kept as the narrowing step in rule 3 |
| Egress broker and placeholders (#32) | Kept; becomes part of the local broker |
| Runs and env rules (#33) | Runs become short-lived zones; env rules become bindings |
| Host enrollment (#35) | Machine zones and broker enrollment |
| VMs bound to a session (#36) | VMs as profile-matched zones; vsock transport kept |
| `is_admin` by uid | Signed approvals (section 6) |
| Vault file + plaintext replication log | Postgres (section 7); #39 fixed first |

PRs #31–#36 stay open as reference until their code is moved over.

## 12. Decided

- **The Addis primary is bugsy** (a Mac): `harar serve --postgres … --org gg.addis`.
  - Its key ladder starts at bugsy's Secure Enclave, with a key that doesn't
    require presence, so the primary restarts with nobody there. The chip
    still keeps the key from being copied.
  - bugsy is the command centre for Addis and Simien. It is factory-reset
    before setup, and no CI runner is installed on it: private-repo builds run
    elsewhere.
- **The issuer for `gg.addis` is `https://account.addis.gg`**, Addis's account
  service (not built yet). Until it is, the issuer URL is configured per
  primary. Names avoid "id" for the account system.

## 13. Open questions

1. Rate limits and the daily digest's shape for a coordinator.
2. Whether customer orgs run their own primary, use one hosted in Simien Cloud,
   or either.
3. Failover: the rollback anchor is per host, so a standby primary needs the
   anchor to travel with it.
