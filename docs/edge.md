# harar edge

The edge is an optional member of your harar ring that is always on. It runs
in **your own** Cloudflare, Vercel or Supabase account; Addis runs nothing.
harar works without it. With it you get:

- **reach for services off your tailnet** (Railway, Vercel apps, CI): they
  resolve `harar://` references with a narrow service token;
- **an always-on mailbox**, so your phone and Mac sync without a shared
  network (phase 2);
- **a sender for your phone's notifications** (phase 3).

This file is the design the edge is built to. Code that disagrees with it is a
bug in one or the other; fix whichever is wrong in the same PR (as
`architecture.md`). Tracking issue: #95.

## 1. The ring, with and without a platform

```
  phone (harar-app) ◄──── sync ────► edge ◄──── sync ────► Mac / laptop (harar agent)
   member + approver           Cloudflare | Vercel |        member
   its own sealed store        Supabase, optional           its own sealed vault
                                    ▲
                                    │ service tokens: resolve, write
                            Railway, Vercel apps, CI, …
```

- **Members** (your Mac, laptop, phone) each hold the whole vault, sealed to
  their own hardware key. They sync with each other through the edge, or
  directly over a private network (tailnet, VPN, VPC) when there is no edge.
- **The edge** is a member that never holds the whole vault (section 4).
- **Services** are not members. They hold one service token each and get only
  what it allows.

Four seams keep this pluggable:

| Seam | Today | Later |
|---|---|---|
| Transport between members | the edge (HTTPS) | tailnet peer, others |
| Edge host | Cloudflare Workers, Vercel Functions, Supabase Edge Functions | any host that runs a web `fetch` handler |
| Edge storage | D1 (SQLite) on Cloudflare; Postgres on Vercel and Supabase | any SQL |
| Client transport | the local agent (`vault()`) | the edge (`vault({ edge, token })`) |

## 2. One file, one adapter per platform

`edge/harar-edge.ts` is the whole API: a standard web `fetch(request)` handler
using only Web APIs (`crypto.subtle`, `Request`, `Response`). It is the same
file on every platform. Each platform adds an entry file of a few lines that
gives it three things:

1. **SQL**: a `query(sql, params)` function. Statements are written once with
   `?` placeholders in SQL that SQLite and Postgres both accept; the Postgres
   adapter numbers them (`$1`, `$2`, …).
2. **The edge key**: 32 random bytes, from the platform's secret store (a
   Worker secret or Secrets Store on Cloudflare, an encrypted environment
   variable on Vercel, a function secret on Supabase). Never in the database:
   someone who copies the database gets ciphertext only.
3. **Config**: written into the entry file by `harar edge init`, not read from
   the environment. The log sinks' tokens are the only other secrets, and they
   come from the platform's secret store too.

`harar edge init --cloudflare|--vercel|--supabase` asks for a folder (default
`./harar-edge`) and writes the core file, the entry file and the platform's
config there (`wrangler.toml`, `vercel.json`, or `supabase/functions/…`). Every
answer also has a flag, so CI can run it, except a secret: those are asked for
with a no-echo prompt and never taken as an argument. The written files carry
harar's version; `harar edge update` (later) refreshes the core file.

`init` never replaces a file. It also writes three 0600 files, which git
ignores: `.harar-edge.key` (the edge key, for the platform's secret store),
`.harar-edge.setup` (the setup code) and `.harar-edge.recovery` (the edge key
encrypted with the recovery code); Supabase also gets `.harar-edge.env`. It
shows the **recovery code** once (section 4a). For Supabase it adds the
function's section to an existing `supabase/config.toml`. It prints the steps
that are left. On Cloudflare:

```sh
cd harar-edge
npx wrangler deploy                                  # the first deploy also creates the D1 database
npx wrangler secret put HARAR_EDGE_KEY < .harar-edge.key
harar edge pair https://harar-edge.<you>.workers.dev --dir .
```

### The CLI

This machine is a device of the edges it pairs with. Its key is in the Secure
Enclave on a Mac, so each signed request asks for Touch ID; elsewhere, or with
`--file-key`, it's a 0600 file. Paired edges are listed in `edges.json`:
in `~/Library/Application Support/harar` on a Mac, `~/.local/state/harar`
on Linux (state that must outlive a reboot, so never `$XDG_RUNTIME_DIR`): the
state folder, where the agent keeps its vault too.

| Command | Does |
|---|---|
| `harar edge init --cloudflare\|--vercel\|--supabase [--dir] [--log-sink]` | writes the folder (above) |
| `harar edge pair <url> [--dir] [--name] [--file-key]` | pairs with the setup code from `--dir`, or a code typed at a no-echo prompt. With `--dir`, it first checks the edge has the folder's key (section 4a), and afterwards removes the key, setup code and recovery copy from disk |
| `harar edge recover [--with-code] [--out <file>] [--env]` | restores the edge key (section 4a), to stdout for piping into the platform, never to a terminal |
| `harar edge pairing` | a one-time code for another device (10 minutes) |
| `harar edge devices`, `harar edge unpair <id>` | the paired devices |
| `harar edge put <path> [--rotate]`, `harar edge delete <path>`, `harar edge secrets` | secrets; the value is typed twice at a no-echo prompt, or `--secret-stdin` |
| `harar edge token create <name> --read <pattern> --write <pattern> [--expires-in <s>]` | a service token, shown once |
| `harar edge token list`, `harar edge token revoke <id>` | the tokens |
| `harar edge log [--after <seq>]` | the log, with its hash chain checked here |

With more than one edge paired, `--edge <url>` says which. Every command
answers in JSON.

## 3. Who may call what

**Devices** are members paired with the edge. Each has a P-256 key: the Secure
Enclave on a Mac or iPhone, a TPM or key file elsewhere. A device signs every
request:

```
Harar-Device:    <device id>
Harar-Time:      <unix seconds>
Harar-Nonce:     <16 random bytes, base64url>
Harar-Signature: base64url( ECDSA-P256-SHA256 over
                   "harar-edge-v1\n" method "\n" api-path-and-query "\n" time "\n" nonce "\n" hex(sha256(body)) )
```

`api-path-and-query` is the path from `/v1/` on, plus the query, without any
prefix the platform mounts the edge under. On Supabase the caller sends
`/functions/v1/harar-edge/v1/secrets` and the function sees
`/harar-edge/v1/secrets`, but both sign `/v1/secrets`.

The signature is raw `r || s` (64 bytes). The edge refuses a time more than 5
minutes off and a nonce it has seen, and keeps nonces for 10 minutes.

**Pairing.**
- `harar edge init` makes a setup code (128 bits) and writes only its SHA-256
  into the entry file. The first device to `POST /v1/pair` with it becomes the
  owner. The code works once.
- Every later device pairs with a code an already-paired device makes
  (`POST /v1/pairings`): one-time, 10 minutes, kept as a hash. The phone pairs
  this way by scanning a QR code.
- Removing a device (`DELETE /v1/devices/{id}`) is immediate. The last device
  can't be removed, so the edge always has an owner.

**Service tokens** are made by a device:
`harar_edge_<id>_<secret>`, shown once. The edge keeps only
`sha256(secret)`. Each token has a name, `read` and `write` path patterns
(exact, or a prefix ending in `*`, as harar's own `prod/site/*`), and an
optional expiry. Revoking one is immediate.

## 4. What the edge can read

**Blind for sync, sees only what it serves.**

- In phase 1 the edge holds only the secrets devices put there for services
  (`PUT /v1/secrets/{path}`), encrypted at rest under its key.
- In phase 2, members' whole vaults travel between them through the edge as
  signed ops **sealed under the ring key**, which only members hold (wrapped
  to each member's own key). The edge stores and forwards that ciphertext and
  can't open it, nor learn secrets' names (section 5a).

So someone who gets into the Cloudflare, Vercel or Supabase account gets the
secrets that edge serves to services, never the vault.

**At rest:** each secret version has its own random data key (AES-256-GCM),
wrapped by the edge key. The associated data is `path | version`, so a
ciphertext moved to another row fails to decrypt. This mirrors harar's own key
ladder.

## 4a. The edge key: where it comes from, and its backups

**Where it comes from.** `harar edge init` takes 32 bytes from the operating
system's random generator. It is never printed, logged or passed as an
argument: it goes into `.harar-edge.key` (0600), and from there to the
platform over stdin (`npx wrangler secret put HARAR_EDGE_KEY <
.harar-edge.key`). The platform then holds it where nobody can read it back,
and the edge reads it per request.

**Its id.** `/v1/health` reports `key: { ready, id }`, where `id` is the first
16 hex of `sha256("harar-edge-key-id\n" || key)`. It says *which* key the edge
has without revealing it.

**Nothing readable stays on disk.** `harar edge pair --dir` refuses until the
edge reports the folder key's id, so the platform certainly has it. Then:

1. **On a Mac**, it seals the key to this Mac's Secure Enclave key (Apple's
   ECIES, as harar's master key) and keeps that in `edges.json`. Only this
   Mac can open it, with Touch ID.
2. It stores the **recovery copy** on the edge (`PUT /v1/recovery`).
3. It removes `.harar-edge.key`, `.harar-edge.env`, `.harar-edge.recovery`
   and `.harar-edge.setup`.

**The recovery code** is for people without the app, and a backup for those
with it.
- `init` shows it once: 28 Crockford base32 characters (140 bits) in groups
  of four, read the way harar's recovery codes are (`o` as `0`, `i` and `l`
  as `1`, any case, dashes optional).
- The key is encrypted with it using age with scrypt (slow to guess), and
  that copy lives on the edge.
- So restoring needs **both the paper and the edge's database**; neither
  alone opens anything.

**If the platform loses the key**, any of these restores it, with nothing
re-entered, because the sealed rows are intact:

```sh
harar edge recover | npx wrangler secret put HARAR_EDGE_KEY               # this Mac: Touch ID
harar edge recover --with-code | npx wrangler secret put HARAR_EDGE_KEY   # the recovery code
```

`recover` refuses to print the key to a terminal. It says whether the edge
has no key, this one, or a different one. Device requests don't use the edge
key, so they work while it is missing.

**The phone (phase 3)** pairs with a Secure Enclave key-agreement key, and the
edge seals its key to it, so every phone holds a copy only it can open.
`/v1/recovery` is for devices only, and every read of it is logged.

**Not yet:** `harar edge rekey`, to move every data key to a new edge key.

## 5. The API

All bodies are JSON. Errors are `{ "error": "<code>", "message": "…" }` with a
4xx or 5xx status, and every refusal is logged.

| Endpoint | Caller | Does |
|---|---|---|
| `GET /v1/health` | anyone | `{ version, key: { ready, id }, log }` |
| `POST /v1/pair` | a new device | `{ code, name, public_key }` → `{ device }`. `public_key` is the raw P-256 point, base64url. |
| `POST /v1/pairings` | device | → `{ code, expires_at }` |
| `GET /v1/devices` | device | the paired devices |
| `DELETE /v1/devices/{id}` | device | unpairs it |
| `GET /v1/secrets` | device | paths and versions, no values |
| `PUT /v1/secrets/{path}` | device, or a token that may write `path` | `{ value, rotate? }` → `{ path, version }` |
| `DELETE /v1/secrets/{path}` | device, or a token that may write `path` | deletes it (a new version with no value) |
| `POST /v1/resolve` | device, or a token that may read each ref | `{ refs: ["harar://…"] }` → `{ values: [...] }` in order. All or nothing: one ref it may not read fails the whole request. |
| `POST /v1/tokens` | device | `{ name, read, write, expires_in? }` → `{ id, token }` (the only time the token is shown) |
| `GET /v1/tokens` | device | the tokens, never their secrets |
| `DELETE /v1/tokens/{id}` | device | revokes it |
| `GET /v1/log?after={seq}` | device | log rows after `seq` |
| `PUT /v1/recovery`, `GET /v1/recovery` | device | the edge key encrypted with the recovery code (section 4a) |
| `PUT /v1/sync` | device | `{ ops: [...] }` (1 to 100) → `{ stored, duplicates }`. All or nothing (section 5a). |
| `POST /v1/sync` | device | `{ since }` → `{ ops, next, more }`, at most 100 ops or about 1 MiB a page (section 5a) |

`resolve` takes the same `harar://` references as the clients'
`secrets.resolve`, so a service moves between the local agent and the edge by
changing only how it connects.

## 5a. Sync: members' ops, stored blind (phase 2, step 1)

The design is #101: one ring key per vault, wrapped to each member's
key-agreement key; every change a signed op, chained per author by hash. The
edge only stores and forwards ops. It never has the ring key, so nothing it
holds opens one. Service tokens can't push or pull.

### An op

```json
{ "author": "d-0123456789abcdef", "seq": 4, "prev": "<64 hex>", "kind": "put",
  "key": "<43 base64url>", "version": 2, "sealed": "<base64url>",
  "wrapped_key": "<base64url>", "at": 1762603200000, "sig": "<86 base64url>" }
```

| Field | Is | The edge checks |
|---|---|---|
| `author` | the device id that wrote it | a device paired now (not removed) |
| `seq` | 1, 2, 3, … per author | exactly the author's last stored `seq` + 1 |
| `prev` | the hash of the author's previous op; `""` for its first | equals that hash |
| `kind` | `put`, `rotate`, `delete`, `member.add`, `member.remove`, `rekey` | one of these |
| `key` | `base64url(HMAC-SHA256(ring key, path))`, no padding | 32 bytes |
| `version` | the secret's version (members' business) | a whole number |
| `sealed` | path and value, sealed under a data key | base64url, at most 48 KiB; may be empty |
| `wrapped_key` | that data key, wrapped by the ring key | base64url, at most 1 KiB; may be empty |
| `at` | the author's clock, unix milliseconds | not more than 5 minutes ahead of the edge's |
| `sig` | ECDSA P-256 SHA-256 by the author's device key, raw `r ‖ s` | verifies over the canonical encoding |

An op with any other field is refused, so what the edge stores is what was
sent. A body is still at most 64 KiB, so an op near the size limit goes in a
PUT of its own.

**`key`, not `path`** (a change from #101): the edge must not learn secrets'
names, so an op names its secret by an HMAC of the path under the ring key,
and the path travels inside `sealed`. The edge can tell that two ops touch the
same secret (it needs that to compact), not which secret. For `member.*` and
`rekey` ops, members choose what they put through the HMAC; the edge treats
`key` the same for every kind.

**The canonical encoding** is what `sig` signs and what an op's hash is of:
every field but `sig`, in this order, one per line, with `sealed` and
`wrapped_key` as the hex SHA-256 of their base64url text:

```
"harar-op-v1\n" author "\n" seq "\n" prev "\n" kind "\n" key "\n" version "\n"
  hex(sha256(sealed)) "\n" hex(sha256(wrapped_key)) "\n" at
```

Numbers are decimal with no leading zeros. No field can hold a newline (each is
hex, base64url, decimal, a device id or a fixed word), so the encoding is
unambiguous. Ciphertext goes in by its hash so an op whose ciphertext was
compacted away still verifies, signature and chain (below).

**The op hash** is `hex(sha256(canonical encoding))`. It leaves out `sig`:
an ECDSA signature isn't unique (a fresh one each time, and `s` can be
flipped), and the op is the same op whoever re-signs it. An author's first op
has `prev = ""`, as the log's first row.

### Pushing: `PUT /v1/sync`

The edge checks the whole batch before it logs or stores anything: every
field, every signature, and each author's chain. A batch may carry ops from
more than one paired device (a member can relay ops it pulled). If any op
fails, the batch is refused and nothing is stored: one `deny` row, its reason
the op's code (`bad_op`, `bad_op_signature`, `unknown_author`, `wrong_seq`,
`wrong_prev`, `fork`, `clock`).

- An op already stored with the same hash is a duplicate, not an error, so a
  PUT whose answer was lost can be sent again. One with the same `author` and
  `seq` but another hash is a `fork`.
- Ops from a device stop being taken the moment it is unpaired, even ops it
  signed before and another device relays. Its ops stored before stay.
- **All or nothing without a transaction**: D1 has none through a plain query,
  and caps a statement at 100 parameters. The rows go in marked with the
  batch's id, which every read and check ignores, and one `UPDATE` clears the
  mark. If another PUT takes one of the batch's places first, the batch's rows
  are deleted and the answer is `409 sync_busy` (as with pairing codes, that
  race is an `allow` row followed by a `deny`). Rows a crashed request left
  marked are deleted by the next PUT after a minute.

### Pulling: `POST /v1/sync`

`since` is `{ "<device id>": <last seq I have> }` (`{}` for everything). The
answer has each author's ops after that seq, by author and then seq; `next`
is the `since` for the following call, and `more` says whether there is more
to read now. Because an author's ops only ever become visible in seq order, a
cursor of each author's last seq never skips one. A member keeps the last
`next` and starts its next sync from it.

Each op comes back as sent, plus `hash`, `sealed_sha256`,
`wrapped_key_sha256` and `compacted`.

### Compaction: 30 days

- **What goes.** A `put`, `rotate` or `delete` op that the edge stored more than
  30 days ago, and that a later op on the same `key` supersedes. Later is
  last-write-wins order: larger `at`, then larger author id, then larger
  `seq`. The latest op on a key is never superseded, so it stays; `member.*`
  and `rekey` ops are never compacted.
- **Age is the edge's time**, when the op was stored, not `at`: every member
  gets 30 days to pull a losing write and flag it, however old its author's
  clock said it was.
- **What stays.** Compacting an op drops its `sealed` and `wrapped_key` and
  keeps the rest: author, seq, prev, kind, key, version, at, sig, the hash and
  the two ciphertext hashes. Such an op comes back with `sealed: null`,
  `wrapped_key: null`, `compacted: true`. A member still recomputes its hash
  from those fields and verifies its signature, so **every author's chain
  verifies from its first op**; the alternative, trusting the oldest retained
  op as a new start, would let an edge hide an op by calling it compacted.
  A compacted op keeps a few hundred bytes.
- **When.** On every sync request, before a pull's answer and after a push
  commits: one `UPDATE` that compacts at most 50 ops. Nothing runs on a
  schedule, so an edge nobody syncs with costs nothing, and the work keeps up
  with the writes that make it.

The edge does not resolve conflicts, check versions or open anything: members
do, by these same rules (#101).

## 6. The log

Every request is one row, allowed or refused:

```
seq, at, actor, action, resource, decision, reason, ip, prev_hash, hash
```

- `actor` is `device:<id>`, `token:<id>` or `anonymous`. `action` is one of
  `pair`, `pairing.create`, `device.remove`, `secret.put`, `secret.rotate`,
  `secret.delete`, `secret.list`, `resolve`, `token.create`, `token.revoke`,
  `token.list`, `device.list`, `log.read`, `recovery.set`, `recovery.read`,
  `sync.put`, `sync.read`. A `sync.put`'s resource is the new ops' places,
  `<author>:<first seq>-<last seq>` per author, never their keys or contents.
- **Values are never logged**, nor tokens or codes.
- `hash = sha256(prev_hash || canonical row)`: changing or deleting a row
  breaks every later hash, as in harar's own audit (architecture §8).
- A request is checked before its row is written, so a refusal is one `deny`
  row. One exception: when two requests race for the same one-time thing
  (a pairing code, the setup code), both pass the check, and the loser's
  `allow` row is followed by its `deny`.
- The canonical row is `JSON.stringify([seq, at, actor, action, resource,
  decision, reason, ip])`, and the hash input is `prev_hash + "\n" + that`.

### Sinks

The log's real home is **outside the platform that holds the secrets**, so
someone who breaks into it can't erase what they did.

- **Format: OpenTelemetry logs over OTLP/HTTP (JSON).** One POST of
  `resourceLogs` to `<endpoint>/v1/logs`, with no SDK. Grafana Loki, Datadog,
  Honeycomb, Axiom, Better Stack, Elastic and the OpenTelemetry Collector all
  take it. Each row is one log record: its fields are attributes
  (`harar.seq`, `harar.actor`, `harar.action`, …), `service.name` is
  `harar-edge`. Prometheus is for metrics, not individual events, so it isn't
  the format for this.
- **Use a sink in a different account, with a write-only key** (an
  ingest-only token, or an S3 or R2 bucket with Object Lock). A breaker can
  then stop new rows or add false ones, but can't delete or read old ones, and
  the hash chain shows the gap.
- The edge keeps every row in its own database too, and marks each as shipped
  once every sink took it. Unshipped rows go out with the next request.

### Configurable

In the entry file:

```ts
log: {
  // Each sink: its OTLP/HTTP endpoint, and the headers it wants. A header
  // that carries a token reads it from the platform's secrets
  // (env.HARAR_LOG_TOKEN), never from this file.
  sinks: [{ otlp: "https://otlp.example.com", headers: { authorization: `Bearer ${env.HARAR_LOG_TOKEN}` } }],
  events: "all",                 // or a list of actions
  whenSinksFail: "serve",        // or "refuse"
}
```

- `serve` (the default): answer, and ship the rows later.
- `refuse`: ship before answering; if any sink fails, answer 503.
- Refusals are always logged, whatever `events` says.
- With no sinks the edge still keeps its own chain, and says so on
  `/v1/health`.

Members keep a copy of the log once they sync it (phase 2), and the phone
raises an alarm when the edge's chain stops advancing (phase 3).

## 7. Phases

1. **The edge** (this design):
   - 1a: the edge file and its three adapters;
   - 1b: `harar edge init|pair|put|token|log` in the CLI;
   - 1c: `vault({ edge, token })` in all six clients.
2. **Sync** (#101): a signed, hash-chained op log between members, carried
   blind through the edge. One personal vault first. Conflicts: the later
   write wins (by `at`, then author id), and the other is kept in the history
   and flagged. Mac sync is opt-in (`harar edge sync on`). 30 days of history,
   then compaction.
   - 2a: `harar_ops` and `/v1/sync` on the edge (section 5a);
   - 2b: the Mac agent as a member, and `harar edge sync on`;
   - 2c: harar-app as a member (with phase 3).
3. **harar-app**: the phone pairs by QR code. It is a member, the approver,
   the token manager and the log viewer, and the edge sends its notifications.
4. **Direct peer transport** over a private network, for rings with no edge.
5. **More platforms**, and `harar sync <platform>` to push secrets into a
   platform's own secret store.
