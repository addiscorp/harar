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

## 3. Who may call what

**Devices** are members paired with the edge. Each has a P-256 key: the Secure
Enclave on a Mac or iPhone, a TPM or key file elsewhere. A device signs every
request:

```
Harar-Device:    <device id>
Harar-Time:      <unix seconds>
Harar-Nonce:     <16 random bytes, base64url>
Harar-Signature: base64url( ECDSA-P256-SHA256 over
                   "harar-edge-v1\n" method "\n" path-and-query "\n" time "\n" nonce "\n" hex(sha256(body)) )
```

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
- In phase 2, members' whole vaults travel between them through the edge
  **encrypted to each member's own key**. The edge stores and forwards that
  ciphertext and can't open it.

So someone who gets into the Cloudflare, Vercel or Supabase account gets the
secrets that edge serves to services, never the vault.

**At rest:** each secret version has its own random data key (AES-256-GCM),
wrapped by the edge key. The associated data is `path | version`, so a
ciphertext moved to another row fails to decrypt. This mirrors harar's own key
ladder.

## 5. The API (phase 1)

All bodies are JSON. Errors are `{ "error": "<code>", "message": "…" }` with a
4xx or 5xx status, and every refusal is logged.

| Endpoint | Caller | Does |
|---|---|---|
| `GET /v1/health` | anyone | `{ version }` |
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

`resolve` takes the same `harar://` references as the clients'
`secrets.resolve`, so a service moves between the local agent and the edge by
changing only how it connects.

## 6. The log

Every request is one row, allowed or refused:

```
seq, at, actor, action, resource, decision, reason, ip, prev_hash, hash
```

- `actor` is `device:<id>`, `token:<id>` or `anonymous`. `action` is one of
  `pair`, `pairing.create`, `device.remove`, `secret.put`, `secret.rotate`,
  `secret.delete`, `secret.list`, `resolve`, `token.create`, `token.revoke`,
  `token.list`, `device.list`, `log.read`.
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
2. **Sync**: a signed, hash-chained op log between members, carried blind
   through the edge. Conflicts: each secret's version, the later write wins,
   and the other is kept in the history and flagged.
3. **harar-app**: the phone pairs by QR code. It is a member, the approver,
   the token manager and the log viewer, and the edge sends its notifications.
4. **Direct peer transport** over a private network, for rings with no edge.
5. **More platforms**, and `harar sync <platform>` to push secrets into a
   platform's own secret store.
