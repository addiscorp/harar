# harar edge

The one-file API that runs harar's edge in your own Cloudflare, Vercel or
Supabase account. The design, the API and the log are in
[docs/edge.md](../docs/edge.md).

- `harar-edge.ts`: the API, a web `fetch` handler using only Web APIs. The
  same file on every platform. It serves secrets to services (sealed under
  the edge key) and relays members' sync ops (`/v1/sync`, sealed under a ring
  key it never has; docs/edge.md §5a).
- `platforms/<platform>/`: each platform's entry file and config, as
  `harar edge init` writes them next to `harar-edge.ts`
  (`platforms/layout.json` says where).

Nothing here is published to a registry: `harar edge init` writes these files
into your project, at harar's version.

## Checks

```sh
npm ci
npm run typecheck
npm test                                   # SQLite (node:sqlite)
HARAR_TEST_POSTGRES=postgres://… npm test  # and Postgres
test/check-platforms.sh                    # each platform's entry against the core
```

The sync tests play two ring members with a ring key only the test holds:
they seal ops, push and pull them, and check that nothing the edge stores
(nor its own key) opens one, that every refusal is one `deny` row with
nothing stored, and that after compaction every author's chain still
verifies, signatures included.

`test/serve-node.ts <init folder> <port>` serves an edge on this machine
(node:sqlite, no platform), and `test/cli-e2e.sh <harar binary>` drives one
with the harar CLI; CI runs it after building harar.

`test/smoke.ts <base url> <setup code>` runs one user's journey against a
running edge: pair, put, token, resolve, refuse, rotate, revoke, and the log
read back as an unbroken chain. `test/assemble.ts` lays out a platform's
folder; `test/serve-vercel.ts` serves the Vercel entry with Node.
