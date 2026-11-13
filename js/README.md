# harar

harar's client for JavaScript and TypeScript (Node and Bun).

```ts
import { vault } from 'harar'

// The harar agent on this machine (`harar agent`): no account, no token.
const harar = vault()

// A harar:// reference names a vault key, as op:// names a 1Password field.
const key = await harar.secrets.resolve('harar://prod/shop/STRIPE_KEY')
const [a, b] = await harar.secrets.resolveAll(['harar://prod/shop/STRIPE_KEY', 'harar://prod/site/DATABASE_URL'])
```

The value is read when you ask for it and held only by your program; nothing
is written to disk. The agent answers only the user it runs as, and the first
time a terminal asks, it asks you to approve (Touch ID on a Mac).
`vault({ socket: '/run/harar.sock' })` talks to a primary instead.

A gateway that attaches keys on their way out (`import { gateway } from
'rixse'`) asks where each may go, and for it for one host only:
`hosts(secret)` and `send(secret, host)`. A refusal, or a harar that cannot be reached, is an error naming why.

## The org's members

An identity service on the primary's machine (id.addis.gg) keeps people and
agents in step with the primary over its local socket:

```js
import { actors } from 'harar'

const members = actors() // the primary at /run/harar.sock
await members.add('gg.addis.agent.ava')      // again: ok, nothing changes
const ava = await members.show('gg.addis.agent.ava') // { name, groups, addedAt, addedBy }, or null
await members.remove('gg.addis.agent.ava')   // with every binding naming it
```

`groups` is read from the policy each time: the roles bound to the member in
every zone. The OS user the service runs as needs a role allowing
`approve actors.*` (or `actors.add`, `actors.remove`, `actors.show`). A
refusal, or a primary that can't be reached within `timeoutMs` (10 s), is an
error, so a caller can fail closed.

## At a harar edge

A service off your network (Railway, Vercel, CI) resolves the same references at
a [harar edge](https://github.com/addiscorp/harar/blob/main/docs/edge.md) in your own
Cloudflare, Vercel or Supabase account, with a service token from
`harar edge token create`. The token comes from the platform's secrets; pass it in.
It reads only what its token allows, and every read is in the edge's log.

```js
const harar = vault({ edge: 'https://harar-edge.you.workers.dev', token: process.env.HARAR_EDGE_TOKEN })
const key = await harar.secrets.resolve('harar://prod/shop/STRIPE_KEY')
```

hosts and send stay on the local socket: they are for gateways.

harar itself: https://github.com/addiscorp/harar
