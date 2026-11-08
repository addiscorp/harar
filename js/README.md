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

harar itself: https://github.com/addiscorp/harar
