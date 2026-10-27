# harar

harar's client for JavaScript and TypeScript (Node and Bun).

```ts
import { vault } from 'harar'

const v = vault({ socket: '/run/harar.sock' })
await v.hosts('prod/shop/STRIPE_KEY')                  // where it may go: ['api.stripe.com']
await v.send('prod/shop/STRIPE_KEY', 'api.stripe.com') // the key, for that host only
```

`vault` is the shape a gateway asks for (`import { gateway } from 'rixse'`):
harar decides every send and records the host, and this client holds
nothing. It speaks to a per-user agent (`harar agent`, where `harar hosts
allow <secret> <host>` sets the hosts) or a primary (where a role's `send`
permission does).

harar itself: https://github.com/addiscorp/harar
