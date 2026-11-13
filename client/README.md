# harar

harar's client for Rust. It talks to a harar primary, or the per-user agent
(`harar agent`), over its local socket; it holds no secrets itself. Who you are
is the OS user your program runs as: the kernel tells harar.

```toml
[dependencies]
harar = "0.4"
```

```rust,no_run
use harar::{VaultClientError, vault};

async fn example() -> Result<(), VaultClientError> {
    // The harar agent on this machine (`harar agent`): no account, no token.
    // It answers only the user it runs as, and the first time a terminal
    // asks, it asks you to approve (Touch ID on a Mac).
    let harar = vault();

    // A `harar://` reference names a vault key, as `op://` names a 1Password
    // field. The value is read now and held only in memory.
    let key = harar.secrets().resolve("harar://prod/shop/STRIPE_KEY").await?;
    let both = harar.secrets().resolve_all(&["harar://prod/shop/STRIPE_KEY", "harar://prod/site/DATABASE_URL"]).await?;

    // A primary's socket instead of the agent's.
    let primary = harar::VaultClient::from_socket_path(harar::DEFAULT_PRIMARY_SOCKET);
    let database_url = primary.secrets().resolve("harar://prod/site/DATABASE_URL").await?;
    Ok(())
}
```

A gateway that attaches a key on its way out asks where it may go, and for
it for one host only: `hosts("prod/shop/STRIPE_KEY")` and
`send("prod/shop/STRIPE_KEY", "api.stripe.com")`.

## At a harar edge

A service off your network (Railway, Vercel, CI) resolves the same references at
a [harar edge](https://github.com/addiscorp/harar/blob/main/docs/edge.md) in your own
Cloudflare, Vercel or Supabase account, with a service token from
`harar edge token create`. The token comes from the platform's secrets; pass it in.
It reads only what its token allows, and every read is in the edge's log.

With the `edge` feature (`cargo add harar --features edge`):

```rust,ignore
let harar = harar::edge("https://harar-edge.you.workers.dev", &token)?;
let key = harar.secrets().resolve("harar://prod/shop/STRIPE_KEY").await?;
```

hosts and send stay on the local socket: they are for gateways.

harar itself is the binary, installed from its releases, not from crates.io:

```sh
curl -fsSL https://harar-releases.addis.gg/install.sh | sh
```

JavaScript and TypeScript use the npm package `harar` (`import { vault } from
'harar'`). More at https://harar.addis.gg.
