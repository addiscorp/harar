# harar

harar's client for Rust. It talks to a harar primary, or the per-user agent
(`harar agent`), over its local socket; it holds no secrets itself. Who you are
is the OS user your program runs as: the kernel tells harar.

```toml
[dependencies]
harar = "0.2"
```

```rust,no_run
use harar::{VaultClient, VaultClientError};

async fn example() -> Result<(), VaultClientError> {
    let v = VaultClient::from_socket_path(harar::DEFAULT_PRIMARY_SOCKET);
    let database_url = v.get("prod/site/DATABASE_URL").await?;

    // Where a secret may go, and the secret for that host only.
    let hosts = v.hosts("prod/shop/STRIPE_KEY").await?; // ["api.stripe.com"]
    let key = v.send("prod/shop/STRIPE_KEY", "api.stripe.com").await?;
    Ok(())
}
```

harar itself is the binary, installed from its releases, not from crates.io:

```sh
curl -fsSL https://harar-releases.addis.gg/install.sh | sh
```

JavaScript and TypeScript use the npm package `harar` (`import { vault } from
'harar'`). More at https://harar.addis.gg.
