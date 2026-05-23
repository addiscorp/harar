# gild-vault-client

Rust SDK for reading process secrets from `gild-vault`.

The crate assumes `gild-vault` is already running on the host and
listening on `/run/tana-vault.sock`. The agent owns workload identity, upstream
vault auth, auditing, and TTL policy. This SDK keeps a process-local in-memory
cache with no TTL.

## Usage

```rust
use gild_vault_client::Secrets;

# async fn example() -> Result<(), gild_vault_client::SecretsError> {
let secrets = Secrets::from_socket()?;
let stripe_key = secrets.get("STRIPE_SECRET_KEY").await?;

let boot = secrets.boot(&["DATABASE_URL", "REDIS_URL"]).await?;
let database_url = boot.get("DATABASE_URL").expect("DATABASE_URL returned");
# Ok(())
# }
```

## API

- `Secrets::from_socket()` creates a client for `/run/tana-vault.sock`.
- `Secrets::from_socket_path(path)` creates a client for a non-default agent
  socket, mostly useful for tests and local development.
- `Secrets::get(key)` returns one secret value, using the in-memory cache on
  repeat calls.
- `Secrets::boot(keys)` fetches a set of keys and returns a `HashMap`.

The wire protocol is HTTP-shaped over a Unix socket:

```text
GET /v1/secret/{key} HTTP/1.1
Host: gild-vault
Accept: application/json
```

The expected success response body is JSON with a string `value` field:

```json
{ "value": "secret-value" }
```
