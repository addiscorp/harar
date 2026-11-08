# harar

harar's client for Go.

```sh
go get github.com/addiscorp/harar/go
```

```go
import harar "github.com/addiscorp/harar/go"

// The harar agent on this machine (`harar agent`): no account, no token.
vault := harar.Vault()

// A harar:// reference names a vault key, as op:// names a 1Password field.
key, err := vault.Secrets.Resolve(ctx, "harar://prod/shop/STRIPE_KEY")
keys, err := vault.Secrets.ResolveAll(ctx, []string{"harar://prod/shop/STRIPE_KEY", "harar://prod/site/DATABASE_URL"})
```

The value is read when you ask for it and held only by your program; nothing
is written to disk. The agent answers only the user it runs as, and the first
time a terminal asks, it asks you to approve (Touch ID on a Mac).
`harar.VaultAt("/run/harar.sock")` talks to a primary instead.

A gateway that attaches keys on their way out asks where each may go, and for
it for one host only: `vault.Hosts(ctx, secret)` and
`vault.Send(ctx, secret, host)`. A refusal, or a harar that cannot be reached,
is a `*harar.Error` naming why. harar has a minute to answer; a context with
an earlier deadline, or a cancel, ends the wait sooner.

No dependencies beyond the standard library; Go 1.21 or later. Versions are
harar's own: `go/vX.Y.Z` is tagged with each stable release `vX.Y.Z`.

harar itself: https://github.com/addiscorp/harar
