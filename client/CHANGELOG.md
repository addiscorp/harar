# Changelog

The `harar` crate's version is harar's release version: it is published to
crates.io when a release is promoted to stable, never from a canary.

## 0.2.0

- First release on crates.io, as `harar` (it was `harar-client`, on a private
  registry, whose 0.2.0 and 0.2.1 are not this code). `use harar::VaultClient`.
- `VaultClient` speaks to a harar primary or the per-user agent over its local
  socket: secrets (`get`, `put`, `delete`, `list`), where a secret may go
  (`hosts`, `allow_host`, `revoke_host`, `send`), identity tokens (`token`),
  policy (`policy_show`, `policy_change`), and approvals, approver devices and
  recovery.
- `oidc`, `model`, `approvals`, `recovery` and `primary` hold the identity
  model and the wire types the server uses.
