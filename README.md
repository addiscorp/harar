# harar

A free, open-source secrets vault for developers and their agents.

- **No tokens on disk.** `.env` files and config hold `harar://` references; the
  values live in an encrypted vault and are filled in when a command runs.
- **Real tokens never enter an agent's sandbox.** Agents get short-lived
  credentials, or a broker outside the sandbox adds the real one on the way out.
- **OIDC between services.** harar issues short-lived identity tokens so services
  trust each other without shared secrets.

It runs on macOS (Apple silicon and Intel Macs with a T2 chip, where the master
key is sealed to the Secure Enclave) and Linux. It works without an account.

> **Status: early and not yet audited.** Don't keep anything in it you can't
> rotate.

## Install

```sh
curl -fsSL https://harar-releases.addis.gg/install.sh | sh
```

It installs `harar` into `~/.harar/bin`, checked against the SHA-256 in the
release's manifest, with no sudo. Builds: macOS (Apple silicon and Intel) and
Linux x86_64. `sh -s -- --canary` installs the newest build of `main`.

## From your code

The `harar` binary is the server. Programs talk to it through a client on its
local socket; the clients hold no secrets.

- **Rust:** the [`harar`](client/README.md) crate, `harar = "0.2"`, `use harar::VaultClient`.
- **JavaScript and TypeScript:** the [`harar`](js/README.md) npm package,
  `import { vault } from 'harar'`.
- **Python:** the [`harar`](python/README.md) PyPI package, `pip install harar`,
  `from harar import vault`.
- **Ruby:** the [`harar`](ruby/README.md) gem, `gem install harar`,
  `Harar.vault(socket: ...)`.
- **PHP:** the [`addis/harar`](php/README.md) Composer package,
  `composer require addis/harar`, `Harar\vault(socket: ...)`.

All of them publish from a stable release, at its version.

## Build

```sh
cargo build --release --locked
```

`server/` is the binary (package `harar-server`); `client/` is the `harar` crate.

## Run a primary

A primary holds one org's vault and policy and issues its tokens. The OS user
named by `--owner-user` speaks as the owner; everyone else is refused until
the owner maps them.

The Postgres connection string lives in a file only the primary's user can
read (0600), so a password never shows in `ps`.

```sh
sudo harar serve --org gg.addis --machine bugsy \
  --owner gg.addis.human.sami --owner-user sami \
  --postgres-file /var/lib/harar/postgres \
  --master-key-file /etc/harar/master.key

harar policy show
harar policy role set gg.addis.role.site --read 'prod/site/*' \
  --token 'https://api.simien.dev deploy:site'
harar policy bind gg.addis.service.site --role gg.addis.role.site --zone gg.addis.zone.bugsy
harar policy user map site gg.addis.service.site
harar policy test --actor gg.addis.service.site --read prod/site/DATABASE_URL
harar token --aud https://api.simien.dev --scope deploy:site
```

See [docs/architecture.md](docs/architecture.md) for the model.

## License

[Apache-2.0](LICENSE)
