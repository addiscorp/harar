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

## Build

```sh
cargo build --release --locked
```

## Run a primary

A primary holds one org's vault and policy and issues its tokens. The OS user
named by `--owner-user` speaks as the owner; everyone else is refused until
the owner maps them.

The Postgres connection string lives in a file only the primary's user can
read (0600), so a password never shows in `ps`.

```sh
sudo harar serve --org gg.addis --machine bugsy \
  --owner gg.addis.human.sami --owner-user sami \
  --postgres-file /var/lib/harar/postgres

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
