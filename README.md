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

## License

[Apache-2.0](LICENSE)
