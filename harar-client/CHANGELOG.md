# Changelog

## 0.2.1 - 2026-07-22

- Publish the dedicated one-time custody client contract introduced by Harar
  custody v2: `VaultClient::stage_once`, `VaultClient::consume_once`, and
  `VaultClient::purge_once` with their binding request types.
- This is an additive client API release. The v2 custody wire envelopes are
  unchanged from the reviewed Harar source merged at
  `6ac611caf3fe8a2e1d854c49e5ee3454ef70d3d6`.

## 0.2.0

- Previous Linkhash registry release. It does not expose the one-time custody
  client contract.
