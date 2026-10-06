# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `tessera-core`: FROST(Ed25519) threshold signing bound to Stellar
  transaction hashes and Soroban authorization payloads, the
  `tessera/signer/v1` wire types, and share files sealed with Argon2id and
  XChaCha20-Poly1305.
- Distributed key generation (`tessera dkg`) over an untrusted relay:
  round-2 packages are encrypted to each recipient, and a round-1 fingerprint
  compared out of band catches substituted messages.
- Proactive share refresh (`tessera dkg start --refresh`), which keeps the
  account, retires old shares, and can drop participants.
- `tessera-policy`: deny-by-default policies over decoded transactions and
  whole authorization invocation trees, with per-asset and SEP-41 token limits
  per transaction and per day, destination allowlists and validity bounds.
- `tessera-signer`: one share behind a policy-enforcing HTTP API, with an
  optional RPC of its own for the latest ledger,
  single-use nonces, a durable spend ledger, a decision log, request limits and
  Prometheus metrics.
- `tessera` CLI: `dkg`, `keygen` (development dealer), `inspect`, `check`
  (transactions, or authorization entries with `--latest-ledger`) and `share`.
- A recorded 2-of-3 transcript, replayed by tessera-coordinator's tests.
- Container image for the signer, and release binaries for Linux, macOS and
  Windows.

[Unreleased]: https://github.com/Use-Tessera/tessera/commits/main
