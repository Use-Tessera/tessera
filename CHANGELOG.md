# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-10-27

### Added

- Hourly limits: `per_hour` on `[[asset]]` and `[[token]]` caps the trailing
  hour as well as the trailing day, so a compromised application or agent
  can't spend the day's budget in minutes. It is refused at load if it is
  above `per_day`, where it could never apply.
- Mutual TLS for `tessera-signer`: with `[tls]` in `signer.toml` (certificate,
  key and client CA, all PEM) the signer serves HTTPS and accepts only clients
  whose certificate chains to the CA, with the bearer token still required.
  rustls with the `ring` provider.
- `tessera-wasm` (`bindings/wasm`): the signing policy for JavaScript.
  `check()` judges a base64 transaction envelope or Soroban authorization
  entry against a `policy.toml`; `samples()` builds example inputs.
- A [policy checker](https://use-tessera.github.io/tessera/) on GitHub Pages,
  running the signer's own policy code in the browser.

### Changed

- `Policy::evaluate` and `evaluate_auth` take `spent(asset, window)` instead
  of `spent_today(asset)`, with `window` either `tessera_policy::DAY` or
  `HOUR` in seconds. `SpendLedger::spent_within` answers it.
- axum-server 0.8, which drops the unmaintained `rustls-pemfile`.

### Security

- Updated rustls, rustls-webpki and tokio past seven RustSec advisories
  (RUSTSEC-2026-0346 to -0349, -0381, -0382 and -0386).

## [0.1.1] - 2026-10-07

### Fixed

- Release packaging: only the archives are uploaded, checksummed and attached;
  0.1.0's publish step tripped over the staging folders.

## [0.1.0] - 2026-10-07

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
- `tessera-signer`: one share behind a policy-enforcing HTTP API, with
  single-use nonces, a durable spend ledger, a decision log, request limits,
  Prometheus metrics, and optionally its own RPC for the latest ledger.
- `tessera` CLI: `dkg`, `keygen` (development dealer), `inspect`, `check`
  (transactions, or authorization entries with `--latest-ledger`) and `share`.
- A recorded 2-of-3 transcript, replayed by tessera-coordinator's tests.
- Container image for the signer, and release binaries for Linux, macOS and
  Windows.

[Unreleased]: https://github.com/Use-Tessera/tessera/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Use-Tessera/tessera/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Use-Tessera/tessera/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Use-Tessera/tessera/releases/tag/v0.1.0
