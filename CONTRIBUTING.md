# Contributing

Tessera takes part in the [Stellar Wave](https://www.drips.network/wave/stellar)
program; Wave issues are labeled with their complexity.

## Setup

```sh
git clone https://github.com/Use-Tessera/tessera && cd tessera
cargo test --workspace
```

`rust-toolchain.toml` pins the toolchain; the minimum supported Rust version is
1.88. On Windows with the GNU toolchain, crates that use `raw-dylib` need a
MinGW-w64 assembler on `PATH` (for example WinLibs).

## Before you open a PR

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Ground rules

- **Get assigned first.** Comment on the issue and wait for assignment.
- **One issue, one PR**, linked with `Closes #N`.
- **Never implement cryptography here.** FROST, Ed25519, Argon2 and
  XChaCha20-Poly1305 come from reviewed crates. Glue code is fine; new
  primitives are not.
- **Policy changes are deny-by-default.** A new rule must refuse when
  misconfigured, and must come with tests for both the approve and refuse paths.
- **No panics in library code.** `unwrap`, `expect` and `panic!` are denied by lint.
- **Keep the tree clean.** No notes, summaries, PR drafts or backup files; CI
  rejects the common ones.

## Fixtures

- `crates/tessera-core/tests/fixtures/payment.xdr`: an unsigned testnet payment.
- `crates/tessera-signer/tests/fixtures/transcript.json`: real 2-of-3 runs over
  a transaction and a Soroban authorization entry, which `tessera-coordinator`
  replays in its tests.

Regenerate both with `UPDATE_FIXTURES=1 cargo test --workspace`. If the
transcript changes, copy it to `tessera-coordinator/testdata/` in the same change.

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org): `feat(policy): …`,
`fix(signer): …`, `docs: …`.
