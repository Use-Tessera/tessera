<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo.svg" alt="Tessera" height="64">
  </picture>
</p>

<p align="center">
  <b>Threshold signing for Stellar. Any t of n parties sign as one ordinary account, and every signer enforces its own policy.</b>
</p>

<p align="center">
  <a href="https://github.com/Use-Tessera/tessera/actions/workflows/ci.yml"><img src="https://github.com/Use-Tessera/tessera/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="License"></a>
</p>

---

Tessera splits one Ed25519 key into shares with
[FROST](https://www.rfc-editor.org/rfc/rfc9591) (RFC 9591, via the Zcash
Foundation's audited `frost-ed25519`). Any `t` of the `n` share holders produce
a single, standard Ed25519 signature. Stellar sees an ordinary account with an
ordinary signature:

- **no contract and no multisig setup**, so it works for G-accounts, Soroban
  source-account auth, and anything else that verifies Ed25519;
- **one signature on chain**, so fees and transaction size don't grow with the
  number of signers;
- **a private signer set**: nothing on chain reveals how many parties signed or
  who they are.

Each signer is a small daemon holding one encrypted share. It decodes every
transaction it is asked to sign, computes the hash itself (no blind signing),
and refuses anything outside its policy: amount caps per transaction and per
day, destination and contract allowlists, mandatory short expiry, and no
`set_options` or `account_merge` unless explicitly allowed. A compromised
coordinator, or a compromised AI agent holding one share, can't move funds
past the policy.

## Proven on testnet

| What | Transaction |
|---|---|
| 2-of-3 group pays 1 XLM; one signature on chain | [`11302d7d…6eb7`](https://stellar.expert/explorer/testnet/tx/11302d7dd5c62fd059e6d90bb4a1574b9da286187bf8e2e3fb121e6f5d3b6eb7) |
| Full stack: three signer daemons, one offline, Go coordinator submits | [`ddfa1079…5009`](https://stellar.expert/explorer/testnet/tx/ddfa10791ce6f24fa1950eee3dd1ae71fa3335c92a58737751c606079bfd5009) |

In the same run, a 150 XLM request was refused by both remaining signers:

```text
error: policy refused: 01000000: spends 150 native, more than per_transaction 100 | 03000000: spends 150 native, more than per_transaction 100
```

Reproduce it with [`scripts/testnet-demo.sh`](https://github.com/Use-Tessera/tessera-coordinator/blob/main/scripts/testnet-demo.sh).

## Quick start

```sh
cargo install --git https://github.com/Use-Tessera/tessera tessera-cli tessera-signer

# 2-of-3 group, each share encrypted with Argon2id + XChaCha20-Poly1305
export TESSERA_PASSPHRASE_1=… TESSERA_PASSPHRASE_2=… TESSERA_PASSPHRASE_3=…
tessera keygen --threshold 2 --signers 3 --out shares/

# what does this transaction actually do?
tessera inspect --network testnet AAAAAgAAAA…

# would my signers sign it?
tessera check --policy examples/policy.toml --account G… AAAAAgAAAA…
```

Run one `tessera-signer` per share (on separate machines), then point
[`tessera-coordinator`](https://github.com/Use-Tessera/tessera-coordinator) at
them. A signer config:

```toml
listen = "0.0.0.0:7401"
network = "testnet"
share = "share-1.json"
policy = "policy.toml"
state_dir = "state"
token_env = "TESSERA_TOKEN"
```

The policy format is documented in [`examples/policy.toml`](examples/policy.toml).

## How a signature happens

```text
coordinator ──round1──▶ signers           each returns fresh nonce commitments
coordinator ──round2──▶ t signers         each: decode tx → hash it → check policy → sign share
coordinator ──aggregate──▶ any signer     shares → one Ed25519 signature
coordinator verifies it against the group key, attaches it, optionally submits
```

Nonces are single-use by construction: a signer drops a session's nonces as
soon as round 2 is attempted, whether it signs or refuses.

## Crates

| Crate | What it is |
|---|---|
| `tessera-core` | FROST rounds bound to Stellar transaction hashes, encrypted share files, the `tessera/signer/v1` wire types |
| `tessera-policy` | Transaction → intent decoding, deny-by-default policy evaluation |
| `tessera-signer` | The signer daemon (`axum`) |
| `tessera-cli` | `tessera keygen`, `inspect`, `check`, `share` |

## Status and limits

Read [docs/security-model.md](docs/security-model.md) before trusting this with
funds. In short: key generation currently uses a **trusted dealer**
(distributed key generation is next on the roadmap), signers authenticate the
coordinator with bearer tokens rather than mTLS, and the code has not been
audited.

## Roadmap

1. **Signing core and signer daemon.** Done: this repository.
2. **Coordinator.** Done:
   [`tessera-coordinator`](https://github.com/Use-Tessera/tessera-coordinator).
3. **Key generation and rotation.** Distributed key generation over end-to-end-encrypted
   coordinator relay, plus proactive share refresh.
4. **Richer signing.** Soroban authorization entries (address credentials),
   and token-amount limits for SEP-41 `transfer`.
5. **Hardening.** mTLS between coordinator and signers, HSM/enclave-backed
   share storage, and an external audit.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
