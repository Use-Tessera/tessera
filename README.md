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
- **one signature on chain**, so the transaction doesn't grow with the number
  of signers;
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
| An AI agent with no key pays an API (HTTP 402) from the group; a prompt-injected 100 XLM transfer and the call past its hourly limit are refused | [`0a40a9a7…9895`](https://stellar.expert/explorer/testnet/tx/0a40a9a76450f67c1480afa0af8faf742998bc5b54dee7de9e278643ab169895), one of [five payments](https://github.com/Use-Tessera/tessera-coordinator#an-agent-pays-for-an-api) |

In the same run, a 150 XLM request was refused by both remaining signers:

```text
error: policy refused: 01000000: spends 150 native, more than per_transaction 100 | 03000000: spends 150 native, more than per_transaction 100
```

Reproduce it with [`scripts/testnet-demo.sh`](https://github.com/Use-Tessera/tessera-coordinator/blob/main/scripts/testnet-demo.sh),
and the agent run with [`scripts/agent-demo.sh`](https://github.com/Use-Tessera/tessera-coordinator/blob/main/scripts/agent-demo.sh).

Testnet is reset every few months, after which these links stop resolving; the script reproduces the whole run on a fresh network.

## Why not Stellar's native multisig?

Stellar accounts already support several weighted signers with thresholds.
That is the right choice for many teams. Tessera is for when its trade-offs
don't fit:

| | Native multisig | Tessera |
|---|---|---|
| What the chain sees | The account's signers, weights and thresholds, and which keys signed each transaction | One ordinary key and one signature |
| Changing who can sign | `set_options` on chain, visible to everyone | Share refresh or a new key ceremony off chain; the account doesn't change |
| Group size | Up to 20 signatures per transaction | Any `t` of `n`; still one signature |
| Transaction size | Grows by 72 bytes per signature (it counts toward Soroban resource fees) | Constant |
| Where it works | Stellar accounts | Anything that checks one Ed25519 key: Stellar accounts, Soroban auth, SEP-10, off-chain messages |
| Per-signer spending policy | Up to each signer's own wallet software | Built into every signer daemon, deny by default, checked on the decoded transaction |
| Moving parts | None: it's in the protocol | Signer daemons and a coordinator, with two network rounds per signature |
| Maturity | Battle-tested since 2015 | New and unaudited (see [Status and limits](#status-and-limits)) |

Choose Tessera when the signer set should stay private or change without an
on-chain trace, when one key has to work beyond Stellar's account model, or
when you want spending rules enforced by every signer rather than trusted to
each one's wallet. An AI agent holding one share, for instance, can propose
payments, but the policy-checking signers decide which are made.

## Try a policy in your browser

The [policy checker](https://use-tessera.github.io/tessera/) runs the signer's
own policy code, compiled to WebAssembly: paste a `policy.toml` and a
transaction or Soroban authorization entry, and it shows whether the signers
would sign it and, if not, every rule it breaks.

## Quick start

Download `tessera` and `tessera-signer` for Linux, macOS or Windows from
[Releases](https://github.com/Use-Tessera/tessera/releases), run the signer
image (`ghcr.io/use-tessera/tessera-signer`, amd64 and arm64), or build the
release from source:

```sh
cargo install --git https://github.com/Use-Tessera/tessera --tag v0.1.1 --locked tessera-cli tessera-signer

# 2-of-3 group for development: one machine deals all three shares,
# each encrypted with Argon2id + XChaCha20-Poly1305
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
# Optional: read the latest ledger here instead of trusting the coordinator's
rpc = "https://soroban-testnet.stellar.org"

# Optional: serve only over mutual TLS (PEM files). The coordinator must present
# a certificate issued by client_ca, and the token is still required.
[tls]
cert = "signer.crt"
key = "signer.key"
client_ca = "coordinator-ca.crt"
```

The policy format is documented in [`examples/policy.toml`](examples/policy.toml).

## Key generation without a dealer

For real funds, generate the key so that it never exists in one place. Each
operator runs three steps on their own machine and posts the files they print
anywhere the others can read them:

```sh
export TESSERA_PASSPHRASE=…   # this operator's own passphrase
tessera dkg start --index 1 --threshold 2 --signers 3 --state dkg.state > round1-1.json

# once every round1-*.json is in: read the fingerprint aloud on a call
tessera dkg fingerprint round1-*.json

tessera dkg exchange --state dkg.state --fingerprint <agreed> --out round2/ round1-*.json
tessera dkg finish --state dkg.state --out share-1.json round2/*.json
```

The shared folder can be hostile. Round-2 packages are encrypted to each
recipient and bound to sender and recipient, and `exchange` refuses to run
unless the round-1 fingerprint matches the one everyone agreed on, which
catches a swapped commitment or encryption key.

Refresh shares on a schedule, or after a machine may have been compromised,
by running the same steps from each current share:

```sh
tessera dkg start --refresh share-1.json --state dkg.state > round1-1.json
```

The account stays the same, and a share from before the refresh no longer
combines with one from after it, so a share that leaked last month is worth
nothing once everyone has refreshed. Refreshing with `--participants` set to
fewer holders (at least the threshold) removes the others from the group.

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
| `tessera-core` | FROST rounds bound to Stellar transaction hashes and authorization entries, distributed key generation, encrypted share files, the `tessera/signer/v1` wire types |
| `tessera-policy` | Transaction → intent decoding, deny-by-default policy evaluation |
| `tessera-signer` | The signer daemon (`axum`) |
| `tessera-cli` | `tessera dkg`, `keygen`, `inspect`, `check`, `share` |

## Status and limits

Read [docs/security-model.md](docs/security-model.md) before trusting this with
funds. In short: generate keys with `tessera dkg`, not the development
dealer; turn on `[tls]` so signers accept only the coordinator's certificate
as well as its token; and the code has not been audited.

## Roadmap

1. **Signing core and signer daemon.** Done: this repository.
2. **Coordinator.** Done:
   [`tessera-coordinator`](https://github.com/Use-Tessera/tessera-coordinator).
3. **Key generation and rotation.** Distributed key generation over an
   untrusted relay, and proactive share refresh: done.
4. **Richer signing.** Soroban authorization entries (address credentials)
   and SEP-41 `transfer` limits: done.
5. **Hardening.** Mutual TLS between coordinator and signers: done. Next,
   HSM/enclave-backed share storage, and an external audit.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
