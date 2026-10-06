# Security model

Tessera's promise: **no single party can sign, and no signer signs what its
policy forbids.** This page says what each party can do, what it cannot, and
which gaps are still open.

## Parties

| Party | Holds | Can | Cannot |
|---|---|---|---|
| Signer | One encrypted key share, its policy, its spend ledger | Refuse anything; sign what its policy allows | Sign alone (needs `t-1` others) |
| Coordinator | Nothing secret | Pick which signers take part; withhold or delay signing | Get a share over a transaction a signer didn't see and approve; pass off a bad signature (it verifies the aggregate itself) |
| Application or agent | An API token | Ask for signatures | Bypass signer policies |
| Network observer | The chain | See one ordinary Ed25519 signature | Tell that the account is a threshold group |

## Properties and how they hold

**Threshold.** FROST (RFC 9591) with the Zcash Foundation's `frost-ed25519`.
Fewer than `t` shares reveal nothing about the key, and fewer than `t`
participants cannot produce a signature. Tests run every `t`-subset, and check
that one share alone and shares from another group both fail.

**No blind signing.** Round 2 carries the transaction envelope, not a hash.
The signer decodes it, computes `SHA-256(networkID ‖ ENVELOPE_TYPE_TX ‖ tx)`
for its own configured network, judges the decoded intent, and only then signs
that hash. A coordinator cannot request a share over bytes the signer has not
inspected, or over another network's hash.

**Single-use nonces.** Reusing a FROST nonce pair across two messages leaks
the share. Nonces are generated per session, removed from memory the moment
round 2 is attempted (approved or refused), expire after 120 seconds, and the
signing function takes them by value, so reuse cannot compile.

**Independent policy.** Each signer evaluates its own policy file and reports
its SHA-256 at `/v1/info`, so operators can confirm what is live. A `t`-of-`n`
group therefore needs `t` independent approvals. Policies are deny-by-default:
unlisted operations, assets and contracts are refused, operations that act for
another account are refused, and every transaction must expire within
`max_validity`.

**Durable limits.** Approved spend is appended to the signer's ledger and
`fsync`ed *before* the share leaves the signer, so a crash cannot reset a
daily limit. Spend counts on approval, even if the transaction is never
submitted. That's conservative by design.

**Authorization entries.** For contract calls submitted by someone else
(an x402 facilitator, a relayer), signers sign a `SorobanAuthorizationEntry`
instead of a transaction. The whole invocation tree is judged, not just the
root call, so an allowed call cannot carry a forbidden sub-invocation. Signing
entries is off unless the policy has an `[auth]` section, and the entry must
expire within `max_validity_ledgers` of the network's latest ledger.

**Verified output.** The coordinator verifies the aggregate with Go's
`crypto/ed25519` against the group key and its own hash of the transaction.

**Shares at rest.** Argon2id (64 MiB, 3 passes) derives a key that encrypts the
share with XChaCha20-Poly1305. The public header (account, identifier,
threshold) is authenticated as associated data, so editing it makes the file
undecryptable.

**Audit trail.** Every attempt, signed, refused or failed, is appended to a
hash-chained log. `tessera-coordinator audit verify` detects edits, deletions
and reordering.

## Known gaps

These are tracked as roadmap items, not hidden:

1. **Trusted-dealer key generation.** `tessera keygen` sees the whole key while
   it runs. Run it on an offline machine you then wipe. Distributed key
   generation is the next milestone.
2. **Bearer-token transport auth.** Signer endpoints check a shared bearer
   token in constant time. Deploy them behind TLS. Mutual TLS is planned.
3. **Daily limits are per signer and per asset in stroops.** They do not
   convert between assets, and contract calls (including SEP-41 `transfer`)
   are allowed or refused by contract and function only, not by amount.
4. **The latest ledger comes from the coordinator.** A signer cannot read the
   chain itself, so it trusts the coordinator's `latest_ledger` when bounding
   an authorization's lifetime. It refuses values more than about a day behind
   the highest it has seen, which limits but does not remove the risk of a
   malicious coordinator stretching an authorization's validity. Signers
   reading an RPC of their own is on the roadmap.
5. **No audit yet.** Until an independent review, keep the group's balance at
   what you can afford to lose.
