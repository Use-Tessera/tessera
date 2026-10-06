# Security policy

Tessera controls funds, so treat any way to get a signature the policy should
refuse, or to learn anything about a key share, as critical.

## Reporting

Report vulnerabilities privately through
[GitHub security advisories](https://github.com/Use-Tessera/tessera/security/advisories/new).
Do not open a public issue. We aim to acknowledge reports within three days.

In scope, most severe first:

1. Recovering a key share or the group key, including through nonce reuse.
2. Getting a signature share for a transaction the signer's policy refuses,
   or for a transaction the signer did not decode.
3. Resetting or bypassing daily limits.
4. Panics, unbounded memory use or excessive CPU on malicious input.

## Status

Not yet audited. Read [docs/security-model.md](docs/security-model.md) for the
current guarantees and known gaps (notably trusted-dealer key generation).
