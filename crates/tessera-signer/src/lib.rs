//! The Tessera signer: one key share behind an HTTP API, guarded by a policy.
//!
//! | Route | Purpose |
//! |---|---|
//! | `GET /v1/info` | Identity, group account, network, policy hash |
//! | `POST /v1/round1` | Fresh nonce commitments for a session |
//! | `POST /v1/round2` | A signature share, if the policy approves the transaction |
//! | `POST /v1/aggregate` | Combine shares (public data only) |
//! | `POST /v1/round2/auth` | A signature share over a Soroban authorization entry, if the policy allows it |
//! | `POST /v1/aggregate/auth` | Combine shares into a signed authorization entry |
//! | `GET /metrics` | Prometheus counters: sessions, and decisions by kind and outcome |
//!
//! Every `/v1` route and `/metrics` require `Authorization: Bearer <token>` when a token is
//! configured. `GET /healthz` is open. Bodies are capped at 256 KB and requests
//! at 30 seconds.

pub mod config;
mod routes;
pub mod rpc;
pub mod state;

pub use routes::{LedgerSource, MAX_BODY, REQUEST_TIMEOUT, Signer, router};
