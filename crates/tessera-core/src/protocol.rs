//! JSON messages between the coordinator and signers (`tessera/signer/v1`).
//!
//! Binary values are lowercase hex; transaction envelopes are base64 XDR.
//! Maps are keyed by participant identifier (hex).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Protocol version string, returned by `GET /v1/info`.
pub const PROTOCOL: &str = "tessera/signer/v1";

/// `GET /v1/info`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Info {
    /// Always [`PROTOCOL`].
    pub protocol: String,
    /// This signer's identifier.
    pub identifier: String,
    /// Group account (`G…`).
    pub account: String,
    /// Signatures needed.
    pub threshold: u16,
    /// Participants in the group.
    pub signers: usize,
    /// Network passphrase this signer will sign for.
    pub network: String,
    /// SHA-256 of the policy file this signer enforces, hex.
    pub policy_sha256: String,
}

/// `POST /v1/round1`: start a session and get this signer's commitments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Round1Request {
    /// Coordinator-chosen session ID (1–64 chars of `[A-Za-z0-9_-]`).
    pub session: String,
}

/// Response to [`Round1Request`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Round1Response {
    /// This signer's identifier.
    pub identifier: String,
    /// Serialized `SigningCommitments`.
    pub commitments: String,
}

/// `POST /v1/round2`: ask for a signature share over a transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Round2Request {
    /// Session from round 1.
    pub session: String,
    /// `TransactionEnvelope`, base64 XDR.
    pub envelope: String,
    /// Commitments of every participating signer, this one included.
    pub commitments: BTreeMap<String, String>,
}

/// Response to [`Round2Request`] when the policy allows the transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Round2Response {
    /// This signer's identifier.
    pub identifier: String,
    /// Serialized `SignatureShare`.
    pub share: String,
}

/// `POST /v1/aggregate`: combine shares. Stateless; uses only public data.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AggregateRequest {
    /// `TransactionEnvelope`, base64 XDR.
    pub envelope: String,
    /// Commitments used in round 2.
    pub commitments: BTreeMap<String, String>,
    /// Signature shares from round 2.
    pub shares: BTreeMap<String, String>,
}

/// Response to [`AggregateRequest`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateResponse {
    /// Transaction hash that was signed, hex.
    pub hash: String,
    /// Ed25519 signature, hex.
    pub signature: String,
    /// The envelope with the signature attached, base64 XDR.
    pub envelope: String,
}

/// Error body for every non-2xx response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ErrorBody {
    /// Human-readable error.
    pub error: String,
    /// Policy violations, when the signer refused to sign.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
}
