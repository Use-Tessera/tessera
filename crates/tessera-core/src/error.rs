use thiserror::Error;

/// Errors from key handling, the signing protocol and transaction hashing.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// A FROST operation failed (bad share, bad commitment, cheating signer, ...).
    #[error("FROST: {0}")]
    Frost(#[from] frost_ed25519::Error),

    /// Input was not valid XDR, hex, base64 or JSON.
    #[error("malformed {what}: {reason}")]
    Malformed {
        /// What was being decoded.
        what: &'static str,
        /// Decoder message.
        reason: String,
    },

    /// The key share file could not be decrypted (wrong passphrase or tampered file).
    #[error("cannot decrypt key share: wrong passphrase or corrupted file")]
    Decrypt,

    /// Threshold parameters are out of range.
    #[error("invalid threshold: need 2 <= threshold <= signers <= 255, got {threshold} of {signers}")]
    Threshold {
        /// Requested threshold.
        threshold: u16,
        /// Requested number of signers.
        signers: u16,
    },

    /// The aggregated signature does not verify against the group key.
    #[error("aggregated signature does not verify against the group key")]
    BadSignature,

    /// The operating system's random number generator failed.
    #[error("system randomness unavailable")]
    Randomness,

    /// Distributed key generation received inconsistent or tampered messages.
    #[error("DKG: {0}")]
    Dkg(String),
}

impl Error {
    pub(crate) fn malformed(what: &'static str, reason: impl ToString) -> Self {
        Self::Malformed { what, reason: reason.to_string() }
    }
}
