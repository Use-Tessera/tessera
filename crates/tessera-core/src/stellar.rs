//! What Stellar needs from a signer: the transaction hash it signs and where
//! the signature goes.

use sha2::{Digest, Sha256};
use stellar_xdr::{DecoratedSignature, Limits, ReadXdr, Signature, SignatureHint, TransactionEnvelope, VecM, WriteXdr};

use crate::Error;

/// Upper bounds applied when decoding untrusted transaction XDR.
pub const DECODE_LIMITS: Limits = Limits { depth: 256, len: 1024 * 1024 };

/// A Stellar network, identified by the SHA-256 of its passphrase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Network {
    passphrase: String,
    id: [u8; 32],
}

impl Network {
    /// Passphrase of the public network.
    pub const PUBLIC: &'static str = "Public Global Stellar Network ; September 2015";
    /// Passphrase of the SDF test network.
    pub const TESTNET: &'static str = "Test SDF Network ; September 2015";

    /// Builds a network from its passphrase.
    pub fn new(passphrase: impl Into<String>) -> Self {
        let passphrase = passphrase.into();
        let id = Sha256::digest(passphrase.as_bytes()).into();
        Self { passphrase, id }
    }

    /// Resolves `"public"`/`"mainnet"`, `"testnet"`, or a literal passphrase.
    pub fn from_name(name: &str) -> Self {
        match name {
            "public" | "mainnet" => Self::new(Self::PUBLIC),
            "testnet" => Self::new(Self::TESTNET),
            other => Self::new(other),
        }
    }

    /// The passphrase.
    pub fn passphrase(&self) -> &str {
        &self.passphrase
    }

    /// SHA-256 of the passphrase.
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}

/// Decodes a base64 `TransactionEnvelope`.
pub fn decode_envelope(b64: &str) -> Result<TransactionEnvelope, Error> {
    TransactionEnvelope::from_xdr_base64(b64.trim(), DECODE_LIMITS)
        .map_err(|e| Error::malformed("transaction envelope", e))
}

/// Encodes a `TransactionEnvelope` as base64.
pub fn encode_envelope(env: &TransactionEnvelope) -> Result<String, Error> {
    env.to_xdr_base64(Limits::none()).map_err(|e| Error::malformed("transaction envelope", e))
}

/// The 32-byte hash an account signs for this envelope on `network`.
///
/// For a fee-bump envelope this is the outer (fee-bump) transaction.
pub fn transaction_hash(network: &Network, env: &TransactionEnvelope) -> Result<[u8; 32], Error> {
    env.hash(network.id()).map_err(|e| Error::malformed("transaction envelope", e))
}

/// The `G…` address of an Ed25519 public key.
pub fn account_id(public_key: &[u8; 32]) -> String {
    stellar_xdr::PublicKey::PublicKeyTypeEd25519(stellar_xdr::Uint256(*public_key)).to_string()
}

/// Appends a decorated signature to the envelope (the outer one for fee bumps).
pub fn attach_signature(
    env: &mut TransactionEnvelope,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let hint: [u8; 4] = public_key.get(28..).and_then(|s| s.try_into().ok()).ok_or(Error::BadSignature)?;
    let decorated = DecoratedSignature {
        hint: SignatureHint(hint),
        signature: Signature(signature.to_vec().try_into().map_err(|e| Error::malformed("signature", e))?),
    };
    let sigs: &mut VecM<DecoratedSignature, 20> = match env {
        TransactionEnvelope::TxV0(e) => &mut e.signatures,
        TransactionEnvelope::Tx(e) => &mut e.signatures,
        TransactionEnvelope::TxFeeBump(e) => &mut e.signatures,
    };
    let mut v = sigs.to_vec();
    v.push(decorated);
    *sigs = v.try_into().map_err(|_| Error::malformed("transaction envelope", "more than 20 signatures"))?;
    Ok(())
}
