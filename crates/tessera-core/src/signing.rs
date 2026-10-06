//! The two FROST rounds and aggregation, bound to Stellar transactions.
//!
//! Signers never sign bytes they were handed. Round 2 takes the transaction
//! envelope and network, and the signer computes the hash itself, so a
//! coordinator cannot get a share over anything the signer did not see.

use std::collections::BTreeMap;

use frost_ed25519::round1::{SigningCommitments, SigningNonces};
use frost_ed25519::round2::SignatureShare;
use frost_ed25519::{Identifier, SigningPackage};
use stellar_xdr::TransactionEnvelope;

use crate::Error;
use crate::keys::{KeyShare, decode_map, group_key};
use crate::stellar::{Network, transaction_hash};

/// Round 1: fresh nonces (kept secret by the signer) and their commitments (sent to the coordinator).
pub fn commit(share: &KeyShare) -> (SigningNonces, SigningCommitments) {
    let mut rng = rand_core::OsRng;
    frost_ed25519::round1::commit(share.key_package().signing_share(), &mut rng)
}

/// Hex-encodes commitments for the wire.
pub fn encode_commitments(c: &SigningCommitments) -> Result<String, Error> {
    Ok(hex::encode(c.serialize()?))
}

/// Builds the signing package for a transaction from wire commitments.
pub fn signing_package(
    network: &Network,
    envelope: &TransactionEnvelope,
    commitments: &BTreeMap<String, String>,
) -> Result<(SigningPackage, [u8; 32]), Error> {
    let hash = transaction_hash(network, envelope)?;
    let commitments = decode_map(commitments, "commitments", SigningCommitments::deserialize)?;
    Ok((SigningPackage::new(commitments, &hash), hash))
}

/// Round 2: this signer's share of the signature.
///
/// Takes the nonces by value: a nonce pair must never sign twice, and moving
/// it here makes reuse a compile error rather than a key leak.
pub fn sign(share: &KeyShare, nonces: SigningNonces, package: &SigningPackage) -> Result<String, Error> {
    let s = frost_ed25519::round2::sign(package, &nonces, share.key_package())?;
    Ok(hex::encode(s.serialize()))
}

/// Combines shares into an Ed25519 signature and checks it against the group key.
///
/// Uses only public data, so anyone holding the group's public key package can aggregate.
pub fn aggregate(
    public: &frost_ed25519::keys::PublicKeyPackage,
    package: &SigningPackage,
    shares: &BTreeMap<String, String>,
) -> Result<[u8; 64], Error> {
    let shares: BTreeMap<Identifier, SignatureShare> =
        decode_map(shares, "signature shares", SignatureShare::deserialize)?;
    let signature = frost_ed25519::aggregate(package, &shares, public)?;
    public.verifying_key().verify(package.message(), &signature).map_err(|_| Error::BadSignature)?;
    let bytes = signature.serialize()?;
    bytes.try_into().map_err(|_| Error::BadSignature)
}

/// Runs both rounds in-process with the given shares. For tests, demos and offline signing.
pub fn sign_locally(network: &Network, envelope: &TransactionEnvelope, shares: &[KeyShare]) -> Result<[u8; 64], Error> {
    let first = shares.first().ok_or(Error::Threshold { threshold: 0, signers: 0 })?;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for s in shares {
        let (n, c) = commit(s);
        nonces.insert(s.identifier_hex(), n);
        commitments.insert(s.identifier_hex(), encode_commitments(&c)?);
    }
    let (package, _) = signing_package(network, envelope, &commitments)?;
    let mut sig_shares = BTreeMap::new();
    for s in shares {
        let n = nonces.remove(&s.identifier_hex()).ok_or(Error::BadSignature)?;
        sig_shares.insert(s.identifier_hex(), sign(s, n, &package)?);
    }
    aggregate(first.public_key_package(), &package, &sig_shares)
}

/// The group key of a public key package.
pub fn group_public_key(public: &frost_ed25519::keys::PublicKeyPackage) -> [u8; 32] {
    group_key(public.verifying_key())
}
