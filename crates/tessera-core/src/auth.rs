//! Soroban authorization entries signed by a Tessera group.
//!
//! When a contract call needs the group's authorization but someone else
//! submits the transaction (an x402 facilitator, a relayer, a fee sponsor), the
//! group signs a `SorobanAuthorizationEntry` with address credentials instead
//! of the transaction. The payload is
//! `SHA-256(HashIdPreimage::SorobanAuthorization{network, nonce, expiration, invocation})`,
//! and for a Stellar account the signature goes into the credentials as
//! `[{public_key, signature}]`.

use sha2::{Digest, Sha256};
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ReadXdr, ScAddress, ScBytes, ScMap, ScMapEntry,
    ScSymbol, ScVal, ScVec, SorobanAuthorizationEntry, SorobanCredentials, WriteXdr,
};

use crate::Error;
use crate::stellar::{DECODE_LIMITS, Network};

/// Decodes a base64 `SorobanAuthorizationEntry`.
pub fn decode_entry(b64: &str) -> Result<SorobanAuthorizationEntry, Error> {
    SorobanAuthorizationEntry::from_xdr_base64(b64.trim(), DECODE_LIMITS)
        .map_err(|e| Error::malformed("authorization entry", e))
}

/// Encodes a `SorobanAuthorizationEntry` as base64.
pub fn encode_entry(entry: &SorobanAuthorizationEntry) -> Result<String, Error> {
    entry.to_xdr_base64(Limits::none()).map_err(|e| Error::malformed("authorization entry", e))
}

/// The address the entry authorizes for, if it uses address credentials.
pub fn authorizer(entry: &SorobanAuthorizationEntry) -> Option<&ScAddress> {
    match &entry.credentials {
        SorobanCredentials::Address(c) => Some(&c.address),
        _ => None,
    }
}

/// The 32-byte payload the group signs for this entry on `network`.
///
/// Only `Address` credentials are supported: source-account entries are
/// covered by the transaction signature, and newer credential kinds are
/// refused rather than signed with the wrong payload.
pub fn payload_hash(network: &Network, entry: &SorobanAuthorizationEntry) -> Result<[u8; 32], Error> {
    let SorobanCredentials::Address(creds) = &entry.credentials else {
        return Err(Error::malformed(
            "authorization entry",
            "only address credentials can be signed (source-account entries are covered by the transaction signature)",
        ));
    };
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network.id()),
        nonce: creds.nonce,
        signature_expiration_ledger: creds.signature_expiration_ledger,
        invocation: entry.root_invocation.clone(),
    });
    let xdr = preimage.to_xdr(Limits::none()).map_err(|e| Error::malformed("authorization preimage", e))?;
    Ok(Sha256::digest(xdr).into())
}

/// Stores the group's signature in the entry, in the `[{public_key, signature}]`
/// form a Stellar account's built-in auth expects.
pub fn attach_signature(
    entry: &mut SorobanAuthorizationEntry,
    public_key: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), Error> {
    let SorobanCredentials::Address(creds) = &mut entry.credentials else {
        return Err(Error::malformed("authorization entry", "only address credentials can carry a signature"));
    };
    let sym = |s: &str| -> Result<ScVal, Error> {
        Ok(ScVal::Symbol(ScSymbol(s.as_bytes().to_vec().try_into().map_err(|e| Error::malformed("symbol", e))?)))
    };
    let bytes = |b: &[u8]| -> Result<ScVal, Error> {
        Ok(ScVal::Bytes(ScBytes(b.to_vec().try_into().map_err(|e| Error::malformed("bytes", e))?)))
    };
    // Map keys must be sorted: "public_key" < "signature".
    let map = ScMap(
        vec![
            ScMapEntry { key: sym("public_key")?, val: bytes(public_key)? },
            ScMapEntry { key: sym("signature")?, val: bytes(signature)? },
        ]
        .try_into()
        .map_err(|e| Error::malformed("signature map", e))?,
    );
    let list = ScVec(vec![ScVal::Map(Some(map))].try_into().map_err(|e| Error::malformed("signature list", e))?);
    creds.signature = ScVal::Vec(Some(list));
    Ok(())
}
