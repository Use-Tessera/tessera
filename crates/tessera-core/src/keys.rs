//! Key shares and their encrypted on-disk form.

use std::collections::BTreeMap;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frost_ed25519::keys::{IdentifierList, KeyPackage, PublicKeyPackage};
use frost_ed25519::{Identifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{Error, stellar};

/// Format tag of share files.
pub const SHARE_FORMAT: &str = "tessera/share/v1";

/// One participant's secret share plus the group's public key material.
#[derive(Clone)]
pub struct KeyShare {
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
}

impl std::fmt::Debug for KeyShare {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyShare")
            .field("identifier", &self.identifier_hex())
            .field("account", &self.account())
            .finish()
    }
}

impl KeyShare {
    /// Pairs a FROST key package with the group's public key package.
    pub fn new(key_package: KeyPackage, public_key_package: PublicKeyPackage) -> Self {
        Self { key_package, public_key_package }
    }

    /// The FROST key package (contains the secret share).
    pub fn key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// The group's public key package.
    pub fn public_key_package(&self) -> &PublicKeyPackage {
        &self.public_key_package
    }

    /// This participant's identifier.
    pub fn identifier(&self) -> Identifier {
        *self.key_package.identifier()
    }

    /// Identifier as lowercase hex, the form used on the wire.
    pub fn identifier_hex(&self) -> String {
        hex::encode(self.identifier().serialize())
    }

    /// Minimum number of participants needed to sign.
    pub fn threshold(&self) -> u16 {
        *self.key_package.min_signers()
    }

    /// Total number of participants.
    pub fn signers(&self) -> usize {
        self.public_key_package.verifying_shares().len()
    }

    /// The group's Ed25519 public key.
    pub fn group_public_key(&self) -> [u8; 32] {
        group_key(self.public_key_package.verifying_key())
    }

    /// The group's Stellar account (`G…`).
    pub fn account(&self) -> String {
        stellar::account_id(&self.group_public_key())
    }

    /// Encrypts the share under `passphrase`.
    pub fn seal(&self, passphrase: &[u8], kdf: KdfParams) -> Result<ShareFile, Error> {
        let header = ShareHeader {
            format: SHARE_FORMAT.into(),
            account: self.account(),
            identifier: self.identifier_hex(),
            threshold: self.threshold(),
            signers: self.signers(),
            public_key_package: hex::encode(self.public_key_package.serialize()?),
        };
        let plaintext = Zeroizing::new(self.key_package.serialize()?);
        let secret = Sealed::seal(passphrase, kdf, &header.aad()?, &plaintext)?;
        Ok(ShareFile { header, secret })
    }
}

pub(crate) fn group_key(vk: &VerifyingKey) -> [u8; 32] {
    let mut out = [0u8; 32];
    if let Ok(bytes) = vk.serialize() {
        out.iter_mut().zip(bytes).for_each(|(o, b)| *o = b);
    }
    out
}

/// Generates shares with a trusted dealer.
///
/// The dealer sees the whole key while it runs. Use it for development, or
/// on an offline machine whose memory is discarded afterwards; distributed key
/// generation is on the roadmap.
pub fn deal(threshold: u16, signers: u16) -> Result<Vec<KeyShare>, Error> {
    if threshold < 2 || threshold > signers || signers > 255 {
        return Err(Error::Threshold { threshold, signers });
    }
    let rng = rand_core::OsRng;
    let (shares, public) = frost_ed25519::keys::generate_with_dealer(signers, threshold, IdentifierList::Default, rng)?;
    shares.into_values().map(|s| Ok(KeyShare::new(KeyPackage::try_from(s)?, public.clone()))).collect()
}

/// Argon2id cost parameters, stored with each share file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost: u32,
    /// Iterations.
    pub t_cost: u32,
    /// Parallelism.
    pub p_cost: u32,
}

impl Default for KdfParams {
    /// OWASP's recommended Argon2id setting: 64 MiB, 3 passes.
    fn default() -> Self {
        Self { m_cost: 64 * 1024, t_cost: 3, p_cost: 1 }
    }
}

fn derive_key(passphrase: &[u8], salt: &[u8], kdf: KdfParams) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params =
        Params::new(kdf.m_cost, kdf.t_cost, kdf.p_cost, Some(32)).map_err(|e| Error::malformed("KDF parameters", e))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, &mut *key)
        .map_err(|e| Error::malformed("KDF parameters", e))?;
    Ok(key)
}

/// Public part of a share file. Authenticated, not encrypted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareHeader {
    /// Always [`SHARE_FORMAT`].
    pub format: String,
    /// Group account (`G…`).
    pub account: String,
    /// Participant identifier, hex.
    pub identifier: String,
    /// Signatures needed.
    pub threshold: u16,
    /// Participants in the group.
    pub signers: usize,
    /// Serialized `PublicKeyPackage`, hex.
    pub public_key_package: String,
}

impl ShareHeader {
    fn aad(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|e| Error::malformed("share header", e))
    }
}

/// Encrypted secret share.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    /// Argon2id parameters.
    pub kdf: KdfParams,
    /// Argon2 salt, hex.
    pub salt: String,
    /// XChaCha20-Poly1305 nonce, hex.
    pub nonce: String,
    /// Encrypted `KeyPackage`, hex. The header is the associated data.
    pub ciphertext: String,
}

impl Sealed {
    /// Encrypts `plaintext` under a key derived from `passphrase`, binding `aad`.
    pub(crate) fn seal(passphrase: &[u8], kdf: KdfParams, aad: &[u8], plaintext: &[u8]) -> Result<Self, Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut salt).map_err(|_| Error::Randomness)?;
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let key = derive_key(passphrase, &salt, kdf)?;
        let ciphertext = XChaCha20Poly1305::new((&*key).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .map_err(|_| Error::Decrypt)?;
        Ok(Self { kdf, salt: hex::encode(salt), nonce: hex::encode(nonce), ciphertext: hex::encode(ciphertext) })
    }

    /// Decrypts; fails on a wrong passphrase or if the ciphertext or `aad` changed.
    pub(crate) fn open(&self, passphrase: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        let hx = |what, s: &str| hex::decode(s).map_err(|e| Error::malformed(what, e));
        let salt = hx("salt", &self.salt)?;
        let nonce = hx("nonce", &self.nonce)?;
        if nonce.len() != 24 {
            return Err(Error::malformed("nonce", "expected 24 bytes"));
        }
        let ciphertext = hx("ciphertext", &self.ciphertext)?;
        let key = derive_key(passphrase, &salt, self.kdf)?;
        Ok(Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad })
                .map_err(|_| Error::Decrypt)?,
        ))
    }
}

/// A key share as stored on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ShareFile {
    /// Public, authenticated metadata.
    #[serde(flatten)]
    pub header: ShareHeader,
    /// The encrypted secret.
    pub secret: Sealed,
}

impl ShareFile {
    /// Parses a share file.
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let f: Self = serde_json::from_str(text).map_err(|e| Error::malformed("share file", e))?;
        if f.header.format != SHARE_FORMAT {
            return Err(Error::malformed("share file", format!("unknown format {:?}", f.header.format)));
        }
        Ok(f)
    }

    /// Serializes the share file.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::malformed("share file", e))
    }

    /// Decrypts the share. Fails if the passphrase is wrong or any header field was altered.
    pub fn open(&self, passphrase: &[u8]) -> Result<KeyShare, Error> {
        let plaintext = self.secret.open(passphrase, &self.header.aad()?)?;
        let key_package = KeyPackage::deserialize(&plaintext)?;
        let public_key_package = PublicKeyPackage::deserialize(
            &hex::decode(&self.header.public_key_package).map_err(|e| Error::malformed("public key package", e))?,
        )?;
        let share = KeyShare::new(key_package, public_key_package);
        if share.account() != self.header.account || share.identifier_hex() != self.header.identifier {
            return Err(Error::Decrypt);
        }
        Ok(share)
    }
}

/// Parses a hex identifier from the wire.
pub fn parse_identifier(hex_id: &str) -> Result<Identifier, Error> {
    let bytes = hex::decode(hex_id).map_err(|e| Error::malformed("identifier", e))?;
    Ok(Identifier::deserialize(&bytes)?)
}

/// Maps hex identifiers to decoded values, rejecting duplicates and bad hex.
pub(crate) fn decode_map<T>(
    map: &BTreeMap<String, String>,
    what: &'static str,
    decode: impl Fn(&[u8]) -> Result<T, frost_ed25519::Error>,
) -> Result<BTreeMap<Identifier, T>, Error> {
    let mut out = BTreeMap::new();
    for (id, value) in map {
        let bytes = hex::decode(value).map_err(|e| Error::malformed(what, e))?;
        if out.insert(parse_identifier(id)?, decode(&bytes)?).is_some() {
            return Err(Error::malformed(what, "duplicate identifier"));
        }
    }
    Ok(out)
}
