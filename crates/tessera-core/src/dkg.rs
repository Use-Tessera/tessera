//! Distributed key generation: no participant, and no machine, ever holds the
//! whole key.
//!
//! Each participant runs three steps, with a broadcast after each of the first two:
//!
//! 1. [`start`] returns a [`Round1Message`] for everyone: a FROST commitment
//!    with a proof of knowledge (RFC 9591's DKG), plus an X25519 key on which
//!    the participant receives round 2.
//! 2. [`exchange`], given everyone's round-1 messages, returns one
//!    [`Round2Message`] per other participant, encrypted to that participant.
//! 3. [`finish`], given the round-2 messages addressed to this participant,
//!    returns its [`KeyShare`]. Every participant ends with the same group key.
//!
//! Messages may travel through an untrusted relay. Round-2 packages are
//! encrypted and bound to their sender and recipient, so the relay can neither
//! read nor redirect them. The relay could still substitute round-1 messages,
//! so before step 2 participants compare the round-1 [`fingerprint`] over a
//! channel the relay does not control, such as a call.
//!
//! Between steps the participant's secret state is sealed under a passphrase
//! as a [`StateFile`].

use std::collections::BTreeMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use frost_ed25519::Identifier;
use frost_ed25519::keys::dkg::{self as fdkg, round1, round2};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::Error;
use crate::keys::{KdfParams, KeyShare, Sealed, parse_identifier};

/// Format tag of round-1 messages.
pub const ROUND1_FORMAT: &str = "tessera/dkg/round1/v1";
/// Format tag of round-2 messages.
pub const ROUND2_FORMAT: &str = "tessera/dkg/round2/v1";
/// Format tag of sealed state files.
pub const STATE_FORMAT: &str = "tessera/dkg/state/v1";

/// Broadcast by every participant after [`start`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Round1Message {
    /// Always [`ROUND1_FORMAT`].
    pub format: String,
    /// Sender's FROST identifier, hex.
    pub identifier: String,
    /// Signatures the group will need.
    pub threshold: u16,
    /// Participants in the group.
    pub signers: u16,
    /// FROST round-1 package (commitment and proof of knowledge), hex.
    pub package: String,
    /// X25519 public key that round-2 packages for the sender are encrypted to, hex.
    pub encryption_key: String,
    /// For a share refresh, the group account whose shares are refreshed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<String>,
}

/// Sent by one participant to one other after [`exchange`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Round2Message {
    /// Always [`ROUND2_FORMAT`].
    pub format: String,
    /// Sender's identifier, hex.
    pub from: String,
    /// Recipient's identifier, hex.
    pub to: String,
    /// XChaCha20-Poly1305 nonce, hex.
    pub nonce: String,
    /// Encrypted FROST round-2 package, hex.
    pub ciphertext: String,
}

/// A participant's secret state between [`start`] and [`exchange`].
pub struct Round1State {
    secret: round1::SecretPackage,
    dh: StaticSecret,
    message: Round1Message,
    old: Option<KeyShare>,
}

/// A participant's secret state between [`exchange`] and [`finish`].
pub struct Round2State {
    secret: round2::SecretPackage,
    dh: StaticSecret,
    round1: Vec<Round1Message>,
    old: Option<KeyShare>,
}

/// Step 1: participant `index` (1-based) of a `threshold`-of-`signers` group.
pub fn start(index: u16, threshold: u16, signers: u16) -> Result<(Round1State, Round1Message), Error> {
    if threshold < 2 || threshold > signers || signers > 255 {
        return Err(Error::Threshold { threshold, signers });
    }
    if index == 0 || index > signers {
        return Err(Error::Dkg(format!("participant index must be 1..={signers}, got {index}")));
    }
    let id = Identifier::try_from(index)?;
    let (secret, package) = fdkg::part1(id, signers, threshold, rand_core::OsRng)?;
    begin(secret, package, threshold, signers, None)
}

/// Step 1 of a proactive refresh: `participants` holders of `share`'s group
/// (all of them, or at least the threshold to drop the others) re-randomise
/// their shares. The group key stays the same, and shares from before the
/// refresh no longer combine with shares from after it, so a share that
/// leaked earlier becomes useless once every participant has refreshed.
pub fn start_refresh(share: &KeyShare, participants: u16) -> Result<(Round1State, Round1Message), Error> {
    let threshold = share.threshold();
    if participants < threshold || usize::from(participants) > share.signers() {
        return Err(Error::Dkg(format!(
            "a refresh needs between {threshold} and {} participants, got {participants}",
            share.signers()
        )));
    }
    let (secret, package) =
        frost_ed25519::keys::refresh::refresh_dkg_part1(share.identifier(), participants, threshold, rand_core::OsRng)?;
    begin(secret, package, threshold, participants, Some(share.clone()))
}

fn begin(
    secret: round1::SecretPackage,
    package: round1::Package,
    threshold: u16,
    signers: u16,
    old: Option<KeyShare>,
) -> Result<(Round1State, Round1Message), Error> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|_| Error::Randomness)?;
    let dh = StaticSecret::from(*seed);
    let message = Round1Message {
        format: ROUND1_FORMAT.into(),
        identifier: hex::encode(secret.identifier().serialize()),
        threshold,
        signers,
        package: hex::encode(package.serialize()?),
        encryption_key: hex::encode(PublicKey::from(&dh).as_bytes()),
        refresh: old.as_ref().map(KeyShare::account),
    };
    Ok((Round1State { secret, dh, message: message.clone(), old }, message))
}

/// SHA-256 over the full set of round-1 messages, in identifier order.
///
/// Every participant must see the same value before running [`exchange`].
pub fn fingerprint(round1: &[Round1Message]) -> Result<String, Error> {
    let mut sorted: Vec<&Round1Message> = round1.iter().collect();
    sorted.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    let mut h = Sha256::new();
    h.update(ROUND1_FORMAT.as_bytes());
    for m in sorted {
        let json = serde_json::to_vec(m).map_err(|e| Error::malformed("round-1 message", e))?;
        h.update((json.len() as u64).to_be_bytes());
        h.update(&json);
    }
    Ok(hex::encode(h.finalize()))
}

/// Step 2: given every participant's round-1 message (this one's may be
/// included), returns the round-2 messages to deliver.
pub fn exchange(state: Round1State, round1: &[Round1Message]) -> Result<(Round2State, Vec<Round2Message>), Error> {
    let all = complete_round1(&state.message, round1)?;
    let me = parse_identifier(&state.message.identifier)?;
    let others = round1_packages(&all, me)?;
    let (secret, outgoing) = match state.old {
        Some(_) => frost_ed25519::keys::refresh::refresh_dkg_part2(state.secret, &others)?,
        None => fdkg::part2(state.secret, &others)?,
    };

    let mut messages = Vec::with_capacity(outgoing.len());
    for (to, package) in outgoing {
        let recipient = find(&all, to)?;
        let key = channel_key(&state.dh, &recipient.encryption_key, me, to)?;
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
        let plaintext = Zeroizing::new(package.serialize()?);
        let ciphertext = XChaCha20Poly1305::new((&*key).into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &route(me, to) })
            .map_err(|_| Error::Dkg("encryption failed".into()))?;
        messages.push(Round2Message {
            format: ROUND2_FORMAT.into(),
            from: hex::encode(me.serialize()),
            to: hex::encode(to.serialize()),
            nonce: hex::encode(nonce),
            ciphertext: hex::encode(ciphertext),
        });
    }
    Ok((Round2State { secret, dh: state.dh, round1: all, old: state.old }, messages))
}

/// Step 3: given round-2 messages (those for other participants are ignored),
/// returns this participant's key share.
pub fn finish(state: Round2State, round2: &[Round2Message]) -> Result<KeyShare, Error> {
    let me = *state.secret.identifier();
    let mine = hex::encode(me.serialize());
    let mut packages = BTreeMap::new();
    for m in round2.iter().filter(|m| m.to == mine) {
        if m.format != ROUND2_FORMAT {
            return Err(Error::Dkg(format!("unknown round-2 format {:?}", m.format)));
        }
        let from = parse_identifier(&m.from)?;
        if from == me {
            return Err(Error::Dkg("a round-2 message claims to come from this participant".into()));
        }
        let sender = find(&state.round1, from)?;
        let key = channel_key(&state.dh, &sender.encryption_key, from, me)?;
        let nonce = hex::decode(&m.nonce).map_err(|e| Error::malformed("round-2 nonce", e))?;
        if nonce.len() != 24 {
            return Err(Error::malformed("round-2 nonce", "expected 24 bytes"));
        }
        let ciphertext = hex::decode(&m.ciphertext).map_err(|e| Error::malformed("round-2 ciphertext", e))?;
        let plaintext = Zeroizing::new(
            XChaCha20Poly1305::new((&*key).into())
                .decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &route(from, me) })
                .map_err(|_| Error::Dkg(format!("round-2 message from {} does not decrypt", m.from)))?,
        );
        if packages.insert(from, round2::Package::deserialize(&plaintext)?).is_some() {
            return Err(Error::Dkg(format!("two round-2 messages from {}", m.from)));
        }
    }
    let expected = state.round1.len().saturating_sub(1);
    if packages.len() != expected {
        return Err(Error::Dkg(format!("expected {expected} round-2 messages for {mine}, got {}", packages.len())));
    }
    let round1 = round1_packages(&state.round1, me)?;
    let Some(old) = state.old else {
        let (key_package, public_key_package) = fdkg::part3(&state.secret, &round1, &packages)?;
        return Ok(KeyShare::new(key_package, public_key_package));
    };
    let (key_package, public_key_package) = frost_ed25519::keys::refresh::refresh_dkg_shares(
        &state.secret,
        &round1,
        &packages,
        old.public_key_package().clone(),
        old.key_package().clone(),
    )?;
    let share = KeyShare::new(key_package, public_key_package);
    if share.account() != old.account() {
        return Err(Error::Dkg("the refresh changed the group key".into()));
    }
    Ok(share)
}

/// Checks the round-1 set is complete and consistent and that this
/// participant's own message is the one it sent.
fn complete_round1(own: &Round1Message, given: &[Round1Message]) -> Result<Vec<Round1Message>, Error> {
    let mut all: BTreeMap<String, Round1Message> = BTreeMap::new();
    all.insert(own.identifier.clone(), own.clone());
    for m in given {
        if m.format != ROUND1_FORMAT {
            return Err(Error::Dkg(format!("unknown round-1 format {:?}", m.format)));
        }
        if m.refresh != own.refresh {
            return Err(Error::Dkg(format!(
                "{} is {}, this participant is {}",
                m.identifier,
                describe(m.refresh.as_deref()),
                describe(own.refresh.as_deref())
            )));
        }
        if m.threshold != own.threshold || m.signers != own.signers {
            return Err(Error::Dkg(format!(
                "{} is running {}-of-{}, this participant {}-of-{}",
                m.identifier, m.threshold, m.signers, own.threshold, own.signers
            )));
        }
        if m.identifier == own.identifier {
            if m != own {
                return Err(Error::Dkg(
                    "the round-1 set carries a different message under this participant's identifier".into(),
                ));
            }
            continue;
        }
        if all.insert(m.identifier.clone(), m.clone()).is_some() {
            return Err(Error::Dkg(format!("two round-1 messages from {}", m.identifier)));
        }
    }
    if all.len() != usize::from(own.signers) {
        return Err(Error::Dkg(format!("expected {} round-1 messages, got {}", own.signers, all.len())));
    }
    Ok(all.into_values().collect())
}

fn describe(refresh: Option<&str>) -> String {
    refresh.map_or_else(|| "generating a new key".into(), |account| format!("refreshing {account}"))
}

fn round1_packages(all: &[Round1Message], me: Identifier) -> Result<BTreeMap<Identifier, round1::Package>, Error> {
    let mut out = BTreeMap::new();
    for m in all {
        let id = parse_identifier(&m.identifier)?;
        if id != me {
            let bytes = hex::decode(&m.package).map_err(|e| Error::malformed("round-1 package", e))?;
            out.insert(id, round1::Package::deserialize(&bytes)?);
        }
    }
    Ok(out)
}

fn find(all: &[Round1Message], id: Identifier) -> Result<&Round1Message, Error> {
    let wanted = hex::encode(id.serialize());
    all.iter().find(|m| m.identifier == wanted).ok_or_else(|| Error::Dkg(format!("{wanted} took no part in round 1")))
}

/// Associated data binding a round-2 ciphertext to its sender and recipient.
fn route(from: Identifier, to: Identifier) -> Vec<u8> {
    [ROUND2_FORMAT.as_bytes(), &from.serialize(), &to.serialize()].concat()
}

/// Key for the `from` → `to` channel: SHA-256 over the X25519 shared secret and both identifiers.
fn channel_key(
    own: &StaticSecret,
    their_hex: &str,
    from: Identifier,
    to: Identifier,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let their: [u8; 32] = hex::decode(their_hex)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Error::malformed("encryption key", "expected 32 bytes of hex"))?;
    let shared = own.diffie_hellman(&PublicKey::from(their));
    if !shared.was_contributory() {
        return Err(Error::Dkg("encryption key is a low-order point".into()));
    }
    let mut h = Sha256::new();
    h.update(b"tessera/dkg/v1 channel key");
    h.update(shared.as_bytes());
    h.update(from.serialize());
    h.update(to.serialize());
    Ok(Zeroizing::new(h.finalize().into()))
}

/// A participant's DKG state, sealed under a passphrase between steps.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateFile {
    /// Always [`STATE_FORMAT`].
    pub format: String,
    /// 1 after [`start`], 2 after [`exchange`].
    pub step: u8,
    /// Participant identifier, hex.
    pub identifier: String,
    /// The encrypted state. `format`, `step` and `identifier` are its associated data.
    pub secret: Sealed,
}

/// A state file's decrypted contents.
pub enum State {
    /// Waiting for round-1 messages.
    Round1(Round1State),
    /// Waiting for round-2 messages.
    Round2(Round2State),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateBody {
    secret: String,
    dh: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<Round1Message>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    round1: Vec<Round1Message>,
    /// For a refresh: the share being replaced, as hex `KeyPackage` and `PublicKeyPackage`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    old: Option<[String; 2]>,
}

fn encode_old(old: Option<&KeyShare>) -> Result<Option<[String; 2]>, Error> {
    old.map(|s| Ok([hex::encode(s.key_package().serialize()?), hex::encode(s.public_key_package().serialize()?)]))
        .transpose()
}

fn decode_old(old: Option<[String; 2]>) -> Result<Option<KeyShare>, Error> {
    old.map(|[key, public]| {
        let hx = |s: &str| hex::decode(s).map_err(|e| Error::malformed("DKG state", e));
        let key = Zeroizing::new(hx(&key)?);
        Ok(KeyShare::new(
            frost_ed25519::keys::KeyPackage::deserialize(&key)?,
            frost_ed25519::keys::PublicKeyPackage::deserialize(&hx(&public)?)?,
        ))
    })
    .transpose()
}

impl Round1State {
    /// This participant's round-1 message.
    pub fn message(&self) -> &Round1Message {
        &self.message
    }

    /// Seals the state under `passphrase`.
    pub fn seal(&self, passphrase: &[u8], kdf: KdfParams) -> Result<StateFile, Error> {
        let body = StateBody {
            secret: hex::encode(self.secret.serialize()?),
            dh: hex::encode(self.dh.to_bytes()),
            message: Some(self.message.clone()),
            round1: Vec::new(),
            old: encode_old(self.old.as_ref())?,
        };
        StateFile::seal(1, &self.message.identifier, &body, passphrase, kdf)
    }
}

impl Round2State {
    /// Seals the state under `passphrase`.
    pub fn seal(&self, passphrase: &[u8], kdf: KdfParams) -> Result<StateFile, Error> {
        let body = StateBody {
            secret: hex::encode(self.secret.serialize()?),
            dh: hex::encode(self.dh.to_bytes()),
            message: None,
            round1: self.round1.clone(),
            old: encode_old(self.old.as_ref())?,
        };
        StateFile::seal(2, &hex::encode(self.secret.identifier().serialize()), &body, passphrase, kdf)
    }
}

impl StateFile {
    fn seal(step: u8, identifier: &str, body: &StateBody, passphrase: &[u8], kdf: KdfParams) -> Result<Self, Error> {
        let mut file = Self {
            format: STATE_FORMAT.into(),
            step,
            identifier: identifier.into(),
            secret: Sealed { kdf, salt: String::new(), nonce: String::new(), ciphertext: String::new() },
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(body).map_err(|e| Error::malformed("DKG state", e))?);
        file.secret = Sealed::seal(passphrase, kdf, &file.aad(), &plaintext)?;
        Ok(file)
    }

    fn aad(&self) -> Vec<u8> {
        format!("{}\n{}\n{}", self.format, self.step, self.identifier).into_bytes()
    }

    /// Parses a state file.
    pub fn from_json(text: &str) -> Result<Self, Error> {
        let f: Self = serde_json::from_str(text).map_err(|e| Error::malformed("DKG state file", e))?;
        if f.format != STATE_FORMAT {
            return Err(Error::malformed("DKG state file", format!("unknown format {:?}", f.format)));
        }
        Ok(f)
    }

    /// Serializes the state file.
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(|e| Error::malformed("DKG state file", e))
    }

    /// Decrypts the state.
    pub fn open(&self, passphrase: &[u8]) -> Result<State, Error> {
        let plaintext = self.secret.open(passphrase, &self.aad())?;
        let body: StateBody = serde_json::from_slice(&plaintext).map_err(|e| Error::malformed("DKG state", e))?;
        let secret = Zeroizing::new(hex::decode(&body.secret).map_err(|e| Error::malformed("DKG state", e))?);
        let dh: [u8; 32] = hex::decode(&body.dh)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| Error::malformed("DKG state", "bad X25519 secret"))?;
        let dh = StaticSecret::from(dh);
        let old = decode_old(body.old)?;
        match (self.step, body.message) {
            (1, Some(message)) => Ok(State::Round1(Round1State {
                secret: round1::SecretPackage::deserialize(&secret)?,
                dh,
                message,
                old,
            })),
            (2, None) => Ok(State::Round2(Round2State {
                secret: round2::SecretPackage::deserialize(&secret)?,
                dh,
                round1: body.round1,
                old,
            })),
            _ => Err(Error::malformed("DKG state", "step and contents disagree")),
        }
    }
}
