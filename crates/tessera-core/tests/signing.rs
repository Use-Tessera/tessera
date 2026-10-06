//! FROST signing over Stellar transactions, end to end and adversarially.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use tessera_core::keys::{self, KdfParams, ShareFile};
use tessera_core::stellar::{self, Network};
use tessera_core::xdr::*;
use tessera_core::{Error, signing};

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/payment.xdr");

/// Cheap KDF settings so tests stay fast; production uses `KdfParams::default()`.
const FAST: KdfParams = KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 };

fn payment(source: [u8; 32]) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 100,
            seq_num: SequenceNumber(21_667_474_353_160_193),
            cond: Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(1_791_250_000) }),
            memo: Memo::Text(b"tessera".to_vec().try_into().unwrap()),
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256([7; 32])),
                    asset: Asset::Native,
                    amount: 10_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    })
}

fn verify(group: &[u8; 32], hash: &[u8; 32], sig: &[u8; 64]) {
    VerifyingKey::from_bytes(group).unwrap().verify_strict(hash, &Signature::from_bytes(sig)).unwrap();
}

#[test]
fn fixture_envelope_is_current() {
    let encoded = stellar::encode_envelope(&payment([9; 32])).unwrap() + "\n";
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        std::fs::create_dir_all(std::path::Path::new(FIXTURE).parent().unwrap()).unwrap();
        std::fs::write(FIXTURE, &encoded).unwrap();
    }
    assert_eq!(std::fs::read_to_string(FIXTURE).unwrap().replace("\r\n", "\n"), encoded);
}

#[test]
fn every_two_of_three_subset_produces_a_plain_ed25519_signature() {
    let shares = keys::deal(2, 3).unwrap();
    let group = shares[0].group_public_key();
    assert!(shares.iter().all(|s| s.group_public_key() == group && s.threshold() == 2 && s.signers() == 3));
    assert!(shares[0].account().starts_with('G'));

    let network = Network::from_name("testnet");
    let env = payment(group);
    let hash = stellar::transaction_hash(&network, &env).unwrap();
    for pair in [[0, 1], [0, 2], [1, 2]] {
        let subset = [shares[pair[0]].clone(), shares[pair[1]].clone()];
        let sig = signing::sign_locally(&network, &env, &subset).unwrap();
        verify(&group, &hash, &sig);
    }
    let all = signing::sign_locally(&network, &env, &shares).unwrap();
    verify(&group, &hash, &all);
}

#[test]
fn one_share_cannot_sign_alone() {
    let shares = keys::deal(2, 3).unwrap();
    let env = payment(shares[0].group_public_key());
    let err = signing::sign_locally(&Network::from_name("testnet"), &env, &shares[..1]).unwrap_err();
    assert!(matches!(err, Error::Frost(_)), "{err}");
}

#[test]
fn shares_from_another_group_cannot_join() {
    let a = keys::deal(2, 3).unwrap();
    let b = keys::deal(2, 3).unwrap();
    let env = payment(a[0].group_public_key());
    let mixed = [a[0].clone(), b[1].clone()];
    assert!(signing::sign_locally(&Network::from_name("testnet"), &env, &mixed).is_err());
}

#[test]
fn a_corrupted_signature_share_is_detected_at_aggregation() {
    let shares = keys::deal(2, 3).unwrap();
    let network = Network::from_name("testnet");
    let env = payment(shares[0].group_public_key());

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for s in &shares[..2] {
        let (n, c) = signing::commit(s);
        nonces.insert(s.identifier_hex(), n);
        commitments.insert(s.identifier_hex(), signing::encode_commitments(&c).unwrap());
    }
    let (package, _) = signing::signing_package(&network, &env, &commitments).unwrap();
    let mut sig_shares = BTreeMap::new();
    for s in &shares[..2] {
        sig_shares.insert(
            s.identifier_hex(),
            signing::sign(s, nonces.remove(&s.identifier_hex()).unwrap(), &package).unwrap(),
        );
    }
    // Swap in the other signer's share under this signer's identifier.
    let ids: Vec<String> = sig_shares.keys().cloned().collect();
    let other = sig_shares[&ids[1]].clone();
    sig_shares.insert(ids[0].clone(), other);
    assert!(signing::aggregate(shares[0].public_key_package(), &package, &sig_shares).is_err());
}

#[test]
fn signatures_are_bound_to_the_network() {
    let shares = keys::deal(2, 2).unwrap();
    let group = shares[0].group_public_key();
    let env = payment(group);
    let sig = signing::sign_locally(&Network::from_name("testnet"), &env, &shares).unwrap();
    let public_hash = stellar::transaction_hash(&Network::from_name("public"), &env).unwrap();
    let vk = VerifyingKey::from_bytes(&group).unwrap();
    assert!(vk.verify_strict(&public_hash, &Signature::from_bytes(&sig)).is_err());
}

#[test]
fn attached_signature_lands_on_the_envelope() {
    let shares = keys::deal(2, 3).unwrap();
    let group = shares[0].group_public_key();
    let mut env = payment(group);
    let network = Network::from_name("testnet");
    let sig = signing::sign_locally(&network, &env, &shares[..2]).unwrap();
    stellar::attach_signature(&mut env, &group, &sig).unwrap();
    let TransactionEnvelope::Tx(v1) = &env else { panic!() };
    assert_eq!(v1.signatures.len(), 1);
    assert_eq!(v1.signatures[0].hint.0, group[28..]);
    assert_eq!(
        stellar::transaction_hash(&network, &env).unwrap(),
        stellar::transaction_hash(&network, &payment(group)).unwrap()
    );
}

#[test]
fn share_files_round_trip_and_resist_tampering() {
    let share = keys::deal(2, 3).unwrap().remove(1);
    let file = share.seal(b"correct horse", FAST).unwrap();
    let parsed = ShareFile::from_json(&file.to_json().unwrap()).unwrap();
    let opened = parsed.open(b"correct horse").unwrap();
    assert_eq!(opened.identifier_hex(), share.identifier_hex());
    assert_eq!(opened.account(), share.account());

    assert!(matches!(parsed.open(b"wrong"), Err(Error::Decrypt)));

    let mut lowered = parsed.clone();
    lowered.header.threshold = 1;
    assert!(matches!(lowered.open(b"correct horse"), Err(Error::Decrypt)), "header is authenticated");

    let mut swapped = parsed.clone();
    swapped.header.account = keys::deal(2, 3).unwrap()[0].account();
    assert!(matches!(swapped.open(b"correct horse"), Err(Error::Decrypt)));

    assert!(!file.to_json().unwrap().contains(&hex::encode(share.key_package().signing_share().serialize())));
}

#[test]
fn dealer_rejects_meaningless_thresholds() {
    for (t, n) in [(1, 3), (4, 3), (0, 0), (2, 256)] {
        assert!(matches!(keys::deal(t, n), Err(Error::Threshold { .. })), "{t} of {n}");
    }
}
