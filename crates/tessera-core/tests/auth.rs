//! Threshold signatures over Soroban authorization entries.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use ed25519_dalek::{Signature, VerifyingKey};
use tessera_core::stellar::Network;
use tessera_core::xdr::*;
use tessera_core::{auth, keys, signing};

/// An entry authorizing `transfer(group, dest, 5 XLM)` on the native asset contract.
fn entry(group: [u8; 32]) -> SorobanAuthorizationEntry {
    let account =
        |k: [u8; 32]| ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))));
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(group)))),
            nonce: 7_123_456_789,
            signature_expiration_ledger: 5_060_000,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".parse().unwrap(),
                ),
                function_name: ScSymbol(b"transfer".to_vec().try_into().unwrap()),
                args: vec![account(group), account([7; 32]), ScVal::I128(Int128Parts { hi: 0, lo: 50_000_000 })]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    }
}

#[test]
fn a_two_of_three_group_signs_an_authorization_entry() {
    let shares = keys::deal(2, 3).unwrap();
    let group = shares[0].group_public_key();
    let network = Network::from_name("testnet");
    let mut e = entry(group);

    let hash = auth::payload_hash(&network, &e).unwrap();
    let sig = signing::sign_message_locally(&hash, &shares[1..]).unwrap();
    VerifyingKey::from_bytes(&group).unwrap().verify_strict(&hash, &Signature::from_bytes(&sig)).unwrap();

    auth::attach_signature(&mut e, &group, &sig).unwrap();
    let SorobanCredentials::Address(c) = &e.credentials else { panic!() };
    let ScVal::Vec(Some(list)) = &c.signature else { panic!("signature is not a vec") };
    let ScVal::Map(Some(map)) = &list[0] else { panic!("entry is not a map") };
    assert_eq!(map.len(), 2);
    assert!(matches!(&map[0].key, ScVal::Symbol(s) if s.0.as_slice() == b"public_key"));
    assert!(matches!(&map[1].val, ScVal::Bytes(b) if b.0.as_slice() == sig));

    // The signature does not change the payload, and the entry round-trips.
    assert_eq!(auth::payload_hash(&network, &e).unwrap(), hash);
    assert_eq!(auth::decode_entry(&auth::encode_entry(&e).unwrap()).unwrap(), e);
}

#[test]
fn the_payload_binds_network_nonce_expiry_and_invocation() {
    let e = entry([9; 32]);
    let base = auth::payload_hash(&Network::from_name("testnet"), &e).unwrap();
    assert_ne!(auth::payload_hash(&Network::from_name("public"), &e).unwrap(), base);
    for change in 0..3 {
        let mut other = e.clone();
        let SorobanCredentials::Address(c) = &mut other.credentials else { panic!() };
        match change {
            0 => c.nonce += 1,
            1 => c.signature_expiration_ledger += 1,
            _ => other.root_invocation.sub_invocations = vec![e.root_invocation.clone()].try_into().unwrap(),
        }
        assert_ne!(auth::payload_hash(&Network::from_name("testnet"), &other).unwrap(), base, "change {change}");
    }
}

#[test]
fn source_account_entries_are_not_signed_here() {
    let mut e = entry([9; 32]);
    e.credentials = SorobanCredentials::SourceAccount;
    assert!(auth::payload_hash(&Network::from_name("testnet"), &e).is_err());
    assert!(auth::attach_signature(&mut e, &[9; 32], &[0; 64]).is_err());
}
