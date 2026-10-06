//! Records real 2-of-3 signing runs, one over a transaction and one over a
//! Soroban authorization entry, for tessera-coordinator's tests.
//!
//! The coordinator (Go) replays this transcript with fake signers, so its
//! verification runs against a genuine FROST aggregate. Regenerate with
//! `UPDATE_FIXTURES=1 cargo test -p tessera-signer --test transcript` and
//! copy the file to tessera-coordinator/testdata.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, missing_docs)]

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Body;
use axum::http::Request;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tessera_core::keys;
use tessera_core::stellar::{self, Network};
use tessera_core::xdr::*;
use tessera_signer::state::SpendLedger;
use tessera_signer::{Signer, router};
use tower::ServiceExt;

const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/transcript.json");
const NOW: u64 = 1_791_249_500;
const LATEST_LEDGER: u32 = 1_000;
const POLICY: &str = concat!(
    include_str!("../../../examples/policy.toml"),
    "
[auth]
max_validity_ledgers = 120
[[token]]
contract = \"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC\"
per_transaction = \"100\"
per_day = \"500\"
"
);

async fn post(r: &axum::Router, path: &str, body: Value) -> Value {
    let req = if body.is_null() {
        Request::get(path).body(Body::empty()).unwrap()
    } else {
        Request::post(path).header("content-type", "application/json").body(Body::from(body.to_string())).unwrap()
    };
    let resp = r.clone().oneshot(req).await.unwrap();
    assert!(resp.status().is_success(), "{path}: {}", resp.status());
    serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

#[tokio::test]
async fn transcript_fixture_verifies() {
    if std::env::var_os("UPDATE_FIXTURES").is_some() {
        record().await;
    }
    let t: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    let key: [u8; 32] = hex::decode(t["group_public_key"].as_str().unwrap()).unwrap().try_into().unwrap();
    let sig: [u8; 64] = hex::decode(t["aggregate"]["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
    let env = stellar::decode_envelope(t["envelope"].as_str().unwrap()).unwrap();
    let hash = stellar::transaction_hash(&Network::from_name("testnet"), &env).unwrap();
    assert_eq!(t["aggregate"]["hash"].as_str().unwrap(), hex::encode(hash));
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();

    let signed = tessera_core::auth::decode_entry(t["auth"]["aggregate"]["auth_entry"].as_str().unwrap()).unwrap();
    let hash = tessera_core::auth::payload_hash(&Network::from_name("testnet"), &signed).unwrap();
    assert_eq!(t["auth"]["aggregate"]["hash"].as_str().unwrap(), hex::encode(hash));
    let sig: [u8; 64] = hex::decode(t["auth"]["aggregate"]["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

/// A 5 XLM SEP-41 `transfer` from the group, valid for 60 ledgers.
fn auth_entry(group: [u8; 32]) -> String {
    let account =
        |k: [u8; 32]| ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))));
    let e = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(group)))),
            nonce: 42,
            signature_expiration_ledger: LATEST_LEDGER + 60,
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
    };
    tessera_core::auth::encode_entry(&e).unwrap()
}

async fn record() {
    let shares = keys::deal(2, 3).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let policy = POLICY;
    let routers: Vec<_> = shares
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let ledger = SpendLedger::open(&dir.path().join(format!("{i}.jsonl"))).unwrap();
            router(Arc::new(
                Signer::new(s.clone(), Network::from_name("testnet"), policy, None, ledger).unwrap().with_clock(|| NOW),
            ))
        })
        .collect();

    let group = shares[0].group_public_key();
    let env = stellar::encode_envelope(&TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(group)),
            fee: 100,
            seq_num: SequenceNumber(42),
            cond: Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(NOW + 300) }),
            memo: Memo::Text(b"transcript".to_vec().try_into().unwrap()),
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256([7; 32])),
                    asset: Asset::Native,
                    amount: 25_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    }))
    .unwrap();

    let mut signers = Vec::new();
    let mut commitments = BTreeMap::new();
    for r in &routers {
        let v = post(r, "/v1/info", Value::Null).await;
        signers.push(json!({ "identifier": v["identifier"], "policy_sha256": v["policy_sha256"] }));
    }
    // Signers 1 and 3 take part.
    for i in [0, 2] {
        let v = post(&routers[i], "/v1/round1", json!({ "session": "transcript" })).await;
        signers[i]["commitments"] = v["commitments"].clone();
        commitments.insert(v["identifier"].as_str().unwrap().to_owned(), v["commitments"].as_str().unwrap().to_owned());
    }
    let mut shares_out = BTreeMap::new();
    for i in [0, 2] {
        let v = post(
            &routers[i],
            "/v1/round2",
            json!({ "session": "transcript", "envelope": env, "commitments": commitments }),
        )
        .await;
        signers[i]["share"] = v["share"].clone();
        shares_out.insert(v["identifier"].as_str().unwrap().to_owned(), v["share"].as_str().unwrap().to_owned());
    }
    let agg = post(
        &routers[0],
        "/v1/aggregate",
        json!({ "envelope": env, "commitments": commitments, "shares": shares_out }),
    )
    .await;

    // The same two sign an authorization entry in a fresh session.
    let entry = auth_entry(group);
    let mut auth_signers = vec![Value::Null; signers.len()];
    let mut commitments = BTreeMap::new();
    for i in [0, 2] {
        let v = post(&routers[i], "/v1/round1", json!({ "session": "transcript-auth" })).await;
        auth_signers[i] = json!({ "commitments": v["commitments"] });
        commitments.insert(v["identifier"].as_str().unwrap().to_owned(), v["commitments"].as_str().unwrap().to_owned());
    }
    let mut auth_shares = BTreeMap::new();
    for i in [0, 2] {
        let body = json!({
            "session": "transcript-auth",
            "auth_entry": entry,
            "latest_ledger": LATEST_LEDGER,
            "commitments": commitments,
        });
        let v = post(&routers[i], "/v1/round2/auth", body).await;
        auth_signers[i]["share"] = v["share"].clone();
        auth_shares.insert(v["identifier"].as_str().unwrap().to_owned(), v["share"].as_str().unwrap().to_owned());
    }
    let auth_agg = post(
        &routers[0],
        "/v1/aggregate/auth",
        json!({ "auth_entry": entry, "commitments": commitments, "shares": auth_shares }),
    )
    .await;

    let transcript = json!({
        "network": Network::TESTNET,
        "account": shares[0].account(),
        "group_public_key": hex::encode(group),
        "threshold": 2,
        "envelope": env,
        "signers": signers,
        "aggregate": agg,
        "auth": {
            "entry": entry,
            "latest_ledger": LATEST_LEDGER,
            "signers": auth_signers,
            "aggregate": auth_agg,
        },
    });
    std::fs::create_dir_all(std::path::Path::new(PATH).parent().unwrap()).unwrap();
    std::fs::write(PATH, serde_json::to_string_pretty(&transcript).unwrap() + "\n").unwrap();
}
