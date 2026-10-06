//! The signer protocol over HTTP, with three in-process signers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tessera_core::keys::{self, KeyShare};
use tessera_core::stellar::{self, Network};
use tessera_core::xdr::*;
use tessera_signer::state::SpendLedger;
use tessera_signer::{Signer, router};
use tower::ServiceExt;

const NOW: u64 = 1_791_249_500;
const POLICY: &str = concat!(
    include_str!("../../../examples/policy.toml"),
    "\n[auth]\nmax_validity_ledgers = 120\n[[token]]\ncontract = \"CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC\"\nper_transaction = \"100\"\nper_day = \"500\"\n"
);
const TOKEN: &str = "s3cret-token";

struct Group {
    shares: Vec<KeyShare>,
    routers: Vec<Router>,
    _dir: tempfile::TempDir,
}

fn group() -> Group {
    let shares = keys::deal(2, 3).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let routers = shares
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let ledger = SpendLedger::open(&dir.path().join(format!("spend-{i}.jsonl"))).unwrap();
            let signer = Signer::new(s.clone(), Network::from_name("testnet"), POLICY, Some(TOKEN.into()), ledger)
                .unwrap()
                .with_clock(|| NOW);
            router(Arc::new(signer))
        })
        .collect();
    Group { shares, routers, _dir: dir }
}

fn payment(source: [u8; 32], xlm: i64) -> String {
    let env = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx: Transaction {
            source_account: MuxedAccount::Ed25519(Uint256(source)),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond: Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(NOW + 300) }),
            memo: Memo::None,
            operations: vec![Operation {
                source_account: None,
                body: OperationBody::Payment(PaymentOp {
                    destination: MuxedAccount::Ed25519(Uint256([7; 32])),
                    asset: Asset::Native,
                    amount: xlm * 10_000_000,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: TransactionExt::V0,
        },
        signatures: VecM::default(),
    });
    stellar::encode_envelope(&env).unwrap()
}

async fn call(r: &Router, path: &str, body: Value, token: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::post(path).header("content-type", "application/json");
    if let Some(t) = token {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    let resp = r.clone().oneshot(req.body(Body::from(body.to_string())).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
}

async fn post(r: &Router, path: &str, body: Value) -> (StatusCode, Value) {
    call(r, path, body, Some(TOKEN)).await
}

/// Runs round 1 on the chosen signers and returns their commitments.
async fn round1(g: &Group, who: &[usize], session: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for &i in who {
        let (st, v) = post(&g.routers[i], "/v1/round1", json!({ "session": session })).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        out.insert(v["identifier"].as_str().unwrap().to_owned(), v["commitments"].as_str().unwrap().to_owned());
    }
    out
}

#[tokio::test]
async fn two_of_three_sign_over_http() {
    let g = group();
    let group_key = g.shares[0].group_public_key();
    let env = payment(group_key, 10);
    let commitments = round1(&g, &[0, 2], "s1").await;

    let mut shares = BTreeMap::new();
    for i in [0, 2] {
        let (st, v) =
            post(&g.routers[i], "/v1/round2", json!({ "session": "s1", "envelope": env, "commitments": commitments }))
                .await;
        assert_eq!(st, StatusCode::OK, "{v}");
        shares.insert(v["identifier"].as_str().unwrap().to_owned(), v["share"].as_str().unwrap().to_owned());
    }

    // Any signer can aggregate, including one that did not sign.
    let (st, v) =
        post(&g.routers[1], "/v1/aggregate", json!({ "envelope": env, "commitments": commitments, "shares": shares }))
            .await;
    assert_eq!(st, StatusCode::OK, "{v}");

    let signed = stellar::decode_envelope(v["envelope"].as_str().unwrap()).unwrap();
    let TransactionEnvelope::Tx(e) = &signed else { panic!() };
    assert_eq!(e.signatures.len(), 1);
    let sig: [u8; 64] = hex::decode(v["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
    let hash = stellar::transaction_hash(&Network::from_name("testnet"), &signed).unwrap();
    assert_eq!(hex::encode(hash), v["hash"].as_str().unwrap());
    ed25519_dalek::VerifyingKey::from_bytes(&group_key)
        .unwrap()
        .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[tokio::test]
async fn policy_refusals_explain_themselves() {
    let g = group();
    let env = payment(g.shares[0].group_public_key(), 150);
    let commitments = round1(&g, &[0, 1], "big").await;
    let (st, v) =
        post(&g.routers[0], "/v1/round2", json!({ "session": "big", "envelope": env, "commitments": commitments }))
            .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(v["violations"][0].as_str().unwrap().contains("per_transaction"), "{v}");
}

#[tokio::test]
async fn nonces_are_single_use() {
    let g = group();
    let env = payment(g.shares[0].group_public_key(), 1);
    let commitments = round1(&g, &[0, 1], "once").await;
    let body = json!({ "session": "once", "envelope": env, "commitments": commitments });
    assert_eq!(post(&g.routers[0], "/v1/round2", body.clone()).await.0, StatusCode::OK);
    assert_eq!(post(&g.routers[0], "/v1/round2", body).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_refused_request_still_burns_the_nonces() {
    let g = group();
    let key = g.shares[0].group_public_key();
    let commitments = round1(&g, &[0, 1], "burn").await;
    let refused = json!({ "session": "burn", "envelope": payment(key, 150), "commitments": commitments });
    assert_eq!(post(&g.routers[0], "/v1/round2", refused).await.0, StatusCode::FORBIDDEN);
    let retry = json!({ "session": "burn", "envelope": payment(key, 1), "commitments": commitments });
    assert_eq!(post(&g.routers[0], "/v1/round2", retry).await.0, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn sessions_cannot_be_reopened() {
    let g = group();
    round1(&g, &[0], "dup").await;
    assert_eq!(post(&g.routers[0], "/v1/round1", json!({ "session": "dup" })).await.0, StatusCode::CONFLICT);
    assert_eq!(post(&g.routers[0], "/v1/round1", json!({ "session": "bad id!" })).await.0, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn daily_limits_accumulate_across_sessions() {
    let g = group();
    let key = g.shares[0].group_public_key();
    for n in 0..5 {
        let s = format!("d{n}");
        let commitments = round1(&g, &[0, 1], &s).await;
        let body = json!({ "session": s, "envelope": payment(key, 100), "commitments": commitments });
        assert_eq!(post(&g.routers[0], "/v1/round2", body).await.0, StatusCode::OK, "payment {n}");
    }
    let commitments = round1(&g, &[0, 1], "d5").await;
    let (st, v) = post(
        &g.routers[0],
        "/v1/round2",
        json!({ "session": "d5", "envelope": payment(key, 1), "commitments": commitments }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(v["violations"][0].as_str().unwrap().contains("per_day"), "{v}");
}

#[tokio::test]
async fn transactions_for_other_accounts_are_refused() {
    let g = group();
    let commitments = round1(&g, &[0, 1], "foreign").await;
    let (st, v) = post(
        &g.routers[0],
        "/v1/round2",
        json!({ "session": "foreign", "envelope": payment([3; 32], 1), "commitments": commitments }),
    )
    .await;
    assert_eq!(st, StatusCode::FORBIDDEN);
    assert!(v["violations"][0].as_str().unwrap().contains("not the group account"), "{v}");
}

#[tokio::test]
async fn every_route_requires_the_token() {
    let g = group();
    for path in ["/v1/round1", "/v1/round2", "/v1/aggregate"] {
        assert_eq!(call(&g.routers[0], path, json!({}), None).await.0, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(call(&g.routers[0], path, json!({}), Some("wrong")).await.0, StatusCode::UNAUTHORIZED, "{path}");
    }
    let resp = g.routers[0].clone().oneshot(Request::get("/v1/info").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn info_identifies_the_group_and_policy() {
    let g = group();
    let req = Request::get("/v1/info").header("authorization", format!("Bearer {TOKEN}")).body(Body::empty()).unwrap();
    let resp = g.routers[2].clone().oneshot(req).await.unwrap();
    let v: Value = serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(v["account"], g.shares[0].account());
    assert_eq!(v["threshold"], 2);
    assert_eq!(v["protocol"], "tessera/signer/v1");
    assert_eq!(v["policy_sha256"].as_str().unwrap().len(), 64);
}

#[test]
fn a_policy_for_another_network_is_rejected_at_startup() {
    let share = keys::deal(2, 2).unwrap().remove(0);
    let dir = tempfile::tempdir().unwrap();
    let ledger = SpendLedger::open(&dir.path().join("spend.jsonl")).unwrap();
    assert!(Signer::new(share, Network::from_name("public"), POLICY, None, ledger).is_err());
}

#[test]
fn the_spend_ledger_survives_restarts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("spend.jsonl");
    SpendLedger::open(&path).unwrap().record(NOW, "aa", &[("native".into(), 30)]).unwrap();
    let reopened = SpendLedger::open(&path).unwrap();
    assert_eq!(reopened.spent_since("native", NOW + 10), 30);
    assert_eq!(reopened.spent_since("native", NOW + 86_400), 0, "entries age out after 24h");
}

fn auth_entry(group: [u8; 32], xlm: u64, expires: u32) -> String {
    let account =
        |k: [u8; 32]| ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))));
    let e = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(group)))),
            nonce: 42,
            signature_expiration_ledger: expires,
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                contract_address: ScAddress::Contract(
                    "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC".parse().unwrap(),
                ),
                function_name: ScSymbol(b"transfer".to_vec().try_into().unwrap()),
                args: vec![account(group), account([7; 32]), ScVal::I128(Int128Parts { hi: 0, lo: xlm * 10_000_000 })]
                    .try_into()
                    .unwrap(),
            }),
            sub_invocations: VecM::default(),
        },
    };
    tessera_core::auth::encode_entry(&e).unwrap()
}

#[tokio::test]
async fn two_of_three_sign_an_authorization_entry() {
    let g = group();
    let key = g.shares[0].group_public_key();
    let entry = auth_entry(key, 5, 1_060);
    let commitments = round1(&g, &[1, 2], "auth").await;
    let mut shares = BTreeMap::new();
    for i in [1, 2] {
        let body =
            json!({ "session": "auth", "auth_entry": entry, "latest_ledger": 1_000, "commitments": commitments });
        let (st, v) = post(&g.routers[i], "/v1/round2/auth", body).await;
        assert_eq!(st, StatusCode::OK, "{v}");
        shares.insert(v["identifier"].as_str().unwrap().to_owned(), v["share"].as_str().unwrap().to_owned());
    }
    let (st, v) = post(
        &g.routers[0],
        "/v1/aggregate/auth",
        json!({ "auth_entry": entry, "commitments": commitments, "shares": shares }),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{v}");
    let signed = tessera_core::auth::decode_entry(v["auth_entry"].as_str().unwrap()).unwrap();
    let hash = tessera_core::auth::payload_hash(&Network::from_name("testnet"), &signed).unwrap();
    let sig: [u8; 64] = hex::decode(v["signature"].as_str().unwrap()).unwrap().try_into().unwrap();
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&hash, &ed25519_dalek::Signature::from_bytes(&sig))
        .unwrap();
}

#[tokio::test]
async fn authorization_entries_obey_the_policy() {
    let g = group();
    let key = g.shares[0].group_public_key();
    for (session, entry, latest, want) in [
        ("big", auth_entry(key, 150, 1_060), 1_000, "per_transaction"),
        ("long", auth_entry(key, 1, 5_000), 1_000, "max_validity_ledgers"),
        ("other", auth_entry([3; 32], 1, 1_060), 1_000, "not the group account"),
    ] {
        let commitments = round1(&g, &[0, 1], session).await;
        let body =
            json!({ "session": session, "auth_entry": entry, "latest_ledger": latest, "commitments": commitments });
        let (st, v) = post(&g.routers[0], "/v1/round2/auth", body).await;
        assert_eq!(st, StatusCode::FORBIDDEN, "{session}: {v}");
        assert!(v["violations"].to_string().contains(want), "{session}: {v}");
    }
}

#[tokio::test]
async fn a_stale_latest_ledger_is_refused() {
    let g = group();
    let key = g.shares[0].group_public_key();
    let commitments = round1(&g, &[0, 1], "fresh").await;
    let ok = json!({ "session": "fresh", "auth_entry": auth_entry(key, 1, 100_060), "latest_ledger": 100_000, "commitments": commitments });
    assert_eq!(post(&g.routers[0], "/v1/round2/auth", ok).await.0, StatusCode::OK);
    let commitments = round1(&g, &[0, 1], "stale").await;
    let stale = json!({ "session": "stale", "auth_entry": auth_entry(key, 1, 1_060), "latest_ledger": 1_000, "commitments": commitments });
    let (st, v) = post(&g.routers[0], "/v1/round2/auth", stale).await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{v}");
    assert!(v["error"].as_str().unwrap().contains("stale"));
}

#[tokio::test]
async fn health_needs_no_token_and_bodies_are_capped() {
    let g = group();
    let resp = g.routers[0].clone().oneshot(Request::get("/healthz").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let huge = format!("{{\"session\":\"{}\"}}", "a".repeat(tessera_signer::MAX_BODY));
    let req = Request::post("/v1/round1")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {TOKEN}"))
        .body(Body::from(huge))
        .unwrap();
    let resp = g.routers[0].clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}
