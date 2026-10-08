//! The binding gives the same verdicts as the signer's policy code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use serde_json::Value;
use stellar_xdr::{PublicKey, Uint256};
use tessera_wasm::{check, samples};

const POLICY: &str = include_str!("../../../examples/policy.toml");
const FIXTURE: &str = include_str!("../../../crates/tessera-core/tests/fixtures/payment.xdr");
const NOW: f64 = 1_791_249_500.0;
const LEDGER: u32 = 5_000_000;

/// The group account in the core fixtures.
fn group() -> String {
    PublicKey::PublicKeyTypeEd25519(Uint256([9; 32])).to_string()
}

fn run(policy: &str, xdr: &str) -> Value {
    serde_json::from_str(&check(policy, xdr, &group(), NOW, LEDGER)).unwrap()
}

fn sample(id: &str) -> String {
    let all: Value = serde_json::from_str(&samples(&group(), NOW, LEDGER)).unwrap();
    let s = all.as_array().unwrap().iter().find(|s| s["id"] == id).unwrap();
    s["xdr"].as_str().unwrap().to_owned()
}

fn violations(v: &Value) -> Vec<String> {
    assert_eq!(v["ok"], true, "{v}");
    v["violations"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_owned()).collect()
}

#[test]
fn the_core_fixture_is_approved() {
    let v = run(POLICY, FIXTURE);
    assert_eq!(v["kind"], "transaction");
    assert!(violations(&v).is_empty(), "{v}");
    assert_eq!(v["spend"][0]["asset"], "XLM");
}

#[test]
fn each_sample_gets_the_expected_verdict() {
    let cases: &[(&str, Option<&str>)] = &[
        ("payment", None),
        ("too-much", Some("more than per_transaction")),
        ("no-expiry", Some("no expiry")),
        ("merge", Some("account_merge is not allowed")),
        ("contract", None),
        ("auth", Some("does not allow signing authorization entries")),
    ];
    for (id, refusal) in cases {
        let found = violations(&run(POLICY, &sample(id)));
        match refusal {
            None => assert!(found.is_empty(), "{id}: {found:?}"),
            Some(why) => assert!(found.iter().any(|f| f.contains(why)), "{id}: {found:?}"),
        }
    }
}

#[test]
fn an_auth_section_lets_the_entry_through() {
    let policy = format!("{POLICY}\n[auth]\nmax_validity_ledgers = 120\n");
    let v = run(&policy, &sample("auth"));
    assert_eq!(v["kind"], "authorization");
    assert!(violations(&v).is_empty(), "{v}");
}

#[test]
fn unreadable_inputs_say_which_one() {
    let stage = |v: Value| v["stage"].as_str().unwrap().to_owned();
    assert_eq!(stage(run("network = ", FIXTURE)), "policy");
    assert_eq!(stage(run(POLICY, "not xdr")), "xdr");
    assert_eq!(stage(run(POLICY, "  ")), "xdr");
    let v: Value = serde_json::from_str(&check(POLICY, FIXTURE, "GBAD", NOW, LEDGER)).unwrap();
    assert_eq!(stage(v), "account");
    let v: Value = serde_json::from_str(&samples("nope", NOW, LEDGER)).unwrap();
    assert!(v["error"].is_string());
}
