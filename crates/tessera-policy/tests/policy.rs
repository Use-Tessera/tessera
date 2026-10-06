//! Every policy rule, approved and refused.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use tessera_core::stellar::account_id;
use tessera_core::xdr::*;
use tessera_policy::{Intent, OpKind, Policy, format_amount, parse_amount};

const NOW: u64 = 1_791_249_500;
const GROUP: [u8; 32] = [9; 32];
const USDC_ISSUER: &str = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5";
const CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

fn policy() -> Policy {
    Policy::from_toml(include_str!("../../../examples/policy.toml")).unwrap()
}

fn group() -> String {
    account_id(&GROUP)
}

fn tx(ops: Vec<OperationBody>) -> Transaction {
    Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(GROUP)),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(NOW + 300) }),
        memo: Memo::None,
        operations: ops
            .into_iter()
            .map(|body| Operation { source_account: None, body })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap(),
        ext: TransactionExt::V0,
    }
}

fn env(t: Transaction) -> TransactionEnvelope {
    TransactionEnvelope::Tx(TransactionV1Envelope { tx: t, signatures: VecM::default() })
}

fn pay(asset: Asset, amount: i64) -> OperationBody {
    OperationBody::Payment(PaymentOp { destination: MuxedAccount::Ed25519(Uint256([7; 32])), asset, amount })
}

fn xlm(units: i64) -> OperationBody {
    pay(Asset::Native, units * 10_000_000)
}

fn usdc(units: i64) -> OperationBody {
    let issuer: AccountId = USDC_ISSUER.parse().unwrap();
    pay(Asset::CreditAlphanum4(AlphaNum4 { asset_code: AssetCode4(*b"USDC"), issuer }), units * 10_000_000)
}

fn call(contract: &str, function: &str) -> OperationBody {
    let id: ContractId = contract.parse().unwrap();
    OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function: HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: ScAddress::Contract(id),
            function_name: ScSymbol(function.as_bytes().to_vec().try_into().unwrap()),
            args: VecM::default(),
        }),
        auth: VecM::default(),
    })
}

fn judge(t: Transaction) -> Vec<String> {
    judge_env(env(t), 0)
}

fn judge_env(e: TransactionEnvelope, spent: i128) -> Vec<String> {
    policy().evaluate(&Intent::from_envelope(&e), &group(), NOW, |_| spent).violations
}

fn refused(t: Transaction, needle: &str) {
    let v = judge(t);
    assert!(v.iter().any(|m| m.contains(needle)), "expected a violation containing {needle:?}, got {v:?}");
}

#[test]
fn an_ordinary_payment_is_approved() {
    let d = policy().evaluate(&Intent::from_envelope(&env(tx(vec![xlm(10)]))), &group(), NOW, |_| 0);
    assert!(d.approved(), "{:?}", d.violations);
    assert_eq!(d.spend.get("native"), Some(&100_000_000));
}

#[test]
fn the_source_must_be_the_group_account() {
    let mut t = tx(vec![xlm(1)]);
    t.source_account = MuxedAccount::Ed25519(Uint256([1; 32]));
    refused(t, "is not the group account");
}

#[test]
fn transactions_must_expire_soon() {
    let mut t = tx(vec![xlm(1)]);
    t.cond = Preconditions::None;
    refused(t, "no expiry");

    let mut t = tx(vec![xlm(1)]);
    t.cond = Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(NOW + 3_600) });
    refused(t, "more than max_validity");

    let mut t = tx(vec![xlm(1)]);
    t.cond = Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(NOW - 1) });
    refused(t, "already expired");
}

#[test]
fn fees_are_capped() {
    let mut t = tx(vec![xlm(1)]);
    t.fee = 200_000;
    refused(t, "exceeds max_fee");
}

#[test]
fn dangerous_operations_are_refused_by_default() {
    let set_options = OperationBody::SetOptions(SetOptionsOp {
        inflation_dest: None,
        clear_flags: None,
        set_flags: None,
        master_weight: Some(0),
        low_threshold: None,
        med_threshold: None,
        high_threshold: None,
        home_domain: None,
        signer: None,
    });
    refused(tx(vec![set_options]), "set_options is not allowed");

    let merge = OperationBody::AccountMerge(MuxedAccount::Ed25519(Uint256([7; 32])));
    refused(tx(vec![merge]), "account_merge is not allowed");
}

#[test]
fn operations_cannot_act_for_other_accounts() {
    let mut t = tx(vec![xlm(1)]);
    let mut ops = t.operations.to_vec();
    ops[0].source_account = Some(MuxedAccount::Ed25519(Uint256([3; 32])));
    t.operations = ops.try_into().unwrap();
    refused(t, "acts for another account");
}

#[test]
fn unlisted_assets_are_refused() {
    let issuer: AccountId = USDC_ISSUER.parse().unwrap();
    let eurc = pay(Asset::CreditAlphanum4(AlphaNum4 { asset_code: AssetCode4(*b"EURC"), issuer }), 1);
    refused(tx(vec![eurc]), "no limits configured for asset EURC");
}

#[test]
fn per_transaction_limits_sum_every_operation() {
    assert!(judge(tx(vec![xlm(60), xlm(40)])).is_empty());
    refused(tx(vec![xlm(60), xlm(41)]), "more than per_transaction 100");
    refused(tx(vec![usdc(251)]), "more than per_transaction 250");
}

#[test]
fn daily_limits_include_what_was_already_spent() {
    assert!(judge_env(env(tx(vec![xlm(100)])), 400 * 10_000_000).is_empty());
    let v = judge_env(env(tx(vec![xlm(100)])), 401 * 10_000_000);
    assert!(v.iter().any(|m| m.contains("24h spend of native to 501")), "{v:?}");
}

#[test]
fn create_account_spends_lumens_but_must_be_allowed() {
    let create = OperationBody::CreateAccount(CreateAccountOp {
        destination: AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([5; 32]))),
        starting_balance: 50_000_000,
    });
    refused(tx(vec![create]), "create_account is not allowed");
}

#[test]
fn destination_allowlist_applies_when_configured() {
    let toml = include_str!("../../../examples/policy.toml").replace(
        "# [destinations]\n# allow = [\"GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR\"]",
        "[destinations]\nallow = [\"GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR\"]",
    );
    let p = Policy::from_toml(&toml).unwrap();
    let v = p.evaluate(&Intent::from_envelope(&env(tx(vec![xlm(1)]))), &group(), NOW, |_| 0).violations;
    assert!(v.iter().any(|m| m.contains("not on the allowlist")), "{v:?}");
}

#[test]
fn contract_calls_need_both_contract_and_function_allowed() {
    assert!(judge(tx(vec![call(CONTRACT, "transfer")])).is_empty());
    refused(tx(vec![call(CONTRACT, "approve")]), "function approve");
    let other = ContractId(Hash([1; 32])).to_string();
    refused(tx(vec![call(&other, "transfer")]), &format!("contract {other} is not allowed"));
}

#[test]
fn fee_bumps_are_refused_unless_enabled() {
    let inner = TransactionV1Envelope { tx: tx(vec![xlm(1)]), signatures: VecM::default() };
    let bump = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: FeeBumpTransaction {
            fee_source: MuxedAccount::Ed25519(Uint256(GROUP)),
            fee: 200,
            inner_tx: FeeBumpTransactionInnerTx::Tx(inner),
            ext: FeeBumpTransactionExt::V0,
        },
        signatures: VecM::default(),
    });
    let v = judge_env(bump, 0);
    assert!(v.iter().any(|m| m.contains("fee-bump")), "{v:?}");
}

#[test]
fn every_violation_is_reported_not_just_the_first() {
    let mut t = tx(vec![xlm(500), usdc(1_000)]);
    t.fee = 1_000_000;
    t.cond = Preconditions::None;
    assert!(judge(t).len() >= 4);
}

#[test]
fn intents_are_readable() {
    let i = Intent::from_envelope(&env(tx(vec![usdc(5), call(CONTRACT, "transfer")])));
    assert_eq!(i.operations.len(), 2);
    assert!(matches!(&i.operations[0].kind, OpKind::Payment { asset, .. } if asset == &format!("USDC:{USDC_ISSUER}")));
    assert!(
        matches!(&i.operations[1].kind, OpKind::InvokeContract { contract, function } if contract == CONTRACT && function == "transfer")
    );
}

#[test]
fn malformed_policies_are_rejected() {
    let base = include_str!("../../../examples/policy.toml");
    for (bad, why) in [
        (base.replace("\"payment\", ", "\"teleport\", "), "unknown operation"),
        (base.replace("per_transaction = \"100\"", "per_transaction = \"1.00000001\""), "too many decimals"),
        (base.replace("max_fee = 100000", "max_fee = 0"), "zero fee"),
        (format!("{base}\nsurprise = 1\n"), "unknown field"),
        (
            format!("{base}\n[[asset]]\nasset = \"native\"\nper_transaction = \"1\"\nper_day = \"1\"\n"),
            "duplicate asset",
        ),
    ] {
        assert!(Policy::from_toml(&bad).is_err(), "{why}");
    }
}

#[test]
fn amounts_round_trip() {
    assert_eq!(parse_amount("1"), Some(10_000_000));
    assert_eq!(parse_amount("0.0000001"), Some(1));
    assert_eq!(parse_amount("12.5"), Some(125_000_000));
    for bad in ["", ".5", "1.", "-1", "1e3", "1.00000001"] {
        assert_eq!(parse_amount(bad), None, "{bad:?}");
    }
    assert_eq!(format_amount(125_000_000), "12.5");
    assert_eq!(format_amount(10_000_000), "1");
}
