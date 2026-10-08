//! Tessera's signing policy for JavaScript.
//!
//! [`check`] runs the same [`tessera_policy`] code a signer runs before it
//! contributes a share, so a policy can be tried against real transactions
//! and authorization entries without running a signer. [`samples`] builds
//! example inputs for a group account.
//!
//! Results are JSON strings, so the binding needs no JavaScript glue beyond
//! what wasm-bindgen generates.

use serde_json::{Value, json};
use stellar_xdr::{
    AccountId, Asset, ContractId, HostFunction, Int128Parts, InvokeContractArgs, InvokeHostFunctionOp, Limits, Memo,
    MuxedAccount, Operation, OperationBody, PaymentOp, Preconditions, PublicKey, ReadXdr, ScAddress, ScSymbol, ScVal,
    SequenceNumber, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanAuthorizedFunction,
    SorobanAuthorizedInvocation, SorobanCredentials, TimeBounds, TimePoint, Transaction, TransactionEnvelope,
    TransactionExt, TransactionV1Envelope, Uint256, VecM, WriteXdr,
};
use tessera_policy::{AuthCall, AuthIntent, Decision, Intent, OpKind, Policy, format_amount};
use wasm_bindgen::prelude::*;

/// Large enough for any real envelope, small enough that a hostile one can't exhaust memory.
const DECODE_LIMITS: Limits = Limits { depth: 500, len: 1 << 20 };

/// The Stellar asset contract for lumens on testnet, which the example policy allows.
const XLM_CONTRACT: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

/// Judges `xdr` (a base64 transaction envelope or Soroban authorization
/// entry) against `policy_toml` for the group account `account`.
///
/// `now` is the unix time to check expiry against; `latest_ledger` is the
/// network's current ledger, used for authorization entries. Daily limits
/// assume nothing has been spent yet today.
///
/// Returns `{ok, stage?, error?, kind?, intent?, violations?, spend?}`:
/// `ok` is false with a `stage` of `policy`, `account` or `xdr` when an input
/// can't be read, and otherwise `violations` lists every broken rule (empty
/// means the signer would sign).
#[wasm_bindgen]
pub fn check(policy_toml: &str, xdr: &str, account: &str, now: f64, latest_ledger: u32) -> String {
    let fail = |stage: &str, error: String| json!({ "ok": false, "stage": stage, "error": error }).to_string();
    let policy = match Policy::from_toml(policy_toml) {
        Ok(p) => p,
        Err(e) => return fail("policy", e.to_string()),
    };
    let account = account.trim();
    if account.parse::<AccountId>().is_err() {
        return fail("account", format!("{account:?} is not a Stellar account address (G…)"));
    }
    let now = if now.is_finite() && now > 0.0 { now as u64 } else { 0 };
    let xdr = xdr.trim();
    if xdr.is_empty() {
        return fail("xdr", "paste a transaction envelope or authorization entry first".into());
    }
    if let Ok(env) = TransactionEnvelope::from_xdr_base64(xdr, DECODE_LIMITS) {
        let intent = Intent::from_envelope(&env);
        let decision = policy.evaluate(&intent, account, now, |_| 0);
        return judged("transaction", describe_tx(&intent), &decision);
    }
    if let Ok(entry) = SorobanAuthorizationEntry::from_xdr_base64(xdr, DECODE_LIMITS) {
        let Some(intent) = AuthIntent::from_entry(&entry) else {
            return fail(
                "xdr",
                "this authorization entry uses source-account credentials; signers only sign address credentials"
                    .into(),
            );
        };
        let decision = policy.evaluate_auth(&intent, account, latest_ledger, |_| 0);
        return judged("authorization", describe_auth(&intent), &decision);
    }
    fail("xdr", "this is not a base64 TransactionEnvelope or SorobanAuthorizationEntry".into())
}

/// Example inputs for `account`, as `[{id, label, xdr}]`, expiring relative
/// to `now` and `latest_ledger`. Returns `{"error": …}` for a bad account.
#[wasm_bindgen]
pub fn samples(account: &str, now: f64, latest_ledger: u32) -> String {
    match build_samples(account.trim(), if now.is_finite() && now > 0.0 { now as u64 } else { 0 }, latest_ledger) {
        Ok(v) => v.to_string(),
        Err(e) => json!({ "error": e }).to_string(),
    }
}

/// The binding's version.
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

fn judged(kind: &str, intent: Value, d: &Decision) -> String {
    let spend: Vec<Value> =
        d.spend.iter().map(|(asset, v)| json!({ "asset": label(asset), "amount": format_amount(*v) })).collect();
    json!({ "ok": true, "kind": kind, "intent": intent, "violations": d.violations, "spend": spend }).to_string()
}

fn label(asset: &str) -> String {
    match asset {
        "native" => "XLM".to_owned(),
        a => a.split(':').next().unwrap_or(a).to_owned(),
    }
}

fn describe_tx(i: &Intent) -> Value {
    let ops: Vec<Value> = i
        .operations
        .iter()
        .map(|op| {
            let what = match &op.kind {
                OpKind::Payment { destination, asset, amount } => {
                    format!("send {} {} to {destination}", format_amount(i128::from(*amount)), label(asset))
                }
                OpKind::CreateAccount { destination, starting_balance } => {
                    format!("create {destination} with {} XLM", format_amount(i128::from(*starting_balance)))
                }
                OpKind::InvokeContract { contract, function, transfer } => match transfer {
                    Some(t) => format!(
                        "call {function} on {contract}: {} units from {} to {}",
                        format_amount(t.amount),
                        t.from,
                        t.to
                    ),
                    None => format!("call {function} on {contract}"),
                },
                OpKind::Other(name) => name.replace('_', " "),
            };
            json!({ "name": op.kind.name(), "what": what, "source": op.source })
        })
        .collect();
    json!({
        "source": i.source,
        "fee": i.fee,
        "max_time": i.max_time,
        "fee_bump": i.fee_bump,
        "operations": ops,
    })
}

fn describe_auth(i: &AuthIntent) -> Value {
    let calls: Vec<Value> = i
        .calls
        .iter()
        .map(|c| match c {
            AuthCall::CreateContract => json!({ "name": "create_contract", "what": "deploy a contract" }),
            AuthCall::Contract { contract, function, transfer } => {
                let what = match transfer {
                    Some(t) => format!(
                        "call {function} on {contract}: {} units from {} to {}",
                        format_amount(t.amount),
                        t.from,
                        t.to
                    ),
                    None => format!("call {function} on {contract}"),
                };
                json!({ "name": "invoke_contract", "what": what })
            }
        })
        .collect();
    json!({ "address": i.address, "expiration_ledger": i.expiration_ledger, "calls": calls })
}

fn build_samples(account: &str, now: u64, latest_ledger: u32) -> Result<Value, String> {
    let group: AccountId = account.parse().map_err(|_| format!("{account:?} is not a Stellar account address (G…)"))?;
    let AccountId(PublicKey::PublicKeyTypeEd25519(key)) = &group;
    let source = MuxedAccount::Ed25519(key.clone());
    let payee = MuxedAccount::Ed25519(Uint256([7; 32]));
    let soon = Preconditions::Time(TimeBounds { min_time: TimePoint(0), max_time: TimePoint(now + 300) });
    let xlm = |units: i64| units * 10_000_000;
    let pay = |units: i64| {
        OperationBody::Payment(PaymentOp { destination: payee.clone(), asset: Asset::Native, amount: xlm(units) })
    };
    let addr = |m: &MuxedAccount| match m {
        MuxedAccount::Ed25519(k) => {
            ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(k.clone()))))
        }
        MuxedAccount::MuxedEd25519(m) => {
            ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(m.ed25519.clone()))))
        }
    };
    let transfer_args = |units: i64| -> Result<InvokeContractArgs, String> {
        let contract: ContractId = XLM_CONTRACT.parse().map_err(|_| "bad contract id".to_owned())?;
        Ok(InvokeContractArgs {
            contract_address: ScAddress::Contract(contract),
            function_name: ScSymbol("transfer".try_into().map_err(|_| "bad symbol".to_owned())?),
            args: vec![addr(&source), addr(&payee), ScVal::I128(Int128Parts { hi: 0, lo: xlm(units) as u64 })]
                .try_into()
                .map_err(|_| "too many arguments".to_owned())?,
        })
    };
    let tx = |cond: Preconditions, ops: Vec<OperationBody>| -> Result<String, String> {
        let operations = ops
            .into_iter()
            .map(|body| Operation { source_account: None, body })
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "too many operations".to_owned())?;
        let t = Transaction {
            source_account: source.clone(),
            fee: 100,
            seq_num: SequenceNumber(1),
            cond,
            memo: Memo::None,
            operations,
            ext: TransactionExt::V0,
        };
        TransactionEnvelope::Tx(TransactionV1Envelope { tx: t, signatures: VecM::default() })
            .to_xdr_base64(Limits::none())
            .map_err(|e| e.to_string())
    };
    let invoke = OperationBody::InvokeHostFunction(InvokeHostFunctionOp {
        host_function: HostFunction::InvokeContract(transfer_args(5)?),
        auth: VecM::default(),
    });
    let entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(group.clone()),
            nonce: 1,
            signature_expiration_ledger: latest_ledger.saturating_add(60),
            signature: ScVal::Void,
        }),
        root_invocation: SorobanAuthorizedInvocation {
            function: SorobanAuthorizedFunction::ContractFn(transfer_args(5)?),
            sub_invocations: VecM::default(),
        },
    }
    .to_xdr_base64(Limits::none())
    .map_err(|e| e.to_string())?;
    Ok(json!([
        { "id": "payment", "label": "Pay 25 XLM", "xdr": tx(soon.clone(), vec![pay(25)])? },
        { "id": "too-much", "label": "Pay 150 XLM", "xdr": tx(soon.clone(), vec![pay(150)])? },
        { "id": "no-expiry", "label": "No expiry", "xdr": tx(Preconditions::None, vec![pay(10)])? },
        { "id": "merge", "label": "Merge the account", "xdr": tx(soon.clone(), vec![OperationBody::AccountMerge(payee.clone())])? },
        { "id": "contract", "label": "Token transfer", "xdr": tx(soon, vec![invoke])? },
        { "id": "auth", "label": "Authorization entry", "xdr": entry },
    ]))
}
