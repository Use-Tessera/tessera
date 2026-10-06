//! Judging Soroban authorization entries.

#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing, missing_docs)]

use tessera_core::stellar::account_id;
use tessera_core::xdr::*;
use tessera_policy::{AuthCall, AuthIntent, Policy};

const GROUP: [u8; 32] = [9; 32];
const LEDGER: u32 = 5_000_000;
const XLM: &str = "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC";

fn policy(extra: &str) -> Policy {
    Policy::from_toml(&format!("{}\n{extra}", include_str!("../../../examples/policy.toml"))).unwrap()
}

fn with_auth() -> Policy {
    policy(&format!(
        "[auth]\nmax_validity_ledgers = 120\n[[token]]\ncontract = \"{XLM}\"\nper_transaction = \"100\"\nper_day = \"500\"\n"
    ))
}

fn account(k: [u8; 32]) -> ScVal {
    ScVal::Address(ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(k)))))
}

fn invoke(
    contract: &str,
    function: &str,
    args: Vec<ScVal>,
    subs: Vec<SorobanAuthorizedInvocation>,
) -> SorobanAuthorizedInvocation {
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: ScAddress::Contract(contract.parse().unwrap()),
            function_name: ScSymbol(function.as_bytes().to_vec().try_into().unwrap()),
            args: args.try_into().unwrap(),
        }),
        sub_invocations: subs.try_into().unwrap(),
    }
}

fn transfer(from: [u8; 32], xlm: i64) -> SorobanAuthorizedInvocation {
    invoke(
        XLM,
        "transfer",
        vec![account(from), account([7; 32]), ScVal::I128(Int128Parts { hi: 0, lo: (xlm * 10_000_000) as u64 })],
        vec![],
    )
}

fn entry(address: [u8; 32], expires: u32, root: SorobanAuthorizedInvocation) -> SorobanAuthorizationEntry {
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(address)))),
            nonce: 1,
            signature_expiration_ledger: expires,
            signature: ScVal::Void,
        }),
        root_invocation: root,
    }
}

fn judge(p: &Policy, e: &SorobanAuthorizationEntry, spent: i128) -> Vec<String> {
    p.evaluate_auth(&AuthIntent::from_entry(e).unwrap(), &account_id(&GROUP), LEDGER, |_| spent).violations
}

#[test]
fn an_x402_style_token_payment_is_approved() {
    let d = with_auth().evaluate_auth(
        &AuthIntent::from_entry(&entry(GROUP, LEDGER + 60, transfer(GROUP, 5))).unwrap(),
        &account_id(&GROUP),
        LEDGER,
        |_| 0,
    );
    assert!(d.approved(), "{:?}", d.violations);
    assert_eq!(d.spend.get(XLM), Some(&50_000_000));
}

#[test]
fn auth_signing_is_off_unless_the_policy_enables_it() {
    let v = judge(&policy(""), &entry(GROUP, LEDGER + 60, transfer(GROUP, 1)), 0);
    assert!(v[0].contains("does not allow signing authorization entries"), "{v:?}");
}

#[test]
fn expiry_is_bounded() {
    let p = with_auth();
    assert!(judge(&p, &entry(GROUP, LEDGER, transfer(GROUP, 1)), 0).iter().any(|m| m.contains("already expired")));
    assert!(
        judge(&p, &entry(GROUP, LEDGER + 121, transfer(GROUP, 1)), 0)
            .iter()
            .any(|m| m.contains("max_validity_ledgers 120"))
    );
}

#[test]
fn only_the_groups_own_authorization_is_signed() {
    assert!(
        judge(&with_auth(), &entry([3; 32], LEDGER + 10, transfer([3; 32], 1)), 0)
            .iter()
            .any(|m| m.contains("not the group account"))
    );
}

#[test]
fn limits_apply_to_authorized_transfers() {
    let p = with_auth();
    assert!(
        judge(&p, &entry(GROUP, LEDGER + 10, transfer(GROUP, 101)), 0).iter().any(|m| m.contains("per_transaction"))
    );
    assert!(
        judge(&p, &entry(GROUP, LEDGER + 10, transfer(GROUP, 50)), 460 * 10_000_000)
            .iter()
            .any(|m| m.contains("per_day"))
    );
}

#[test]
fn forbidden_sub_invocations_are_caught() {
    let other = ContractId(Hash([1; 32])).to_string();
    // An allowed outer call that tries to smuggle in a call to an unlisted contract.
    let root = invoke(
        XLM,
        "transfer",
        vec![account(GROUP), account([7; 32]), ScVal::I128(Int128Parts { hi: 0, lo: 1 })],
        vec![invoke(&other, "drain", vec![], vec![])],
    );
    let v = judge(&with_auth(), &entry(GROUP, LEDGER + 10, root), 0);
    assert!(v.iter().any(|m| m.contains("call 1") && m.contains("is not allowed")), "{v:?}");
}

#[test]
fn the_whole_tree_is_visible() {
    let root = invoke(XLM, "transfer", vec![], vec![transfer(GROUP, 1), transfer(GROUP, 2)]);
    let i = AuthIntent::from_entry(&entry(GROUP, LEDGER + 10, root)).unwrap();
    assert_eq!(i.calls.len(), 3);
    assert!(matches!(&i.calls[2], AuthCall::Contract { transfer: Some(t), .. } if t.amount == 20_000_000));
}
