//! A transaction, reduced to what a policy needs to judge it.

use stellar_xdr::{
    AccountId, Asset, FeeBumpTransactionInnerTx, HostFunction, MuxedAccount, Operation, OperationBody, Preconditions,
    PublicKey, ScAddress, ScVal, SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation,
    SorobanCredentials, Transaction, TransactionEnvelope, TransactionV0, Uint256,
};

/// Everything a policy looks at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// Source account of the (inner) transaction, `G…`.
    pub source: String,
    /// Maximum total fee the envelope can charge, in stroops.
    pub fee: i64,
    /// Latest close time the transaction is valid for, if bounded.
    pub max_time: Option<u64>,
    /// True for fee-bump envelopes.
    pub fee_bump: bool,
    /// Operations, in order.
    pub operations: Vec<Op>,
}

/// One operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Op {
    /// Operation-level source account, if it differs from the transaction's.
    pub source: Option<String>,
    /// What the operation does.
    pub kind: OpKind,
}

/// The operations policies understand. Everything else is [`OpKind::Other`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpKind {
    /// `payment`.
    Payment {
        /// Destination account (`G…`; muxed accounts resolve to their base account).
        destination: String,
        /// `native` or `CODE:ISSUER`.
        asset: String,
        /// Amount in stroops.
        amount: i64,
    },
    /// `create_account`, which spends native lumens.
    CreateAccount {
        /// New account.
        destination: String,
        /// Starting balance in stroops.
        starting_balance: i64,
    },
    /// `invoke_host_function` calling a contract.
    InvokeContract {
        /// Contract address (`C…`).
        contract: String,
        /// Function name.
        function: String,
        /// Decoded arguments when the call looks like SEP-41 `transfer(from, to, amount)`.
        transfer: Option<TokenTransfer>,
    },
    /// Any other operation, by its snake_case name (`set_options`, `account_merge`, …).
    Other(String),
}

/// A SEP-41 `transfer(from: Address, to: Address, amount: i128)` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenTransfer {
    /// Address the tokens leave.
    pub from: String,
    /// Address the tokens go to.
    pub to: String,
    /// Amount in the token's smallest unit.
    pub amount: i128,
}

impl OpKind {
    /// The operation name used in policy files.
    pub fn name(&self) -> &str {
        match self {
            OpKind::Payment { .. } => "payment",
            OpKind::CreateAccount { .. } => "create_account",
            OpKind::InvokeContract { .. } => "invoke_contract",
            OpKind::Other(n) => n,
        }
    }
}

impl Intent {
    /// Extracts the intent of an envelope.
    pub fn from_envelope(env: &TransactionEnvelope) -> Self {
        match env {
            TransactionEnvelope::TxV0(e) => Self::from_v0(&e.tx, false, i64::from(e.tx.fee)),
            TransactionEnvelope::Tx(e) => Self::from_tx(&e.tx, false, i64::from(e.tx.fee)),
            TransactionEnvelope::TxFeeBump(e) => {
                let FeeBumpTransactionInnerTx::Tx(inner) = &e.tx.inner_tx;
                Self::from_tx(&inner.tx, true, e.tx.fee)
            }
        }
    }

    fn from_tx(tx: &Transaction, fee_bump: bool, fee: i64) -> Self {
        let source = muxed(&tx.source_account);
        Self {
            fee,
            max_time: max_time(&tx.cond),
            fee_bump,
            operations: tx.operations.iter().map(|o| op(o, &source)).collect(),
            source,
        }
    }

    fn from_v0(tx: &TransactionV0, fee_bump: bool, fee: i64) -> Self {
        let source = account(&tx.source_account_ed25519);
        let max_time = tx.time_bounds.as_ref().and_then(|t| (t.max_time.0 != 0).then_some(t.max_time.0));
        Self { fee, max_time, fee_bump, operations: tx.operations.iter().map(|o| op(o, &source)).collect(), source }
    }
}

fn account(key: &Uint256) -> String {
    PublicKey::PublicKeyTypeEd25519(key.clone()).to_string()
}

fn muxed(m: &MuxedAccount) -> String {
    match m {
        MuxedAccount::Ed25519(k) => account(k),
        MuxedAccount::MuxedEd25519(m) => account(&m.ed25519),
    }
}

fn account_id(a: &AccountId) -> String {
    let AccountId(PublicKey::PublicKeyTypeEd25519(k)) = a;
    account(k)
}

fn asset(a: &Asset) -> String {
    let code = |b: &[u8]| String::from_utf8_lossy(b).trim_end_matches('\0').to_owned();
    match a {
        Asset::Native => "native".to_owned(),
        Asset::CreditAlphanum4(x) => format!("{}:{}", code(&x.asset_code.0), account_id(&x.issuer)),
        Asset::CreditAlphanum12(x) => format!("{}:{}", code(&x.asset_code.0), account_id(&x.issuer)),
    }
}

fn max_time(c: &Preconditions) -> Option<u64> {
    let tb = match c {
        Preconditions::None => None,
        Preconditions::Time(t) => Some(t),
        Preconditions::V2(v) => v.time_bounds.as_ref(),
    };
    tb.and_then(|t| (t.max_time.0 != 0).then_some(t.max_time.0))
}

fn op(o: &Operation, tx_source: &str) -> Op {
    let source = o.source_account.as_ref().map(muxed).filter(|s| s != tx_source);
    let kind = match &o.body {
        OperationBody::Payment(p) => {
            OpKind::Payment { destination: muxed(&p.destination), asset: asset(&p.asset), amount: p.amount }
        }
        OperationBody::CreateAccount(c) => {
            OpKind::CreateAccount { destination: account_id(&c.destination), starting_balance: c.starting_balance }
        }
        OperationBody::InvokeHostFunction(i) => match &i.host_function {
            HostFunction::InvokeContract(args) => match &args.contract_address {
                ScAddress::Contract(id) => {
                    let function = String::from_utf8_lossy(args.function_name.0.as_slice()).into_owned();
                    let transfer = if function == "transfer" { token_transfer(&args.args) } else { None };
                    OpKind::InvokeContract { contract: id.to_string(), function, transfer }
                }
                _ => OpKind::Other("invoke_host_function".to_owned()),
            },
            other => OpKind::Other(snake(other.name())),
        },
        body => OpKind::Other(snake(body.name())),
    };
    Op { source, kind }
}

/// What a Soroban authorization entry would let a contract do on the group's behalf.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthIntent {
    /// The authorizing address (`G…` or `C…`).
    pub address: String,
    /// Last ledger the signature is valid for.
    pub expiration_ledger: u32,
    /// Every authorized call in the invocation tree, depth first.
    pub calls: Vec<AuthCall>,
}

/// One node of an authorization entry's invocation tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthCall {
    /// A contract function call.
    Contract {
        /// Contract address.
        contract: String,
        /// Function name.
        function: String,
        /// Decoded SEP-41 transfer arguments, if it is one.
        transfer: Option<TokenTransfer>,
    },
    /// Deploying a contract.
    CreateContract,
}

impl AuthIntent {
    /// Extracts the intent of an entry with address credentials; `None` otherwise.
    pub fn from_entry(entry: &SorobanAuthorizationEntry) -> Option<Self> {
        let SorobanCredentials::Address(creds) = &entry.credentials else { return None };
        let address = match &creds.address {
            ScAddress::Account(a) => account_id(a),
            ScAddress::Contract(c) => c.to_string(),
            _ => return None,
        };
        let mut calls = Vec::new();
        walk(&entry.root_invocation, &mut calls);
        Some(Self { address, expiration_ledger: creds.signature_expiration_ledger, calls })
    }
}

fn walk(inv: &SorobanAuthorizedInvocation, out: &mut Vec<AuthCall>) {
    out.push(match &inv.function {
        SorobanAuthorizedFunction::ContractFn(args) => match &args.contract_address {
            ScAddress::Contract(id) => {
                let function = String::from_utf8_lossy(args.function_name.0.as_slice()).into_owned();
                let transfer = if function == "transfer" { token_transfer(&args.args) } else { None };
                AuthCall::Contract { contract: id.to_string(), function, transfer }
            }
            other => AuthCall::Contract { contract: format!("{other:?}"), function: String::new(), transfer: None },
        },
        _ => AuthCall::CreateContract,
    });
    for sub in inv.sub_invocations.iter() {
        walk(sub, out);
    }
}

fn address(v: &ScVal) -> Option<String> {
    match v {
        ScVal::Address(ScAddress::Account(a)) => Some(account_id(a)),
        ScVal::Address(ScAddress::Contract(c)) => Some(c.to_string()),
        _ => None,
    }
}

fn token_transfer(args: &[ScVal]) -> Option<TokenTransfer> {
    let [from, to, ScVal::I128(parts)] = args else { return None };
    let amount = (i128::from(parts.hi) << 64) | i128::from(parts.lo);
    Some(TokenTransfer { from: address(from)?, to: address(to)?, amount })
}

fn snake(camel: &str) -> String {
    let mut out = String::with_capacity(camel.len().saturating_add(4));
    for (i, ch) in camel.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}
