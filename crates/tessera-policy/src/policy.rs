//! Signing policy: what a signer is willing to approve.

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use crate::intent::{Intent, OpKind};

/// Operation names a policy may allow.
pub const OPERATIONS: &[&str] = &[
    "payment",
    "create_account",
    "invoke_contract",
    "create_contract",
    "create_contract_v2",
    "upload_contract_wasm",
    "path_payment_strict_receive",
    "path_payment_strict_send",
    "manage_sell_offer",
    "manage_buy_offer",
    "create_passive_sell_offer",
    "set_options",
    "change_trust",
    "allow_trust",
    "account_merge",
    "manage_data",
    "bump_sequence",
    "create_claimable_balance",
    "claim_claimable_balance",
    "begin_sponsoring_future_reserves",
    "end_sponsoring_future_reserves",
    "revoke_sponsorship",
    "clawback",
    "clawback_claimable_balance",
    "set_trust_line_flags",
    "liquidity_pool_deposit",
    "liquidity_pool_withdraw",
    "extend_footprint_ttl",
    "restore_footprint",
];

/// A policy file could not be loaded.
#[derive(Debug, Error)]
#[error("invalid policy: {0}")]
pub struct PolicyError(String);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    network: String,
    max_fee: i64,
    max_validity: u64,
    #[serde(default)]
    allow_fee_bump: bool,
    operations: Operations,
    #[serde(default, rename = "asset")]
    assets: Vec<AssetRule>,
    #[serde(default)]
    destinations: Option<Destinations>,
    #[serde(default, rename = "contract")]
    contracts: Vec<ContractRule>,
    #[serde(default, rename = "token")]
    tokens: Vec<TokenRule>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Operations {
    allow: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssetRule {
    asset: String,
    per_transaction: String,
    per_day: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Destinations {
    allow: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ContractRule {
    id: String,
    functions: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRule {
    contract: String,
    per_transaction: String,
    per_day: String,
    #[serde(default = "seven")]
    decimals: u32,
}

fn seven() -> u32 {
    7
}

#[derive(Clone, Debug)]
struct Limits {
    per_transaction: i128,
    per_day: i128,
    decimals: u32,
}

/// A parsed, validated policy.
#[derive(Clone, Debug)]
pub struct Policy {
    network: String,
    max_fee: i64,
    max_validity: u64,
    allow_fee_bump: bool,
    operations: Vec<String>,
    assets: BTreeMap<String, Limits>,
    destinations: Option<Vec<String>>,
    contracts: BTreeMap<String, Vec<String>>,
}

/// The result of judging an intent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Decision {
    /// Every rule the transaction breaks. Empty means approved.
    pub violations: Vec<String>,
    /// What the transaction spends per asset, in stroops, to record if it is signed.
    pub spend: BTreeMap<String, i128>,
}

impl Decision {
    /// True when no rule was broken.
    pub fn approved(&self) -> bool {
        self.violations.is_empty()
    }
}

/// Parses a decimal amount with up to 7 fractional digits into stroops.
pub fn parse_amount(s: &str) -> Option<i128> {
    parse_units(s, 7)
}

/// Parses a decimal amount into the smallest unit of a token with `decimals` places.
pub fn parse_units(s: &str, decimals: u32) -> Option<i128> {
    let (whole, frac) = s.split_once('.').unwrap_or((s, ""));
    let places = usize::try_from(decimals).ok()?;
    if whole.is_empty()
        || frac.len() > places
        || (s.contains('.') && frac.is_empty())
        || !whole.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let scale = 10i128.checked_pow(decimals)?;
    let whole: i128 = whole.parse().ok()?;
    let frac: i128 = if places == 0 { 0 } else { format!("{frac:0<places$}").parse().ok()? };
    whole.checked_mul(scale)?.checked_add(frac)
}

/// Formats stroops as a decimal amount.
pub fn format_amount(stroops: i128) -> String {
    format_units(stroops, 7)
}

/// Formats an amount in a token's smallest unit as a decimal.
pub fn format_units(v: i128, decimals: u32) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let a = v.unsigned_abs();
    let Some(scale) = 10u128.checked_pow(decimals) else { return v.to_string() };
    let places = usize::try_from(decimals).unwrap_or(0);
    let whole = a.checked_div(scale).unwrap_or(0);
    let frac = format!("{:0places$}", a.checked_rem(scale).unwrap_or(0));
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() { format!("{sign}{whole}") } else { format!("{sign}{whole}.{frac}") }
}

impl Policy {
    /// Parses and validates a TOML policy. See `examples/policy.toml`.
    pub fn from_toml(text: &str) -> Result<Self, PolicyError> {
        let f: File = toml::from_str(text).map_err(|e| PolicyError(e.to_string()))?;
        if f.max_fee <= 0 {
            return Err(PolicyError("max_fee must be positive".into()));
        }
        if f.max_validity == 0 {
            return Err(PolicyError("max_validity must be positive".into()));
        }
        for op in &f.operations.allow {
            if !OPERATIONS.contains(&op.as_str()) {
                return Err(PolicyError(format!("unknown operation {op:?}")));
            }
        }
        let mut assets = BTreeMap::new();
        for a in f.assets {
            let amount =
                |s: &str| parse_amount(s).ok_or_else(|| PolicyError(format!("bad amount {s:?} for {}", a.asset)));
            let limits =
                Limits { per_transaction: amount(&a.per_transaction)?, per_day: amount(&a.per_day)?, decimals: 7 };
            if assets.insert(a.asset.clone(), limits).is_some() {
                return Err(PolicyError(format!("asset {} listed twice", a.asset)));
            }
        }
        let mut contracts: BTreeMap<String, Vec<String>> =
            f.contracts.into_iter().map(|c| (c.id, c.functions)).collect();
        for t in f.tokens {
            if t.decimals > 18 {
                return Err(PolicyError(format!("token {}: decimals must be at most 18", t.contract)));
            }
            let amount = |s: &str| {
                parse_units(s, t.decimals)
                    .ok_or_else(|| PolicyError(format!("bad amount {s:?} for token {}", t.contract)))
            };
            let limits = Limits {
                per_transaction: amount(&t.per_transaction)?,
                per_day: amount(&t.per_day)?,
                decimals: t.decimals,
            };
            if assets.insert(t.contract.clone(), limits).is_some() {
                return Err(PolicyError(format!("token {} listed twice", t.contract)));
            }
            let fns = contracts.entry(t.contract).or_default();
            if !fns.iter().any(|f| f == "transfer" || f == "*") {
                fns.push("transfer".into());
            }
        }
        Ok(Self {
            network: f.network,
            max_fee: f.max_fee,
            max_validity: f.max_validity,
            allow_fee_bump: f.allow_fee_bump,
            operations: f.operations.allow,
            assets,
            destinations: f.destinations.map(|d| d.allow),
            contracts,
        })
    }

    /// The network name or passphrase the policy was written for.
    pub fn network(&self) -> &str {
        &self.network
    }

    /// Judges `intent` for the group account `account` at unix time `now`.
    ///
    /// `spent_today(asset)` returns what this signer already approved for the
    /// asset in the trailing 24 hours, in stroops.
    pub fn evaluate(&self, intent: &Intent, account: &str, now: u64, spent_today: impl Fn(&str) -> i128) -> Decision {
        let mut d = Decision::default();
        let mut deny = |msg: String| d.violations.push(msg);

        if intent.source != account {
            deny(format!("transaction source {} is not the group account", intent.source));
        }
        if intent.fee_bump && !self.allow_fee_bump {
            deny("fee-bump transactions are not allowed".into());
        }
        if intent.fee > self.max_fee {
            deny(format!("fee {} exceeds max_fee {}", intent.fee, self.max_fee));
        }
        match intent.max_time {
            None => deny("transaction has no expiry; set time bounds".into()),
            Some(t) if t < now => deny("transaction has already expired".into()),
            Some(t) if t.saturating_sub(now) > self.max_validity => deny(format!(
                "transaction is valid for {}s, more than max_validity {}s",
                t.saturating_sub(now),
                self.max_validity
            )),
            Some(_) => {}
        }

        let mut spend: BTreeMap<String, i128> = BTreeMap::new();
        for (i, op) in intent.operations.iter().enumerate() {
            let name = op.kind.name();
            if let Some(src) = &op.source {
                deny(format!("operation {i} ({name}) acts for another account ({src})"));
            }
            if !self.operations.iter().any(|o| o == name) {
                deny(format!("operation {i}: {name} is not allowed"));
                continue;
            }
            let mut pay = |deny: &mut dyn FnMut(String), asset: &str, destination: &str, amount: i128| {
                if let Some(allow) = &self.destinations
                    && !allow.iter().any(|a| a == destination)
                {
                    deny(format!("operation {i}: destination {destination} is not on the allowlist"));
                }
                if !self.assets.contains_key(asset) {
                    deny(format!("operation {i}: no limits configured for asset {asset}"));
                }
                let e = spend.entry(asset.to_owned()).or_default();
                *e = e.saturating_add(amount);
            };
            match &op.kind {
                OpKind::Payment { destination, asset, amount } => {
                    pay(&mut deny, asset, destination, i128::from(*amount))
                }
                OpKind::CreateAccount { destination, starting_balance } => {
                    pay(&mut deny, "native", destination, i128::from(*starting_balance))
                }
                OpKind::InvokeContract { contract, function, transfer } => match self.contracts.get(contract) {
                    None => deny(format!("operation {i}: contract {contract} is not allowed")),
                    Some(fns) if !fns.iter().any(|f| f == function || f == "*") => {
                        deny(format!("operation {i}: function {function} of {contract} is not allowed"))
                    }
                    Some(_) => {
                        // Token rules cap SEP-41 transfers like payments of a classic asset.
                        if let (Some(t), true) = (transfer, self.assets.contains_key(contract)) {
                            if t.from != account {
                                deny(format!(
                                    "operation {i}: transfer moves tokens from {}, not the group account",
                                    t.from
                                ));
                            }
                            if t.amount <= 0 {
                                deny(format!("operation {i}: transfer amount must be positive"));
                            }
                            pay(&mut deny, contract, &t.to, t.amount);
                        }
                    }
                },
                OpKind::Other(_) => {}
            }
        }

        for (asset, amount) in &spend {
            let Some(limits) = self.assets.get(asset) else { continue };
            let fmt = |v: i128| format_units(v, limits.decimals);
            if *amount > limits.per_transaction {
                deny(format!(
                    "spends {} {asset}, more than per_transaction {}",
                    fmt(*amount),
                    fmt(limits.per_transaction)
                ));
            }
            let total = spent_today(asset).saturating_add(*amount);
            if total > limits.per_day {
                deny(format!(
                    "would bring 24h spend of {asset} to {}, more than per_day {}",
                    fmt(total),
                    fmt(limits.per_day)
                ));
            }
        }
        d.spend = spend;
        d
    }
}
