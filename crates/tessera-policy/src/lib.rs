//! Signing policy for Tessera signers.
//!
//! A signer decodes every transaction it is asked to sign into an [`Intent`]
//! and refuses unless its [`Policy`] approves. Policies are deny-by-default:
//! operations, assets, contracts and destinations must be listed to be used,
//! and every transaction must expire soon.
//!
//! ```
//! use tessera_policy::{Intent, Policy};
//! # use tessera_core::stellar;
//! # let envelope = stellar::decode_envelope(include_str!("../../tessera-core/tests/fixtures/payment.xdr"))?;
//! # let group = stellar::account_id(&[9; 32]);
//!
//! let policy = Policy::from_toml(include_str!("../../../examples/policy.toml"))?;
//! let decision = policy.evaluate(&Intent::from_envelope(&envelope), &group, 1_791_249_500, |_asset| 0);
//! assert!(decision.approved(), "{:?}", decision.violations);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod intent;
mod policy;

pub use intent::{Intent, Op, OpKind, TokenTransfer};
pub use policy::{Decision, OPERATIONS, Policy, PolicyError, format_amount, format_units, parse_amount, parse_units};
