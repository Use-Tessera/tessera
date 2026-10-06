//! FROST threshold Ed25519 signing for Stellar.
//!
//! A Tessera group of `n` participants controls one ordinary Stellar account.
//! Any `t` of them produce a single Ed25519 signature that Stellar accepts like
//! any other: no multisig thresholds on the account, no contract, and nothing
//! on chain reveals that more than one party signed.
//!
//! ```
//! use tessera_core::{keys, signing, stellar};
//!
//! let shares = keys::deal(2, 3)?;
//! let network = stellar::Network::from_name("testnet");
//! # let envelope = stellar::decode_envelope(include_str!("../tests/fixtures/payment.xdr"))?;
//! // Any two of the three shares sign; the result verifies as plain Ed25519.
//! let signature = signing::sign_locally(&network, &envelope, &shares[1..])?;
//! # let _ = signature;
//! # Ok::<(), tessera_core::Error>(())
//! ```
//!
//! [`signing`] implements the rounds a networked signer runs, [`protocol`] the
//! messages they exchange, and [`keys`] the encrypted share files.

pub mod auth;
pub mod dkg;
mod error;
pub mod keys;
pub mod protocol;
pub mod signing;
pub mod stellar;

pub use error::Error;
pub use frost_ed25519 as frost;
pub use stellar_xdr as xdr;
