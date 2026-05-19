//! `qfc-enclave` — TEE boundary abstraction, signer implementations, and HD
//! derivation. See `docs/server-wallet-rfc.md` §2.1, §2.3.
//!
//! Status:
//! - M1: `Signer` trait + ed25519 / secp256k1 / secp256k1-recoverable impls;
//!   BIP32 (secp256k1) and SLIP-0010 (ed25519) HD derivation; BIP39 mnemonic
//!   helpers. The `Enclave` trait + `MockEnclave` land in P4.
//! - M3: `NitroEnclave` backend.
//!
//! No cryptographic primitive in this crate has FFI surface — every signer is
//! pure Rust (see RFC §1.5).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod derivation;
pub mod error;
pub mod signer;
pub mod signers;

pub use derivation::{derive_classical, mnemonic_to_seed, ClassicalDerivation};
pub use error::{DerivationError, SignerError};
pub use signer::{dispatch_signer, signer_for_scheme, Signer};
pub use signers::{Ed25519Signer, Secp256k1RecoverableSigner, Secp256k1Signer};
