//! `qfc-enclave` — TEE boundary abstraction, signer implementations, HD
//! derivation, and (M1) an in-process `MockEnclave`. See
//! `docs/server-wallet-rfc.md` §2.1, §2.3, §3.4.
//!
//! Status:
//! - M1: `Signer` trait + ed25519 / secp256k1 / secp256k1-recoverable impls
//!   (P2); BIP32 / SLIP-0010 HD derivation (P2); `Enclave` trait +
//!   `MockEnclave` + `AttestationDoc` (P4).
//! - M3: `NitroEnclave` backend.
//!
//! No cryptographic primitive in this crate has FFI surface — every signer
//! and every derivation impl is pure Rust (see RFC §1.5).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod attestation;
pub mod derivation;
pub mod enclave;
pub mod enclaves;
pub mod error;
pub mod signer;
pub mod signers;

pub use attestation::{AttestationDoc, AttestationPayload, MockAttestationKey};
pub use derivation::{derive_classical, mnemonic_to_seed, ClassicalDerivation};
pub use enclave::{
    Enclave, EnclaveError, EnclaveSignRequest, EnclaveSignResponse, GenerateWalletRequest,
    GenerateWalletResponse, SigningContext,
};
pub use enclaves::MockEnclave;
pub use error::{DerivationError, SignerError};
pub use signer::{dispatch_signer, signer_for_scheme, Signer};
pub use signers::{Ed25519Signer, Secp256k1RecoverableSigner, Secp256k1Signer};
