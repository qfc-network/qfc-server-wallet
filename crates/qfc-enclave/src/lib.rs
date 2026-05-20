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
// The M3 modules (`hybrid_verifier`, `verify_attestation`, `enclaves::nitro`)
// reference TLA-shape identifiers (PCR0, COSE_Sign1, AWS_NITRO_…) in docs
// + use byte-array fields whose CBOR/ASN.1 layouts the compiler can't tell
// from prose. Quoting every identifier hurts readability more than it
// helps; the lint stays off crate-wide so docs read like docs.
#![allow(clippy::doc_markdown)]
// M3 helper functions on `HybridVerifier`/`PcrConstraint` take `&self`
// even when they're effectively associated — keeping the call shape
// uniform across the verifier surface is worth more than tightening
// the method signature.
#![allow(clippy::unused_self)]
// `request_id` / `signing_request_id` / `signed_request_id` are similar
// names but their data flow is what makes the tests readable. Renaming
// to `r1`/`r2` would obscure intent.
#![allow(clippy::similar_names)]
// The async surface is a trait requirement (Enclave::attest is async);
// the stub branch is genuinely synchronous but must keep the signature.
#![allow(clippy::unused_async)]
// `NitroWireResponse::Error { message }` is a narrow variant; sharing
// the largest variant pays no penalty in practice (one response per
// vsock round-trip).
#![allow(clippy::large_enum_variant)]
// Exclusive ranges are the natural fit for "test boundary + 1" cases.
#![allow(clippy::range_plus_one)]
// `Vec::fill` is fine but tests use the explicit loop for clarity.
#![allow(clippy::manual_slice_fill)]

pub mod attestation;
pub mod derivation;
pub mod enclave;
pub mod enclaves;
pub mod error;
pub mod hybrid_verifier;
pub mod signer;
pub mod signers;
pub mod verify_attestation;

pub use attestation::{AttestationDoc, AttestationPayload, MockAttestationKey};
pub use derivation::{derive_classical, mnemonic_to_seed, ClassicalDerivation};
pub use enclave::{
    Enclave, EnclaveApproval, EnclaveApprovalDecision, EnclaveError, EnclaveSignRequest,
    EnclaveSignResponse, GenerateWalletRequest, GenerateWalletResponse, SigningContext,
};
pub use enclaves::{MockEnclave, NitroEnclave};
pub use error::{DerivationError, SignerError};
pub use hybrid_verifier::{
    HybridVerifier, HybridVerifyError, WalletCeilings, MAX_APPROVALS, MAX_DECISION_AGE_SECS,
};
pub use signer::{dispatch_signer, signer_for_scheme, Signer};
pub use signers::{Ed25519Signer, Secp256k1RecoverableSigner, Secp256k1Signer};
pub use verify_attestation::{
    verify_attestation, verify_mock_attestation, AttestationVerifyError, NitroAttestationDoc,
    PcrConstraint, VerifiedAttestation,
};
