//! The `Enclave` trait — the TEE boundary the rest of the system targets.
//!
//! See `docs/server-wallet-rfc.md` §2.1, §4.1, §4.2, §4.3.
//!
//! M1 ships the trait and an in-process `MockEnclave` (see `enclaves::mock`).
//! Real `NitroEnclave` arrives in M3.
//!
//! ## M1 simplifications vs RFC §2.1
//!
//! - `EnclaveSignRequest` does not yet carry `policy_decision` or
//!   `approvals`. P5 adds the `qfc-policy` / `qfc-quorum` types and the
//!   enclave-side hybrid invariant re-check (RFC §2.1 decision #2).
//! - Shares are `qfc_sss::ShamirShare` directly rather than the
//!   KMS-wrapped `EncryptedShare` envelope. KMS wrapping is M3 with
//!   `S3KmsShareStore`.
//!
//! The trait shape is forwards-compatible: the additions land as new
//! optional fields, not changes to the existing ones.

use async_trait::async_trait;
use qfc_policy::SignedPolicyDecision;
use qfc_sss::ShamirShare;
use qfc_wallet_types::{ApprovalId, HashAlg, HdPath, RequestId, SigningScheme, WalletId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::attestation::{AttestationDoc, AttestationError};
use crate::error::{DerivationError, SignerError};

/// Errors raised by `Enclave` implementations.
#[derive(Debug, Error)]
pub enum EnclaveError {
    /// The mock backend was constructed without the `QFC_ALLOW_MOCK_ENCLAVE`
    /// safety env var. Fail-closed by design.
    #[error("mock enclave disabled: set QFC_ALLOW_MOCK_ENCLAVE=yes-i-know to opt in (M1 only)")]
    MockNotAllowed,

    /// Number of supplied shares is less than the threshold.
    #[error("not enough shares: need {threshold}, got {provided}")]
    NotEnoughShares {
        /// Required threshold.
        threshold: u8,
        /// Number of shares actually supplied.
        provided: usize,
    },

    /// Shares disagreed on parameters or had duplicate indices.
    #[error("inconsistent shares: {0}")]
    InconsistentShares(&'static str),

    /// SSS combination failed.
    #[error("sss error: {0}")]
    Sss(#[from] qfc_sss::ShareError),

    /// HD derivation failed.
    #[error("derivation error: {0}")]
    Derivation(#[from] DerivationError),

    /// Signer rejected the input.
    #[error("signer error: {0}")]
    Signer(#[from] SignerError),

    /// Attestation issuance failed.
    #[error("attestation error: {0}")]
    Attestation(#[from] AttestationError),

    /// PQ scheme requested but not implemented yet (M5).
    #[error("scheme {0} is not implemented in this milestone")]
    SchemeNotImplemented(&'static str),

    /// Caller's request does not match an internal invariant.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),

    /// Hybrid policy verification failed (RFC §2.1). The enclave will not
    /// sign — fail-closed. See `hybrid_verifier::HybridVerifyError` for the
    /// specific reason.
    #[error("hybrid policy verification failed: {0}")]
    HybridVerification(#[from] crate::hybrid_verifier::HybridVerifyError),

    /// Functionality the backend cannot perform (e.g. real NSM attestation
    /// when the `nitro` feature is not enabled).
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Free-form signing context bound by the attestation.
///
/// `chain_id` and `vm_type` are the two cross-cutting fields the RFC names
/// explicitly. Everything else (request-time metadata that should also be
/// bound) is carried in `extra` so callers can extend without breaking
/// the trait shape.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningContext {
    /// Optional chain identifier (e.g. EVM `chainId`).
    pub chain_id: Option<u64>,
    /// Optional VM type label (e.g. `"evm"`, `"qvm"`, `"wasm"`).
    pub vm_type: Option<String>,
    /// Open extension space; the enclave canonically serializes this as
    /// JSON and includes it in `user_data` for the attestation.
    pub extra: serde_json::Value,
}

/// Decision tag on an `EnclaveApproval`. Mirrors `qfc_quorum::ApprovalDecision`
/// — kept here to avoid a cyclic dep between `qfc-enclave` and `qfc-quorum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnclaveApprovalDecision {
    /// The approver authorised the operation.
    Approve,
    /// The approver vetoed the operation.
    Reject,
}

/// Approval payload visible to the enclave-side hybrid verifier.
///
/// Mirrors `qfc_quorum::SignedApproval` field-for-field. We carry an
/// in-crate copy so `qfc-enclave` does not need to depend on `qfc-quorum`
/// (which depends on `qfc-enclave` already — see D15). The orchestrator
/// converts via the `From<qfc_quorum::SignedApproval>` impl in
/// `qfc-server-wallet`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnclaveApproval {
    /// Stable identifier for the approval action.
    pub approval_id: ApprovalId,
    /// Approver's public key — used by the hybrid verifier to recover the
    /// signer.
    #[serde(with = "serde_bytes")]
    pub approver_public_key: Vec<u8>,
    /// Approver's curve.
    pub approver_scheme: SigningScheme,
    /// Request being approved.
    pub request_id: RequestId,
    /// SHA-256 of the message the signing wallet would sign.
    pub message_hash: [u8; 32],
    /// Approve / Reject.
    pub decision: EnclaveApprovalDecision,
    /// Unix-millisecond timestamp at which the approver signed.
    pub timestamp_unix_ms: i64,
    /// Approver's signature over the canonical preimage.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Input to `Enclave::sign_in_enclave`.
pub struct EnclaveSignRequest {
    /// Identifier for this signing request. Bound into the attestation.
    pub request_id: RequestId,
    /// Wallet to sign on behalf of. Used for share/identity cross-checking.
    pub wallet_id: WalletId,
    /// Shares to reconstruct the master seed from. Must be at least
    /// `params.threshold` and consistent with each other.
    pub shares: Vec<ShamirShare>,
    /// Signing scheme.
    pub scheme: SigningScheme,
    /// Optional HD derivation path. `None` means sign with the master key
    /// directly. Required to be `None` for PQ schemes (RFC §9.1).
    pub hd_path: Option<HdPath>,
    /// Raw message bytes to sign.
    pub message: Vec<u8>,
    /// Pre-hash for the signer to apply (or `None` for ed25519).
    pub hash_alg: HashAlg,
    /// Arbitrary context to bind into the attestation.
    pub context: SigningContext,

    // ------------------------------------------------------------------
    // M3 — Hybrid policy verification (RFC §2.1 decision #2).
    //
    // `policy_decision` is `Option<_>` so M1/M2 callers still compile (the
    // orchestrator started threading the policy decision in M2 P3, but the
    // signed wrapper / enclave-side re-check is M3 new). If a backend has a
    // pinned policy-service public key, `None` is treated as "no signed
    // decision available" and the verifier fails-closed (configurable).
    //
    // `approvals` defaults to empty — pass it when the policy decision was
    // `RequireQuorum`. The hybrid verifier counts approvals and re-verifies
    // each signature against `approver_public_key`.
    // ------------------------------------------------------------------
    /// Signed policy decision authorising the operation.
    pub policy_decision: Option<SignedPolicyDecision>,
    /// Quorum approvals collected upstream (in-enclave re-verified).
    pub approvals: Vec<EnclaveApproval>,
    /// Hard ceilings projected from the wallet record. `None` means the
    /// orchestrator did not project them (M1/M2 callers); the hybrid
    /// verifier then falls back to default empty ceilings (no constraint).
    /// M3 follow-up: production callers MUST populate this.
    pub wallet_ceilings: Option<crate::hybrid_verifier::WalletCeilings>,
    /// Original `qfc_policy::SigningPayload` the orchestrator built — needed
    /// by the in-enclave hybrid verifier to re-check chain / target / value
    /// ceilings against the structured payload (the raw `message` field is
    /// the bytes the signer signs, which is *derived* from the payload but
    /// not the payload itself for VM transactions).
    pub policy_signing_payload: Option<qfc_policy::SigningPayload>,
}

/// Output of `Enclave::sign_in_enclave`.
#[derive(Debug, Clone)]
pub struct EnclaveSignResponse {
    /// The signature bytes (layout depends on scheme; see signers docs).
    pub signature: Vec<u8>,
    /// The (derived) public key associated with the signing key.
    pub public_key: Vec<u8>,
    /// Attestation binding `(request_id || message_hash || signature_hash || …)`.
    pub attestation: AttestationDoc,
}

/// Input to `Enclave::generate_wallet`.
pub struct GenerateWalletRequest {
    /// Identifier for the new wallet. The enclave does not invent this;
    /// the orchestrator assigns it so that the wallet's IDs match the
    /// rest of the system from creation onward.
    pub wallet_id: WalletId,
    /// Scheme of the master key to generate.
    pub scheme: SigningScheme,
    /// SSS threshold `M`.
    pub threshold: u8,
    /// SSS total shares `N`.
    pub total: u8,
    /// HD path used to derive the *reported* public key. For PQ schemes,
    /// must be `None`. For classical schemes, `None` derives the master
    /// (m/) pubkey; non-`None` returns the pubkey at that derivation.
    pub master_hd_path: Option<HdPath>,
}

/// Output of `Enclave::generate_wallet`.
#[derive(Debug, Clone)]
pub struct GenerateWalletResponse {
    /// Newly created Shamir shares. The caller stores them via a `ShareStore`.
    pub shares: Vec<ShamirShare>,
    /// Public key derived at `master_hd_path` (or the master key if `None`).
    pub master_public_key: Vec<u8>,
    /// Attestation binding `(wallet_id || master_public_key || share_index_set)`.
    pub attestation: AttestationDoc,
}

/// The TEE boundary the rest of the system targets.
#[async_trait]
pub trait Enclave: Send + Sync {
    /// Produce a fresh attestation document. The `nonce` is included in
    /// the attestation so callers can prove freshness across runs.
    ///
    /// # Errors
    ///
    /// Backend-specific. Mock returns `EnclaveError::Attestation` on
    /// serialization failure.
    async fn attest(&self, nonce: [u8; 32]) -> Result<AttestationDoc, EnclaveError>;

    /// Reconstruct the secret, derive (if applicable), sign, and emit an
    /// attestation binding the inputs and outputs.
    ///
    /// # Errors
    ///
    /// Per `EnclaveError`. Common cases: insufficient / inconsistent
    /// shares, scheme not implemented, signer rejection, derivation failure.
    async fn sign_in_enclave(
        &self,
        req: EnclaveSignRequest,
    ) -> Result<EnclaveSignResponse, EnclaveError>;

    /// Generate a fresh master seed inside the enclave, split it via SSS,
    /// derive the reported public key, and zeroize the seed before
    /// returning. The shares cross the boundary as `ShamirShare`; the
    /// caller is responsible for persisting them via a `ShareStore`.
    ///
    /// # Errors
    ///
    /// Per `EnclaveError`. PQ schemes return `SchemeNotImplemented`.
    async fn generate_wallet(
        &self,
        req: GenerateWalletRequest,
    ) -> Result<GenerateWalletResponse, EnclaveError>;
}
