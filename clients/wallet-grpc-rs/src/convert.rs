//! User-facing types + small conversions between them and the
//! `tonic`-generated proto structs.
//!
//! We deliberately keep this layer thin. The proto types under `proto`
//! are already perfectly usable; ergonomically we just want:
//!
//! 1. Builder-style request *param* types where the proto's all-public
//!    struct field layout is too easy to misuse (e.g. `CreateWalletParams`
//!    accepts a `SigningScheme` enum instead of a raw `i32`).
//! 2. A `Wallet` view type that hides the proto's `Option<WalletView>`
//!    envelope on the success path.
//! 3. Re-exports of the common enums under nicer paths so callers don't
//!    have to type `qfc_wallet_grpc::proto::SigningScheme`.
//!
//! Everything else (`SigningPayload`, `ApproverIdentity`, `Requester`,
//! `AuditEventView`, …) is re-exported verbatim from `proto` — the
//! proto-generated types are public enums and structs and already have
//! the right shape. See `docs/clients-decisions.md` D57 for the
//! discussion of why we don't pull in `qfc-wallet-types`.

use crate::error::SdkError;
use crate::proto;

// ----------------------------------------------------------------------------
// Re-exports for ergonomics.
// ----------------------------------------------------------------------------

pub use proto::approver_identity;
pub use proto::requester;
pub use proto::signing_payload;
pub use proto::{
    ApprovalDecision, ApprovalView, ApproverIdentity, ApproverSetView, ApproverStatus,
    ApproverView, AuditEventView, AuditKind, HashAlg, Requester, SigningContext, SigningPayload,
    SigningScheme, VmType, WalletStatus, WalletView,
};

// ----------------------------------------------------------------------------
// Param + view types (ergonomic wrappers).
// ----------------------------------------------------------------------------

/// Parameters for `WalletClient::create_wallet`.
///
/// All fields are strongly typed (no raw `i32` enum slots). `policy_id`
/// is `Option<String>` — `None` lets the server allocate a fresh ULID
/// (the proto's empty-string sentinel).
#[derive(Clone, Debug)]
pub struct CreateWalletParams {
    /// Curve to use for the master key.
    pub scheme: SigningScheme,
    /// `M` of M-of-N quorum.
    pub threshold: u32,
    /// `N` total approvers / shares.
    pub total: u32,
    /// Human-readable label.
    pub display_name: String,
    /// Tenant identifier — opaque to the wallet.
    pub owner_id: String,
    /// Optional pre-allocated policy ULID; `None` = server allocates one.
    pub policy_id: Option<String>,
}

impl From<CreateWalletParams> for proto::CreateWalletRequest {
    fn from(p: CreateWalletParams) -> Self {
        Self {
            scheme: p.scheme as i32,
            threshold: p.threshold,
            total: p.total,
            display_name: p.display_name,
            owner_id: p.owner_id,
            policy_id: p.policy_id.unwrap_or_default(),
        }
    }
}

/// Parameters for `WalletClient::sign`.
#[derive(Clone, Debug)]
pub struct SignParams {
    /// Wallet ULID.
    pub wallet_id: String,
    /// What is being signed.
    pub payload: SigningPayload,
    /// Caller identity for the policy + audit chain.
    pub requester: Requester,
    /// Empty string = no BIP32 derivation (required for PQ schemes).
    pub hd_path: String,
    /// Pre-sign hash transformation.
    pub hash_alg: HashAlg,
    /// Optional signing context.
    pub context: Option<SigningContext>,
}

impl From<SignParams> for proto::SignRequest {
    fn from(p: SignParams) -> Self {
        Self {
            wallet_id: p.wallet_id,
            payload: Some(p.payload),
            requester: Some(p.requester),
            hd_path: p.hd_path,
            hash_alg: p.hash_alg as i32,
            context: p.context,
        }
    }
}

/// The signed output. Mirror of `proto::SignResponse` with strongly-named
/// fields. Attestation JSON is left as a string so callers can pick their
/// own JSON library to decode it.
#[derive(Clone, Debug)]
pub struct Signed {
    /// Raw signature bytes (curve-dependent length).
    pub signature: Vec<u8>,
    /// Raw public key bytes the signature was produced under.
    pub public_key: Vec<u8>,
    /// JSON-encoded attestation document (UTF-8).
    pub attestation_json: String,
}

impl From<proto::SignResponse> for Signed {
    fn from(r: proto::SignResponse) -> Self {
        Self {
            signature: r.signature,
            public_key: r.public_key,
            attestation_json: r.attestation_json,
        }
    }
}

/// Parameters for `ApproverClient::register_approver`.
#[derive(Clone, Debug)]
pub struct RegisterApproverParams {
    /// Identity payload (chain / external / hardware / nested wallet).
    pub identity: ApproverIdentity,
    /// Human-readable label.
    pub label: String,
    /// Tenant identifier — opaque to the wallet.
    pub owner_id: String,
    /// Optional webhook URL. `None` = no webhook.
    pub webhook_url: Option<String>,
}

impl From<RegisterApproverParams> for proto::RegisterApproverRequest {
    fn from(p: RegisterApproverParams) -> Self {
        Self {
            identity: Some(p.identity),
            label: p.label,
            owner_id: p.owner_id,
            webhook_url: p.webhook_url.unwrap_or_default(),
        }
    }
}

/// Parameters for `ApproverClient::create_approver_set`.
#[derive(Clone, Debug)]
pub struct CreateApproverSetParams {
    /// Human-readable label.
    pub name: String,
    /// Tenant identifier.
    pub owner_id: String,
    /// Approver ULIDs that make up the set.
    pub members: Vec<String>,
    /// `M` of M-of-N quorum.
    pub threshold: u32,
    /// `N` total members.
    pub total: u32,
    /// Optional per-set quorum timeout. `None` = service default.
    pub quorum_timeout_secs: Option<u32>,
}

impl From<CreateApproverSetParams> for proto::CreateApproverSetRequest {
    fn from(p: CreateApproverSetParams) -> Self {
        Self {
            name: p.name,
            owner_id: p.owner_id,
            members: p.members,
            threshold: p.threshold,
            total: p.total,
            quorum_timeout_secs: p.quorum_timeout_secs.unwrap_or(0),
        }
    }
}

/// Parameters for `ApproverClient::submit_approval`.
#[derive(Clone, Debug)]
pub struct SubmitApprovalParams {
    /// Original signing-request ULID.
    pub request_id: String,
    /// Registered approver ULID submitting the decision.
    pub approver_id: String,
    /// Per-approval ULID (caller allocates).
    pub approval_id: String,
    /// `Approve` / `Reject`.
    pub decision: ApprovalDecision,
    /// Raw signature over the canonical preimage (see
    /// `qfc_quorum::SignedApproval::signing_preimage`).
    pub signature: Vec<u8>,
    /// Unix-millisecond timestamp this approval was signed at.
    pub timestamp_unix_ms: i64,
    /// 32-byte SHA-256 message digest this approval binds to.
    pub message_hash: Vec<u8>,
    /// Redundant cross-check against the registered identity.
    pub identity: ApproverIdentity,
}

impl SubmitApprovalParams {
    /// Validate length-bounded fields client-side before sending. Lets
    /// callers fail fast on a 31-byte digest rather than discover it via
    /// `InvalidArgument` after a round trip.
    pub fn validate(&self) -> Result<(), SdkError> {
        if self.message_hash.len() != 32 {
            return Err(SdkError::BadInput(format!(
                "message_hash must be exactly 32 bytes (got {})",
                self.message_hash.len()
            )));
        }
        if self.signature.is_empty() {
            return Err(SdkError::BadInput("signature must not be empty".into()));
        }
        Ok(())
    }
}

impl From<SubmitApprovalParams> for proto::SubmitApprovalRequest {
    fn from(p: SubmitApprovalParams) -> Self {
        Self {
            request_id: p.request_id,
            approver_id: p.approver_id,
            approval_id: p.approval_id,
            decision: p.decision as i32,
            signature: p.signature,
            timestamp_unix_ms: p.timestamp_unix_ms,
            message_hash: p.message_hash,
            identity: Some(p.identity),
        }
    }
}

/// Parameters for `WalletClient::get_audit_events`.
#[derive(Clone, Debug, Default)]
pub struct AuditEventsQuery {
    /// If `Some`, only return events whose `wallet_id` matches.
    pub wallet_id: Option<String>,
    /// Default 100, cap 1000 (server-enforced).
    pub limit: Option<u32>,
}

impl From<AuditEventsQuery> for proto::GetAuditEventsRequest {
    fn from(q: AuditEventsQuery) -> Self {
        Self {
            wallet_id: q.wallet_id.unwrap_or_default(),
            limit: q.limit.unwrap_or(0),
        }
    }
}

// ----------------------------------------------------------------------------
// Helpers that unwrap the proto's `Option<*View>` envelope.
// ----------------------------------------------------------------------------

/// Unwrap a proto `Option<T>` envelope on a successful response.
///
/// The server always returns `Some(...)` on the success path; a `None`
/// here is a server protocol violation, surfaced as `Internal`.
pub(crate) fn require<T>(field: &'static str, opt: Option<T>) -> Result<T, SdkError> {
    opt.ok_or_else(|| {
        SdkError::Internal(format!("server returned None for required field: {field}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_wallet_params_round_trip() {
        let p = CreateWalletParams {
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            display_name: "demo".into(),
            owner_id: "tenant-a".into(),
            policy_id: None,
        };
        let r: proto::CreateWalletRequest = p.into();
        assert_eq!(r.scheme, SigningScheme::Ed25519 as i32);
        assert_eq!(r.threshold, 2);
        assert_eq!(r.policy_id, ""); // None -> empty
    }

    #[test]
    fn submit_approval_validate_rejects_short_hash() {
        let p = SubmitApprovalParams {
            request_id: "x".into(),
            approver_id: "y".into(),
            approval_id: "z".into(),
            decision: ApprovalDecision::Approve,
            signature: vec![1; 64],
            timestamp_unix_ms: 0,
            message_hash: vec![0; 31], // wrong length
            identity: ApproverIdentity { identity: None },
        };
        let err = p.validate().unwrap_err();
        assert!(matches!(err, SdkError::BadInput(_)));
    }

    #[test]
    fn submit_approval_validate_rejects_empty_sig() {
        let p = SubmitApprovalParams {
            request_id: "x".into(),
            approver_id: "y".into(),
            approval_id: "z".into(),
            decision: ApprovalDecision::Approve,
            signature: vec![],
            timestamp_unix_ms: 0,
            message_hash: vec![0; 32],
            identity: ApproverIdentity { identity: None },
        };
        assert!(p.validate().is_err());
    }
}
