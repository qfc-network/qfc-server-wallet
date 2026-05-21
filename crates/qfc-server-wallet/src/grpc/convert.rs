//! Domain ↔ proto conversion helpers for the gRPC surface.
//!
//! Each conversion is one-direction-at-a-time, expressed as a `From` /
//! `TryFrom` impl on the proto side. We deliberately don't reuse the HTTP
//! DTOs because:
//!
//!   1. They're hex-string-flavored. gRPC carries raw `bytes`, which would
//!      mean a string→hex→bytes detour on the gRPC side and would couple
//!      the two surfaces.
//!   2. The HTTP DTOs depend on `utoipa`. The proto types don't.
//!
//! On failure the helpers return `tonic::Status::invalid_argument` with a
//! short operator-facing hint. Domain-layer errors (`ServiceError`,
//! `RegistryError`, …) get mapped to the closest gRPC status code in
//! [`map_service_error`] / [`map_registry_error`].
//!
//! All helpers here are pub-internal — they're called from `wallet.rs` and
//! `approver.rs` and aren't part of the crate's downstream surface. The
//! `missing_docs` lint is allowed for that reason; the module-level doc
//! plus the source line itself is the contract.
#![allow(clippy::needless_pass_by_value)]
#![allow(missing_docs)]
// `tonic::Status` is intrinsically ~176 bytes (it carries a hyper
// `MetadataMap` for trailing-metadata). Boxing it would defeat the point
// of returning a Status; this is the standard pattern in tonic codebases.
#![allow(clippy::result_large_err)]

use qfc_audit::AuditEvent;
use qfc_enclave::SigningContext as EnclaveSigningContext;
use qfc_policy::{Requester, SigningPayload, VmType};
use qfc_quorum::{
    ApprovalDecision, ApproverIdentity, ApproverRecord, ApproverSet, ApproverStatus,
    HardwareApproverHandle, SignedApproval,
};
use qfc_wallet_types::{
    ApprovalId, ApproverId, ApproverSetId, HashAlg, HdPath, OwnerId, PolicyId, RequestId,
    SigningScheme, WalletId,
};
use tonic::Status;

use crate::grpc::proto;
use crate::service::ServiceError;
use crate::wallet::{WalletConfig, WalletRecord, WalletStatus};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Convenience: lift a missing-required-field into `invalid_argument`.
pub fn require_field<T>(field: &'static str, value: Option<T>) -> Result<T, Status> {
    value.ok_or_else(|| Status::invalid_argument(format!("missing required field: {field}")))
}

/// Parse a ULID string into one of our newtypes, surfacing
/// `invalid_argument` on a malformed value.
pub fn parse_ulid<T: std::str::FromStr>(field: &'static str, s: &str) -> Result<T, Status>
where
    T::Err: std::fmt::Display,
{
    s.parse::<T>()
        .map_err(|e| Status::invalid_argument(format!("invalid {field}: {e}")))
}

/// Decode a 32-byte hash from raw bytes; surface `invalid_argument` on the
/// wrong length.
pub fn require_32_bytes(field: &'static str, bytes: &[u8]) -> Result<[u8; 32], Status> {
    bytes
        .try_into()
        .map_err(|_| Status::invalid_argument(format!("{field} must be exactly 32 bytes")))
}

// ---------------------------------------------------------------------------
// Enum conversions (proto enum -> domain enum, both directions)
// ---------------------------------------------------------------------------

impl From<SigningScheme> for proto::SigningScheme {
    fn from(s: SigningScheme) -> Self {
        match s {
            SigningScheme::Ed25519 => Self::Ed25519,
            SigningScheme::Secp256k1 => Self::Secp256k1,
            SigningScheme::Secp256k1Recoverable => Self::Secp256k1Recoverable,
            SigningScheme::MlDsa44 => Self::MlDsa44,
            SigningScheme::MlDsa65 => Self::MlDsa65,
            SigningScheme::MlDsa87 => Self::MlDsa87,
        }
    }
}

impl TryFrom<proto::SigningScheme> for SigningScheme {
    type Error = Status;
    fn try_from(v: proto::SigningScheme) -> Result<Self, Self::Error> {
        Ok(match v {
            proto::SigningScheme::Unspecified => {
                return Err(Status::invalid_argument("scheme must be specified"));
            }
            proto::SigningScheme::Ed25519 => Self::Ed25519,
            proto::SigningScheme::Secp256k1 => Self::Secp256k1,
            proto::SigningScheme::Secp256k1Recoverable => Self::Secp256k1Recoverable,
            proto::SigningScheme::MlDsa44 => Self::MlDsa44,
            proto::SigningScheme::MlDsa65 => Self::MlDsa65,
            proto::SigningScheme::MlDsa87 => Self::MlDsa87,
        })
    }
}

/// Lift an `i32` (the wire representation prost uses for enums) into our
/// domain enum.
pub fn scheme_from_i32(v: i32) -> Result<SigningScheme, Status> {
    proto::SigningScheme::try_from(v)
        .map_err(|_| Status::invalid_argument(format!("unknown SigningScheme variant: {v}")))?
        .try_into()
}

impl From<HashAlg> for proto::HashAlg {
    fn from(h: HashAlg) -> Self {
        match h {
            HashAlg::None => Self::None,
            HashAlg::Sha256 => Self::Sha256,
            HashAlg::Keccak256 => Self::Keccak256,
            HashAlg::Blake3 => Self::Blake3,
        }
    }
}

impl TryFrom<proto::HashAlg> for HashAlg {
    type Error = Status;
    fn try_from(v: proto::HashAlg) -> Result<Self, Self::Error> {
        Ok(match v {
            proto::HashAlg::Unspecified => {
                return Err(Status::invalid_argument("hash_alg must be specified"));
            }
            proto::HashAlg::None => Self::None,
            proto::HashAlg::Sha256 => Self::Sha256,
            proto::HashAlg::Keccak256 => Self::Keccak256,
            proto::HashAlg::Blake3 => Self::Blake3,
        })
    }
}

pub fn hash_alg_from_i32(v: i32) -> Result<HashAlg, Status> {
    proto::HashAlg::try_from(v)
        .map_err(|_| Status::invalid_argument(format!("unknown HashAlg variant: {v}")))?
        .try_into()
}

impl TryFrom<proto::VmType> for VmType {
    type Error = Status;
    fn try_from(v: proto::VmType) -> Result<Self, Self::Error> {
        Ok(match v {
            proto::VmType::Unspecified => {
                return Err(Status::invalid_argument("vm_type must be specified"));
            }
            proto::VmType::Evm => Self::Evm,
            proto::VmType::Qvm => Self::Qvm,
            proto::VmType::Wasm => Self::Wasm,
        })
    }
}

impl From<WalletStatus> for proto::WalletStatus {
    fn from(s: WalletStatus) -> Self {
        match s {
            WalletStatus::Active => Self::Active,
            WalletStatus::Frozen => Self::Frozen,
            WalletStatus::Revoked => Self::Revoked,
        }
    }
}

impl From<ApproverStatus> for proto::ApproverStatus {
    fn from(s: ApproverStatus) -> Self {
        match s {
            ApproverStatus::Active => Self::Active,
            ApproverStatus::Revoked => Self::Revoked,
        }
    }
}

impl From<ApprovalDecision> for proto::ApprovalDecision {
    fn from(d: ApprovalDecision) -> Self {
        match d {
            ApprovalDecision::Approve => Self::Approve,
            ApprovalDecision::Reject => Self::Reject,
        }
    }
}

impl TryFrom<proto::ApprovalDecision> for ApprovalDecision {
    type Error = Status;
    fn try_from(d: proto::ApprovalDecision) -> Result<Self, Self::Error> {
        Ok(match d {
            proto::ApprovalDecision::Unspecified => {
                return Err(Status::invalid_argument("decision must be specified"));
            }
            proto::ApprovalDecision::Approve => Self::Approve,
            proto::ApprovalDecision::Reject => Self::Reject,
        })
    }
}

pub fn approval_decision_from_i32(v: i32) -> Result<ApprovalDecision, Status> {
    proto::ApprovalDecision::try_from(v)
        .map_err(|_| Status::invalid_argument(format!("unknown ApprovalDecision variant: {v}")))?
        .try_into()
}

impl From<qfc_audit::AuditKind> for proto::AuditKind {
    fn from(k: qfc_audit::AuditKind) -> Self {
        use qfc_audit::AuditKind as K;
        match k {
            K::WalletCreated => Self::WalletCreated,
            K::WalletRevoked => Self::WalletRevoked,
            K::SigningRequested => Self::SigningRequested,
            K::SigningEvaluated => Self::SigningEvaluated,
            K::QuorumNotified => Self::QuorumNotified,
            K::QuorumApprovalReceived => Self::QuorumApprovalReceived,
            K::QuorumApprovalRejected => Self::QuorumApprovalRejected,
            K::QuorumTimedOut => Self::QuorumTimedOut,
            K::QuorumThresholdReached => Self::QuorumThresholdReached,
            K::SigningAttempted => Self::SigningAttempted,
            K::SigningSucceeded => Self::SigningSucceeded,
            K::SigningFailed => Self::SigningFailed,
            K::PolicyChanged => Self::PolicyChanged,
            K::ApproverSetChanged => Self::ApproverSetChanged,
            K::SystemError => Self::SystemError,
            K::EnclaveAttested => Self::EnclaveAttested,
            K::PolicyDecisionSigned => Self::PolicyDecisionSigned,
        }
    }
}

// ---------------------------------------------------------------------------
// Wallet payload / requester / context / wallet view
// ---------------------------------------------------------------------------

pub fn lower_payload(p: proto::SigningPayload) -> Result<SigningPayload, Status> {
    use proto::signing_payload::Payload;
    let payload = require_field("payload.kind", p.payload)?;
    Ok(match payload {
        Payload::Raw(r) => SigningPayload::Raw { bytes: r.bytes },
        Payload::PersonalSign(r) => SigningPayload::PersonalSign { bytes: r.bytes },
        Payload::TypedData(t) => {
            let json: serde_json::Value = serde_json::from_str(&t.json)
                .map_err(|e| Status::invalid_argument(format!("invalid typed_data.json: {e}")))?;
            SigningPayload::TypedData { json }
        }
        Payload::VmTransaction(tx) => {
            let vm_proto = proto::VmType::try_from(tx.vm).map_err(|_| {
                Status::invalid_argument(format!("unknown VmType variant: {}", tx.vm))
            })?;
            SigningPayload::VmTransaction {
                vm: vm_proto.try_into()?,
                chain_id: tx.chain_id,
                to: tx.to,
                raw: tx.raw,
            }
        }
    })
}

pub fn lower_requester(r: proto::Requester) -> Result<Requester, Status> {
    use proto::requester::Requester as R;
    let inner = require_field("requester.kind", r.requester)?;
    Ok(match inner {
        R::ApiKey(a) => Requester::ApiKey { key_id: a.key_id },
        R::OauthSubject(o) => Requester::OAuthSubject { sub: o.sub },
        R::NestedWallet(n) => Requester::NestedWallet {
            wallet_id: parse_ulid("nested_wallet.wallet_id", &n.wallet_id)?,
        },
        R::OnChainContract(c) => Requester::OnChainContract {
            chain_id: c.chain_id,
            address: c.address,
        },
    })
}

pub fn lower_context(c: Option<proto::SigningContext>) -> Result<EnclaveSigningContext, Status> {
    let Some(c) = c else {
        return Ok(EnclaveSigningContext::default());
    };
    let extra = if c.extra_json.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_str(&c.extra_json)
            .map_err(|e| Status::invalid_argument(format!("invalid context.extra_json: {e}")))?
    };
    Ok(EnclaveSigningContext {
        chain_id: c.chain_id,
        vm_type: c.vm_type,
        extra,
    })
}

pub fn lower_hd_path(s: &str) -> Result<Option<HdPath>, Status> {
    if s.is_empty() {
        return Ok(None);
    }
    Ok(Some(s.parse::<HdPath>().map_err(|e| {
        Status::invalid_argument(format!("invalid hd_path: {e}"))
    })?))
}

pub fn lower_create_wallet(req: proto::CreateWalletRequest) -> Result<WalletConfig, Status> {
    let scheme = scheme_from_i32(req.scheme)?;
    let threshold: u8 = req
        .threshold
        .try_into()
        .map_err(|_| Status::invalid_argument("threshold out of u8 range"))?;
    let total: u8 = req
        .total
        .try_into()
        .map_err(|_| Status::invalid_argument("total out of u8 range"))?;
    let policy_id = if req.policy_id.is_empty() {
        PolicyId::new()
    } else {
        parse_ulid("policy_id", &req.policy_id)?
    };
    Ok(WalletConfig {
        display_name: req.display_name,
        owner_id: OwnerId::new(req.owner_id),
        scheme,
        threshold,
        total,
        policy_id,
        max_value_per_tx: None,
        contract_allowlist: Vec::new(),
        chain_allowlist: Vec::new(),
    })
}

pub fn raise_wallet_view(record: WalletRecord) -> proto::WalletView {
    let status: proto::WalletStatus = record.status.into();
    let scheme: proto::SigningScheme = record.config.scheme.into();
    proto::WalletView {
        wallet_id: record.wallet_id.to_string(),
        scheme: scheme.into(),
        threshold: u32::from(record.config.threshold),
        total: u32::from(record.config.total),
        display_name: record.config.display_name,
        owner_id: record.config.owner_id.to_string(),
        policy_id: record.config.policy_id.to_string(),
        master_public_key: record.master_public_key,
        status: status.into(),
        created_at_unix_ms: record.created_at_unix_ms,
    }
}

pub fn raise_audit_event(event: AuditEvent) -> proto::AuditEventView {
    let actor_json = serde_json::to_string(&event.actor).unwrap_or_else(|_| "null".to_string());
    let details_json = serde_json::to_string(&event.details).unwrap_or_else(|_| "null".to_string());
    let kind: proto::AuditKind = event.kind.into();
    proto::AuditEventView {
        event_id: event.event_id.to_string(),
        prev_event_hash: event.prev_event_hash.to_vec(),
        timestamp_unix_ms: event.timestamp_unix_ms,
        actor_json,
        kind: kind.into(),
        request_id: event.request_id.map(|r| r.to_string()).unwrap_or_default(),
        wallet_id: event.wallet_id.map(|w| w.to_string()).unwrap_or_default(),
        details_json,
        server_signature: event.server_signature,
    }
}

// ---------------------------------------------------------------------------
// Approver identity + records
// ---------------------------------------------------------------------------

pub fn lower_approver_identity(p: proto::ApproverIdentity) -> Result<ApproverIdentity, Status> {
    use proto::approver_identity::Identity;
    let inner = require_field("identity.kind", p.identity)?;
    Ok(match inner {
        Identity::Chain(c) => ApproverIdentity::Chain {
            chain_id: c.chain_id,
            address: c.address,
            public_key: c.public_key,
            scheme: scheme_from_i32(c.scheme)?,
        },
        Identity::External(e) => ApproverIdentity::External {
            id: e.id,
            public_key: e.public_key,
            scheme: scheme_from_i32(e.scheme)?,
        },
        Identity::Hardware(h) => ApproverIdentity::Hardware(HardwareApproverHandle {
            handle: h.handle,
            public_key: h.public_key,
            scheme: scheme_from_i32(h.scheme)?,
        }),
        Identity::NestedWallet(n) => ApproverIdentity::NestedWallet {
            wallet_id: parse_ulid("nested_wallet.wallet_id", &n.wallet_id)?,
            public_key: n.public_key,
            scheme: scheme_from_i32(n.scheme)?,
        },
    })
}

pub fn raise_approver_identity(i: ApproverIdentity) -> proto::ApproverIdentity {
    use proto::approver_identity::Identity;
    let inner = match i {
        ApproverIdentity::Chain {
            chain_id,
            address,
            public_key,
            scheme,
        } => {
            let scheme: proto::SigningScheme = scheme.into();
            Identity::Chain(proto::approver_identity::Chain {
                chain_id,
                address,
                public_key,
                scheme: scheme.into(),
            })
        }
        ApproverIdentity::External {
            id,
            public_key,
            scheme,
        } => {
            let scheme: proto::SigningScheme = scheme.into();
            Identity::External(proto::approver_identity::External {
                id,
                public_key,
                scheme: scheme.into(),
            })
        }
        ApproverIdentity::Hardware(h) => {
            let scheme: proto::SigningScheme = h.scheme.into();
            Identity::Hardware(proto::approver_identity::Hardware {
                handle: h.handle,
                public_key: h.public_key,
                scheme: scheme.into(),
            })
        }
        ApproverIdentity::NestedWallet {
            wallet_id,
            public_key,
            scheme,
        } => {
            let scheme: proto::SigningScheme = scheme.into();
            Identity::NestedWallet(proto::approver_identity::NestedWallet {
                wallet_id: wallet_id.to_string(),
                public_key,
                scheme: scheme.into(),
            })
        }
    };
    proto::ApproverIdentity {
        identity: Some(inner),
    }
}

pub fn raise_approver_record(r: ApproverRecord) -> proto::ApproverView {
    let status: proto::ApproverStatus = r.status.into();
    let scheme: proto::SigningScheme = r.scheme.into();
    proto::ApproverView {
        approver_id: r.approver_id.to_string(),
        identity: Some(raise_approver_identity(r.identity)),
        scheme: scheme.into(),
        label: r.label,
        owner_id: r.owner_id.to_string(),
        webhook_url: r.webhook_url.unwrap_or_default(),
        status: status.into(),
        added_at_unix_ms: r.added_at_unix_ms,
    }
}

pub fn raise_approver_set(s: ApproverSet) -> proto::ApproverSetView {
    proto::ApproverSetView {
        approver_set_id: s.id.to_string(),
        name: s.name,
        owner_id: s.owner_id.to_string(),
        members: s.members.iter().map(ToString::to_string).collect(),
        threshold: u32::from(s.threshold),
        total: u32::from(s.total),
        quorum_timeout_secs: s.quorum_timeout_secs.unwrap_or(0),
        created_at_unix_ms: s.created_at_unix_ms,
    }
}

pub fn lower_create_approver_set(
    req: proto::CreateApproverSetRequest,
) -> Result<qfc_quorum::ApproverSetCreate, Status> {
    let mut members = Vec::with_capacity(req.members.len());
    for m in &req.members {
        members.push(parse_ulid::<ApproverId>("member approver_id", m)?);
    }
    let threshold: u8 = req
        .threshold
        .try_into()
        .map_err(|_| Status::invalid_argument("threshold out of u8 range"))?;
    let total: u8 = req
        .total
        .try_into()
        .map_err(|_| Status::invalid_argument("total out of u8 range"))?;
    let quorum_timeout_secs = if req.quorum_timeout_secs == 0 {
        None
    } else {
        Some(req.quorum_timeout_secs)
    };
    Ok(qfc_quorum::ApproverSetCreate {
        name: req.name,
        owner_id: OwnerId::new(req.owner_id),
        members,
        threshold,
        total,
        quorum_timeout_secs,
    })
}

pub fn raise_signed_approval(a: SignedApproval) -> proto::ApprovalView {
    let decision: proto::ApprovalDecision = a.decision.into();
    proto::ApprovalView {
        approval_id: a.approval_id.to_string(),
        request_id: a.request_id.to_string(),
        approver_key: a.approver.key(),
        approver: Some(raise_approver_identity(a.approver)),
        decision: decision.into(),
        message_hash: a.message_hash.to_vec(),
        timestamp_unix_ms: a.timestamp_unix_ms,
        signature: a.signature,
    }
}

/// Lower a `SubmitApprovalRequest` into `(SignedApproval, ApproverId, expected_hash)`.
pub fn lower_submit_approval(
    req: proto::SubmitApprovalRequest,
) -> Result<(SignedApproval, ApproverId, [u8; 32]), Status> {
    let request_id = parse_ulid::<RequestId>("request_id", &req.request_id)?;
    let approver_id = parse_ulid::<ApproverId>("approver_id", &req.approver_id)?;
    let approval_id = parse_ulid::<ApprovalId>("approval_id", &req.approval_id)?;
    let message_hash = require_32_bytes("message_hash", &req.message_hash)?;
    let decision = approval_decision_from_i32(req.decision)?;
    let identity = lower_approver_identity(require_field("identity", req.identity)?)?;
    let signed = SignedApproval {
        approval_id,
        approver: identity,
        request_id,
        message_hash,
        decision,
        timestamp_unix_ms: req.timestamp_unix_ms,
        signature: req.signature,
    };
    Ok((signed, approver_id, message_hash))
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map `ServiceError` to a `tonic::Status`. Matches the HTTP status-code
/// mapping in `api::error::ApiError::from(ServiceError)` so HTTP and gRPC
/// agree on what each failure means.
pub fn map_service_error(e: ServiceError) -> Status {
    match e {
        ServiceError::WalletNotFound(id) => Status::not_found(format!("wallet {id} not found")),
        ServiceError::PolicyDenied(msg) => Status::permission_denied(msg),
        ServiceError::Quorum(qfc_quorum::QuorumError::InvalidApproval(inner)) => {
            Status::failed_precondition(format!("approval verification failed: {inner}"))
        }
        ServiceError::Quorum(qfc_quorum::QuorumError::UnknownApprover(msg)) => {
            Status::not_found(msg)
        }
        ServiceError::Quorum(qfc_quorum::QuorumError::Transport(msg)) => {
            if msg.contains("duplicate approval") {
                Status::already_exists(msg)
            } else {
                Status::internal(msg)
            }
        }
        ServiceError::Quorum(other) => Status::aborted(other.to_string()),
        ServiceError::Enclave(e) => Status::internal(format!("enclave: {e}")),
        ServiceError::Audit(e) => Status::internal(format!("audit: {e}")),
        ServiceError::Store(e) => Status::internal(format!("store: {e}")),
        ServiceError::Policy(e) => Status::internal(format!("policy: {e}")),
        ServiceError::InsufficientShares(e) => Status::internal(format!("shares: {e}")),
        ServiceError::Internal(msg) => Status::internal(msg),
    }
}

/// Map `qfc_quorum::RegistryError` to a `tonic::Status`. Mirrors the HTTP
/// `map_registry_err` in `api::handlers`.
pub fn map_registry_error(err: qfc_quorum::RegistryError) -> Status {
    use qfc_quorum::RegistryError as R;
    let msg = err.to_string();
    match err {
        R::ApproverNotFound(_) | R::ApproverSetNotFound(_) => Status::not_found(msg),
        R::UnknownMember(_)
        | R::RevokedMember(_)
        | R::MemberCountMismatch { .. }
        | R::InvalidThreshold { .. }
        | R::DuplicateMember(_)
        | R::NestingCycle(_)
        | R::NestingTooDeep(_) => Status::failed_precondition(msg),
        R::Io(_) => Status::internal(msg),
    }
}

// Belt-and-braces: keep these `use` lines from being flagged as unused if a
// caller stops using them.
#[allow(dead_code)]
fn _force_use(_w: WalletId, _r: RequestId, _a: ApproverId, _s: ApproverSetId, _ap: ApprovalId) {}
