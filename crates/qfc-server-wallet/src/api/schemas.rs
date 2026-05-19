//! Wire-level request / response shapes for the HTTP API.
//!
//! These DTOs are deliberately **separate** from the underlying domain
//! types so that:
//!
//! 1. We can document them with `utoipa` derives without forcing the
//!    deep types in `qfc-policy` / `qfc-enclave` / `qfc-audit` to depend
//!    on `utoipa`.
//! 2. Byte fields are exposed as hex strings on the wire — far friendlier
//!    than JSON arrays of integers, which is what bare `Vec<u8>` would
//!    produce.
//! 3. The mapping function (`From` / `into_*` impls) is the single place
//!    we revisit when the orchestrator surface evolves.

use qfc_audit::{AuditEvent, AuditKind};
use qfc_enclave::SigningContext;
use qfc_policy::{Requester, SigningPayload, VmType};
use qfc_wallet_types::{HashAlg, HdPath, OwnerId, PolicyId, SigningScheme, WalletId};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::api::error::ApiError;
use crate::wallet::{WalletConfig, WalletRecord, WalletStatus};

// =============================================================================
// Local mirror enums for foreign types that don't (and shouldn't) carry
// utoipa derives. These exist *only* so utoipa can document them. They are
// not used at the boundary directly — the boundary uses serde-string forms
// inherited from the foreign types (rename_all = "snake_case"), and we
// convert with the `into_domain` / `From` impls below.
// =============================================================================

/// OpenAPI mirror of `qfc_wallet_types::SigningScheme`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum SigningSchemeDto {
    Ed25519,
    Secp256k1,
    Secp256k1Recoverable,
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

impl From<SigningSchemeDto> for SigningScheme {
    fn from(d: SigningSchemeDto) -> Self {
        match d {
            SigningSchemeDto::Ed25519 => Self::Ed25519,
            SigningSchemeDto::Secp256k1 => Self::Secp256k1,
            SigningSchemeDto::Secp256k1Recoverable => Self::Secp256k1Recoverable,
            SigningSchemeDto::MlDsa44 => Self::MlDsa44,
            SigningSchemeDto::MlDsa65 => Self::MlDsa65,
            SigningSchemeDto::MlDsa87 => Self::MlDsa87,
        }
    }
}

impl From<SigningScheme> for SigningSchemeDto {
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

/// OpenAPI mirror of `qfc_wallet_types::HashAlg`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum HashAlgDto {
    None,
    Sha256,
    Keccak256,
    Blake3,
}

impl From<HashAlgDto> for HashAlg {
    fn from(d: HashAlgDto) -> Self {
        match d {
            HashAlgDto::None => Self::None,
            HashAlgDto::Sha256 => Self::Sha256,
            HashAlgDto::Keccak256 => Self::Keccak256,
            HashAlgDto::Blake3 => Self::Blake3,
        }
    }
}

/// OpenAPI mirror of `qfc_policy::VmType`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum VmTypeDto {
    Evm,
    Qvm,
    Wasm,
}

impl From<VmTypeDto> for VmType {
    fn from(d: VmTypeDto) -> Self {
        match d {
            VmTypeDto::Evm => Self::Evm,
            VmTypeDto::Qvm => Self::Qvm,
            VmTypeDto::Wasm => Self::Wasm,
        }
    }
}

/// OpenAPI mirror of `qfc_audit::AuditKind`. Matches the wire snake-case
/// representation 1:1.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum AuditKindDto {
    WalletCreated,
    WalletRevoked,
    SigningRequested,
    SigningEvaluated,
    QuorumNotified,
    QuorumApprovalReceived,
    QuorumApprovalRejected,
    QuorumTimedOut,
    SigningAttempted,
    SigningSucceeded,
    SigningFailed,
    PolicyChanged,
    ApproverSetChanged,
    SystemError,
    EnclaveAttested,
}

impl From<AuditKind> for AuditKindDto {
    fn from(k: AuditKind) -> Self {
        match k {
            AuditKind::WalletCreated => Self::WalletCreated,
            AuditKind::WalletRevoked => Self::WalletRevoked,
            AuditKind::SigningRequested => Self::SigningRequested,
            AuditKind::SigningEvaluated => Self::SigningEvaluated,
            AuditKind::QuorumNotified => Self::QuorumNotified,
            AuditKind::QuorumApprovalReceived => Self::QuorumApprovalReceived,
            AuditKind::QuorumApprovalRejected => Self::QuorumApprovalRejected,
            AuditKind::QuorumTimedOut => Self::QuorumTimedOut,
            AuditKind::SigningAttempted => Self::SigningAttempted,
            AuditKind::SigningSucceeded => Self::SigningSucceeded,
            AuditKind::SigningFailed => Self::SigningFailed,
            AuditKind::PolicyChanged => Self::PolicyChanged,
            AuditKind::ApproverSetChanged => Self::ApproverSetChanged,
            AuditKind::SystemError => Self::SystemError,
            AuditKind::EnclaveAttested => Self::EnclaveAttested,
        }
    }
}

/// OpenAPI mirror of `crate::wallet::WalletStatus`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum WalletStatusDto {
    Active,
    Frozen,
    Revoked,
}

impl From<WalletStatus> for WalletStatusDto {
    fn from(s: WalletStatus) -> Self {
        match s {
            WalletStatus::Active => Self::Active,
            WalletStatus::Frozen => Self::Frozen,
            WalletStatus::Revoked => Self::Revoked,
        }
    }
}

// =============================================================================
// Wire DTOs
// =============================================================================

/// Request body for `POST /wallets`. Mirrors `WalletConfig` but uses
/// plain string types for ULIDs so callers can copy/paste IDs from the
/// CLI without escaping issues.
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub struct CreateWalletRequest {
    /// Curve / scheme to use for the wallet's master key.
    pub scheme: SigningSchemeDto,
    /// SSS threshold M (`>= 2`).
    #[schema(example = 2, minimum = 2)]
    pub threshold: u8,
    /// SSS total share count N (`>= threshold`).
    #[schema(example = 3, minimum = 2)]
    pub total: u8,
    /// Human-readable wallet name shown in operator dashboards.
    #[schema(example = "treasury-cold")]
    pub display_name: String,
    /// Tenant / customer identifier.
    #[schema(example = "tenant-alpha")]
    pub owner_id: String,
    /// Optional policy version ULID. If absent a fresh `PolicyId` is
    /// allocated by the service.
    #[schema(example = "01HZX0YBKJ7Z9PR2NQ7X3T6QGH")]
    pub policy_id: Option<String>,
}

impl CreateWalletRequest {
    /// Lower to the domain `WalletConfig`.
    ///
    /// # Errors
    ///
    /// `ApiError::BadRequest` when the supplied `policy_id` is not a
    /// well-formed ULID.
    pub fn into_config(self) -> Result<WalletConfig, ApiError> {
        let policy_id = match self.policy_id {
            Some(s) => s
                .parse::<PolicyId>()
                .map_err(|e| ApiError::BadRequest(format!("invalid policy_id: {e}")))?,
            None => PolicyId::new(),
        };
        Ok(WalletConfig {
            display_name: self.display_name,
            owner_id: OwnerId::new(self.owner_id),
            scheme: self.scheme.into(),
            threshold: self.threshold,
            total: self.total,
            policy_id,
        })
    }
}

/// JSON view of a wallet record returned by `POST /wallets` and
/// `GET /wallets/{id}`. The master public key is hex-encoded.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct WalletView {
    /// ULID identifying the wallet.
    #[schema(example = "01HZX0YBKJ7Z9PR2NQ7X3T6QGH")]
    pub wallet_id: String,
    /// Curve.
    pub scheme: SigningSchemeDto,
    /// SSS threshold M.
    pub threshold: u8,
    /// SSS total N.
    pub total: u8,
    /// Display name.
    pub display_name: String,
    /// Owner / tenant identifier.
    pub owner_id: String,
    /// Policy version ULID.
    pub policy_id: String,
    /// Hex-encoded master public key (32 B for ed25519, 33 B compressed
    /// for secp256k1).
    pub master_public_key_hex: String,
    /// Lifecycle status (`active`, `frozen`, `revoked`).
    pub status: WalletStatusDto,
    /// Unix-millisecond creation timestamp.
    pub created_at_unix_ms: i64,
}

impl From<WalletRecord> for WalletView {
    fn from(r: WalletRecord) -> Self {
        Self {
            wallet_id: r.wallet_id.to_string(),
            scheme: r.config.scheme.into(),
            threshold: r.config.threshold,
            total: r.config.total,
            display_name: r.config.display_name,
            owner_id: r.config.owner_id.to_string(),
            policy_id: r.config.policy_id.to_string(),
            master_public_key_hex: hex::encode(&r.master_public_key),
            status: r.status.into(),
            created_at_unix_ms: r.created_at_unix_ms,
        }
    }
}

/// Caller identity for `POST /wallets/{id}/sign`. Mirrors
/// `qfc_policy::Requester` 1:1 but uses hex for the on-chain contract
/// address.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RequesterDto {
    /// API key identifier.
    ApiKey {
        /// Stable key identifier.
        key_id: String,
    },
    /// OAuth-style subject.
    OauthSubject {
        /// `sub` claim.
        sub: String,
    },
    /// Another wallet acting on this caller's behalf.
    NestedWallet {
        /// Nested wallet's ULID.
        wallet_id: String,
    },
    /// On-chain contract.
    OnChainContract {
        /// Chain identifier.
        chain_id: u64,
        /// Hex-encoded contract address.
        address_hex: String,
    },
}

impl RequesterDto {
    /// Lower to the domain `Requester`.
    ///
    /// # Errors
    ///
    /// `ApiError::BadRequest` on a malformed nested-wallet ULID or
    /// non-hex contract address.
    pub fn into_domain(self) -> Result<Requester, ApiError> {
        Ok(match self {
            Self::ApiKey { key_id } => Requester::ApiKey { key_id },
            Self::OauthSubject { sub } => Requester::OAuthSubject { sub },
            Self::NestedWallet { wallet_id } => Requester::NestedWallet {
                wallet_id: wallet_id
                    .parse::<WalletId>()
                    .map_err(|e| ApiError::BadRequest(format!("invalid wallet_id: {e}")))?,
            },
            Self::OnChainContract {
                chain_id,
                address_hex,
            } => Requester::OnChainContract {
                chain_id,
                address: hex::decode(&address_hex)
                    .map_err(|e| ApiError::BadRequest(format!("invalid address_hex: {e}")))?,
            },
        })
    }
}

/// Wire shape for `qfc_policy::SigningPayload`. Bytes are exposed as
/// hex strings; the `TypedData` and `VmTransaction` variants carry JSON
/// / hex bodies as appropriate.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SigningPayloadDto {
    /// Arbitrary raw bytes.
    Raw {
        /// Hex-encoded bytes.
        bytes_hex: String,
    },
    /// EIP-191 / personal-sign envelope.
    PersonalSign {
        /// Hex-encoded envelope.
        bytes_hex: String,
    },
    /// EIP-712 typed data payload.
    TypedData {
        /// Canonical JSON.
        json: serde_json::Value,
    },
    /// VM-specific transaction.
    VmTransaction {
        /// VM type (`evm`, `qvm`, `wasm`).
        vm: VmTypeDto,
        /// Chain identifier.
        chain_id: u64,
        /// Optional decoded destination address, hex-encoded.
        to_hex: Option<String>,
        /// Hex-encoded raw transaction body.
        raw_hex: String,
    },
}

impl SigningPayloadDto {
    /// Lower to the domain `SigningPayload`.
    ///
    /// # Errors
    ///
    /// `ApiError::BadRequest` when any hex field is invalid.
    pub fn into_domain(self) -> Result<SigningPayload, ApiError> {
        Ok(match self {
            Self::Raw { bytes_hex } => SigningPayload::Raw {
                bytes: hex::decode(&bytes_hex)
                    .map_err(|e| ApiError::BadRequest(format!("invalid bytes_hex: {e}")))?,
            },
            Self::PersonalSign { bytes_hex } => SigningPayload::PersonalSign {
                bytes: hex::decode(&bytes_hex)
                    .map_err(|e| ApiError::BadRequest(format!("invalid bytes_hex: {e}")))?,
            },
            Self::TypedData { json } => SigningPayload::TypedData { json },
            Self::VmTransaction {
                vm,
                chain_id,
                to_hex,
                raw_hex,
            } => SigningPayload::VmTransaction {
                vm: vm.into(),
                chain_id,
                to: match to_hex {
                    Some(s) => Some(
                        hex::decode(&s)
                            .map_err(|e| ApiError::BadRequest(format!("invalid to_hex: {e}")))?,
                    ),
                    None => None,
                },
                raw: hex::decode(&raw_hex)
                    .map_err(|e| ApiError::BadRequest(format!("invalid raw_hex: {e}")))?,
            },
        })
    }
}

/// JSON view of `SigningContext`. Mirrors the domain type with one
/// difference: `extra` defaults to JSON `null` instead of being absent.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct SigningContextDto {
    /// Optional chain identifier.
    pub chain_id: Option<u64>,
    /// Optional VM label.
    pub vm_type: Option<String>,
    /// Open extension space; canonically serialized into the attestation.
    #[serde(default)]
    pub extra: serde_json::Value,
}

impl From<SigningContextDto> for SigningContext {
    fn from(d: SigningContextDto) -> Self {
        Self {
            chain_id: d.chain_id,
            vm_type: d.vm_type,
            extra: d.extra,
        }
    }
}

/// `POST /wallets/{id}/sign` body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignRequest {
    /// The payload to sign.
    pub payload: SigningPayloadDto,
    /// Identity of the caller.
    pub requester: RequesterDto,
    /// Optional HD derivation path. Required to be absent for PQ schemes.
    pub hd_path: Option<String>,
    /// Hash transformation to apply pre-signing.
    pub hash_alg: HashAlgDto,
    /// Optional signing context (chain id, VM type, extras).
    pub context: Option<SigningContextDto>,
}

impl SignRequest {
    /// Parse the optional HD path string into the domain type.
    ///
    /// # Errors
    ///
    /// `ApiError::BadRequest` on a malformed path.
    pub fn hd_path_parsed(&self) -> Result<Option<HdPath>, ApiError> {
        match &self.hd_path {
            None => Ok(None),
            Some(s) => {
                Ok(Some(s.parse::<HdPath>().map_err(|e| {
                    ApiError::BadRequest(format!("invalid hd_path: {e}"))
                })?))
            }
        }
    }
}

/// `POST /wallets/{id}/sign` response body.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SignResponse {
    /// Hex-encoded signature bytes.
    pub signature_hex: String,
    /// Hex-encoded public key the signature was produced under.
    pub public_key_hex: String,
    /// Attestation document. Contains the raw signed payload and the
    /// enclave's public key — full structure preserved so callers can
    /// re-verify.
    pub attestation: serde_json::Value,
}

/// Query string for `GET /audit/events`.
#[derive(Debug, Clone, Default, Deserialize, ToSchema, IntoParams)]
pub struct AuditEventsQuery {
    /// If present, only return events whose `wallet_id` matches.
    pub wallet_id: Option<String>,
    /// Maximum number of most-recent events to return. Default 100,
    /// capped at 1000.
    pub limit: Option<usize>,
}

/// JSON view of `qfc_audit::AuditEvent`. Bytes (`prev_event_hash`,
/// `server_signature`) are surfaced as hex.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditEventView {
    /// ULID identifying the event.
    pub event_id: String,
    /// Hex-encoded SHA-256 of the previous event's signing preimage.
    pub prev_event_hash_hex: String,
    /// Unix-millisecond timestamp.
    pub timestamp_unix_ms: i64,
    /// Who produced the event. Stable JSON representation of
    /// `qfc_audit::Actor` (`{"requester": {"id": "..."}}`, `"system"`, …).
    pub actor: serde_json::Value,
    /// Event classification.
    pub kind: AuditKindDto,
    /// Optional request id.
    pub request_id: Option<String>,
    /// Optional wallet id.
    pub wallet_id: Option<String>,
    /// Freeform per-kind payload.
    pub details: serde_json::Value,
    /// Hex-encoded ed25519 server signature.
    pub server_signature_hex: String,
}

impl From<AuditEvent> for AuditEventView {
    fn from(e: AuditEvent) -> Self {
        Self {
            event_id: e.event_id.to_string(),
            prev_event_hash_hex: hex::encode(e.prev_event_hash),
            timestamp_unix_ms: e.timestamp_unix_ms,
            actor: serde_json::to_value(&e.actor).unwrap_or(serde_json::Value::Null),
            kind: e.kind.into(),
            request_id: e.request_id.map(|r| r.to_string()),
            wallet_id: e.wallet_id.map(|w| w.to_string()),
            details: e.details,
            server_signature_hex: hex::encode(&e.server_signature),
        }
    }
}
