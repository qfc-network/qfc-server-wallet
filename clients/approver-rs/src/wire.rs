//! Wire-format DTOs.
//!
//! The webhook receiver consumes `ApprovalRequestWire` (a serde mirror of
//! `qfc_quorum::ApprovalRequest`) and emits `SubmitApprovalWire` (the
//! server-side `POST /requests/{request_id}/approvals` body — mirrors
//! `qfc_server_wallet::api::schemas::SubmitApprovalRequest`).
//!
//! We deliberately do NOT depend on `qfc-server-wallet` directly; the
//! whole point of the reference client is to be forkable in isolation,
//! and `qfc-server-wallet` pulls in axum + sqlx + the entire wallet
//! service. We re-declare the wire types here and pin equality against
//! the server side via the `tests/preimage_compat.rs` integration test
//! (which DOES use the server crate at test time).

use qfc_wallet_types::SigningScheme;
use serde::{Deserialize, Serialize};

/// Signing scheme enum on the wire. Mirrors `qfc_wallet_types::SigningScheme`
/// in serde shape exactly (`snake_case` lowercase). We mirror rather than
/// re-export so a future server-side rename produces a *compile* error in
/// the cross-compat integration test rather than a silent wire break.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningSchemeWire {
    /// RFC 8032 Ed25519.
    Ed25519,
    /// secp256k1 fixed-width (r || s).
    Secp256k1,
    /// secp256k1 with recovery byte (r || s || v).
    Secp256k1Recoverable,
    /// ML-DSA-44 (FIPS 204).
    MlDsa44,
    /// ML-DSA-65 (FIPS 204).
    MlDsa65,
    /// ML-DSA-87 (FIPS 204).
    MlDsa87,
}

impl From<SigningSchemeWire> for SigningScheme {
    fn from(s: SigningSchemeWire) -> Self {
        match s {
            SigningSchemeWire::Ed25519 => Self::Ed25519,
            SigningSchemeWire::Secp256k1 => Self::Secp256k1,
            SigningSchemeWire::Secp256k1Recoverable => Self::Secp256k1Recoverable,
            SigningSchemeWire::MlDsa44 => Self::MlDsa44,
            SigningSchemeWire::MlDsa65 => Self::MlDsa65,
            SigningSchemeWire::MlDsa87 => Self::MlDsa87,
        }
    }
}

impl From<SigningScheme> for SigningSchemeWire {
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

/// Approver-identity wire form. Mirrors `qfc_quorum::ApproverIdentity` with
/// hex-encoded byte fields — the same shape the server uses in its
/// HTTP DTO.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApproverIdentityWire {
    /// QFC on-chain account.
    Chain {
        /// Chain id.
        chain_id: u64,
        /// Hex-encoded chain address.
        address_hex: String,
        /// Hex-encoded public key.
        public_key_hex: String,
        /// Curve.
        scheme: SigningSchemeWire,
    },
    /// Externally-registered raw public key.
    External {
        /// Audit-stable id.
        id: String,
        /// Hex-encoded public key.
        public_key_hex: String,
        /// Curve.
        scheme: SigningSchemeWire,
    },
    /// Hardware-token-backed identity.
    Hardware {
        /// Stable device+slot handle.
        handle: String,
        /// Hex-encoded public key.
        public_key_hex: String,
        /// Curve.
        scheme: SigningSchemeWire,
    },
    /// Nested server wallet (treasury-of-treasuries).
    NestedWallet {
        /// Nested wallet ULID.
        wallet_id: String,
        /// Hex-encoded master public key.
        public_key_hex: String,
        /// Curve.
        scheme: SigningSchemeWire,
    },
}

impl ApproverIdentityWire {
    /// Borrow the public key hex.
    #[must_use]
    pub fn public_key_hex(&self) -> &str {
        match self {
            Self::Chain { public_key_hex, .. }
            | Self::External { public_key_hex, .. }
            | Self::Hardware { public_key_hex, .. }
            | Self::NestedWallet { public_key_hex, .. } => public_key_hex,
        }
    }

    /// Borrow the curve.
    #[must_use]
    pub fn scheme(&self) -> SigningSchemeWire {
        match self {
            Self::Chain { scheme, .. }
            | Self::External { scheme, .. }
            | Self::Hardware { scheme, .. }
            | Self::NestedWallet { scheme, .. } => *scheme,
        }
    }
}

/// `ApprovalRequest` wire shape. Mirrors `qfc_quorum::ApprovalRequest`.
///
/// `message_hash` is hex-encoded (32 bytes). The server emits this via
/// `serde_json::to_vec(&req)` and HMACs the body — see
/// `WebhookApprover::notify`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequestWire {
    /// Signing-request ULID.
    pub request_id: String,
    /// Hex-encoded SHA-256 message digest (32 bytes).
    pub message_hash: String,
    /// Approver set the server is asking.
    pub approver_set: Vec<ApproverIdentityWire>,
    /// Minimum approvals required.
    pub threshold: u8,
}

/// `POST /requests/{request_id}/approvals` body. Mirrors
/// `qfc_server_wallet::api::schemas::SubmitApprovalRequest`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubmitApprovalWire {
    /// ULID of the registered approver issuing this decision.
    pub approver_id: String,
    /// ULID of this approval action.
    pub approval_id: String,
    /// `approve` or `reject` (`snake_case`).
    pub decision: String,
    /// Hex-encoded signature over the canonical preimage.
    pub signature_hex: String,
    /// Unix-millisecond timestamp of when this approval was signed.
    pub timestamp_unix_ms: i64,
    /// Hex-encoded SHA-256 message hash this approval binds to.
    pub message_hash_hex: String,
    /// Approver-identity payload, echoed for the server's cross-check.
    pub identity: ApproverIdentityWire,
}
