//! Audit event types.
//!
//! See `docs/server-wallet-rfc.md` §2.6.

use qfc_wallet_types::{EventId, RequestId, WalletId};
use serde::{Deserialize, Serialize};

/// Who or what produced the event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// A signing-API caller (typically identified by API key / OAuth subject).
    Requester {
        /// Opaque identifier (API key id, OAuth `sub`, etc.).
        id: String,
    },
    /// One of the approvers in a quorum flow.
    Approver {
        /// Opaque approver identifier (see `qfc-quorum::ApproverIdentity`).
        id: String,
    },
    /// The system itself (cron jobs, server lifecycle, internal housekeeping).
    System,
    /// The enclave (attestation events, key generation, etc.).
    Enclave,
}

/// Classification of the audit event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditKind {
    /// A wallet was created.
    WalletCreated,
    /// A wallet was revoked / closed.
    WalletRevoked,
    /// A signing request was accepted at the API boundary.
    SigningRequested,
    /// The policy engine evaluated a request (`Allow` / `Deny` / `RequireQuorum`).
    SigningEvaluated,
    /// Quorum approvers were notified.
    QuorumNotified,
    /// An approval was received.
    QuorumApprovalReceived,
    /// A rejection was received.
    QuorumApprovalRejected,
    /// Quorum collection timed out.
    QuorumTimedOut,
    /// The enclave was asked to sign.
    SigningAttempted,
    /// The signing call succeeded.
    SigningSucceeded,
    /// The signing call failed.
    SigningFailed,
    /// Policy configuration changed.
    PolicyChanged,
    /// An approver set changed.
    ApproverSetChanged,
    /// A system-level error (e.g. backend unavailable).
    SystemError,
    /// The enclave produced an `attest()` document.
    EnclaveAttested,
}

/// One audit event. Hash-chained via `prev_event_hash`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Globally unique, monotonic-per-sink identifier (ULID).
    pub event_id: EventId,
    /// SHA-256 digest of the immediately preceding event's canonical
    /// serialization. The genesis event uses `[0u8; 32]`.
    #[serde(with = "hex_array_32")]
    pub prev_event_hash: [u8; 32],
    /// Unix-millisecond timestamp.
    pub timestamp_unix_ms: i64,
    /// Who produced the event.
    pub actor: Actor,
    /// Event classification.
    pub kind: AuditKind,
    /// Optional reference to the signing request this event belongs to.
    pub request_id: Option<RequestId>,
    /// Optional reference to the wallet this event belongs to.
    pub wallet_id: Option<WalletId>,
    /// Kind-specific freeform payload.
    pub details: serde_json::Value,
    /// Ed25519 signature over the canonical pre-image
    /// `(prev_event_hash || event_id_bytes || kind_byte || details_json)`,
    /// produced by the audit sink's server key.
    #[serde(with = "hex_bytes")]
    pub server_signature: Vec<u8>,
}

impl AuditEvent {
    /// The canonical bytes that `server_signature` covers. Exposed so
    /// external verifiers can re-check without re-implementing the layout.
    #[must_use]
    pub fn signing_preimage(
        prev_event_hash: &[u8; 32],
        event_id: &EventId,
        kind: AuditKind,
        details: &serde_json::Value,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 32 + 1 + 64);
        buf.extend_from_slice(prev_event_hash);
        buf.extend_from_slice(event_id.to_string().as_bytes());
        buf.push(b'|');
        buf.push(kind_byte(kind));
        buf.push(b'|');
        // Use canonical serialization (sorted keys via serde_json's default).
        serde_json::to_writer(&mut buf, details).unwrap_or(());
        buf
    }
}

/// Stable single-byte tag for each `AuditKind`. Bumping these is a breaking
/// change to the signed preimage; do not renumber without versioning.
#[must_use]
pub const fn kind_byte(k: AuditKind) -> u8 {
    match k {
        AuditKind::WalletCreated => 1,
        AuditKind::WalletRevoked => 2,
        AuditKind::SigningRequested => 3,
        AuditKind::SigningEvaluated => 4,
        AuditKind::QuorumNotified => 5,
        AuditKind::QuorumApprovalReceived => 6,
        AuditKind::QuorumApprovalRejected => 7,
        AuditKind::QuorumTimedOut => 8,
        AuditKind::SigningAttempted => 9,
        AuditKind::SigningSucceeded => 10,
        AuditKind::SigningFailed => 11,
        AuditKind::PolicyChanged => 12,
        AuditKind::ApproverSetChanged => 13,
        AuditKind::SystemError => 14,
        AuditKind::EnclaveAttested => 15,
    }
}

mod hex_array_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s).map_err(serde::de::Error::custom)?;
        v.as_slice()
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
