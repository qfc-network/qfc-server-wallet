//! `SignedApproval` shape + verification.

use qfc_enclave::{dispatch_signer, SignerError};
use qfc_wallet_types::{ApprovalId, HashAlg, RequestId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::identity::ApproverIdentity;

/// Maximum age of an approval before the enclave will reject it as stale.
/// 1 hour. Real M4 deployments may pin tighter / per-wallet windows.
pub const MAX_APPROVAL_AGE_SECS: i64 = 3600;

/// Approve or reject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    /// The approver approves the signing.
    Approve,
    /// The approver rejects the signing.
    Reject,
}

/// One approver's signed decision over a pending signing request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedApproval {
    /// Stable identifier for this approval action (audit-friendly).
    pub approval_id: ApprovalId,
    /// Approver identity. Carries the public key the signature must verify against.
    pub approver: ApproverIdentity,
    /// Request being approved.
    pub request_id: RequestId,
    /// SHA-256 of the message being signed by the *signing wallet*. Bound
    /// into the approval signature so an approval can only ever authorise
    /// the specific operation that was shown to the approver.
    #[serde(with = "hex_array_32")]
    pub message_hash: [u8; 32],
    /// Approve or reject.
    pub decision: ApprovalDecision,
    /// Unix-millisecond timestamp at which the approver signed.
    pub timestamp_unix_ms: i64,
    /// Signature over the canonical preimage (see `signing_preimage`).
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
}

impl SignedApproval {
    /// Canonical bytes that `signature` covers. Exposed so external
    /// verifiers (and the enclave) can compute it without re-implementing
    /// the layout.
    #[must_use]
    pub fn signing_preimage(
        approval_id: &ApprovalId,
        request_id: &RequestId,
        message_hash: &[u8; 32],
        decision: ApprovalDecision,
        timestamp_unix_ms: i64,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(26 + 26 + 32 + 1 + 8);
        buf.extend_from_slice(approval_id.to_string().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(request_id.to_string().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(message_hash);
        buf.push(b'|');
        buf.push(match decision {
            ApprovalDecision::Approve => 0x01,
            ApprovalDecision::Reject => 0x00,
        });
        buf.push(b'|');
        buf.extend_from_slice(&timestamp_unix_ms.to_be_bytes());
        buf
    }

    /// The canonical preimage for *this* approval.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        Self::signing_preimage(
            &self.approval_id,
            &self.request_id,
            &self.message_hash,
            self.decision,
            self.timestamp_unix_ms,
        )
    }

    /// Verify this approval against the embedded approver's public key.
    ///
    /// # Errors
    ///
    /// `ApprovalVerifyError::Stale` if the approval is older than
    /// `MAX_APPROVAL_AGE_SECS` relative to `now_unix_ms`,
    /// `ApprovalVerifyError::WrongRequest` if `expected_request_id` does
    /// not match, `ApprovalVerifyError::WrongMessage` if
    /// `expected_message_hash` does not match,
    /// `ApprovalVerifyError::Signer` for any verification failure.
    pub fn verify(
        &self,
        expected_request_id: &RequestId,
        expected_message_hash: &[u8; 32],
        now_unix_ms: i64,
    ) -> Result<(), ApprovalVerifyError> {
        if &self.request_id != expected_request_id {
            return Err(ApprovalVerifyError::WrongRequest);
        }
        if &self.message_hash != expected_message_hash {
            return Err(ApprovalVerifyError::WrongMessage);
        }
        let age_ms = now_unix_ms.saturating_sub(self.timestamp_unix_ms);
        if age_ms < 0 {
            return Err(ApprovalVerifyError::FromTheFuture);
        }
        if age_ms / 1000 > MAX_APPROVAL_AGE_SECS {
            return Err(ApprovalVerifyError::Stale);
        }
        let preimage = self.preimage();
        dispatch_signer(self.approver.scheme(), |signer| {
            signer.verify(
                self.approver.public_key(),
                &preimage,
                &self.signature,
                hash_alg_for(self.approver.scheme()),
            )
        })?;
        Ok(())
    }
}

/// Choose the hash pre-image alg for a given scheme so verifiers agree with
/// the approver client.
#[must_use]
pub fn hash_alg_for(scheme: qfc_wallet_types::SigningScheme) -> HashAlg {
    use qfc_wallet_types::SigningScheme;
    match scheme {
        SigningScheme::Ed25519
        | SigningScheme::MlDsa44
        | SigningScheme::MlDsa65
        | SigningScheme::MlDsa87 => HashAlg::None,
        SigningScheme::Secp256k1 | SigningScheme::Secp256k1Recoverable => HashAlg::Sha256,
    }
}

/// A pending signing request shown to approvers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    /// Signing-request identifier.
    pub request_id: RequestId,
    /// SHA-256 of the message the signing wallet would sign.
    #[serde(with = "hex_array_32")]
    pub message_hash: [u8; 32],
    /// Set of approvers that need to weigh in.
    pub approver_set: Vec<ApproverIdentity>,
    /// Minimum approvals required.
    pub threshold: u8,
}

impl ApprovalRequest {
    /// Convenience helper: compute `message_hash = SHA-256(message)`.
    #[must_use]
    pub fn message_hash_for(message: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(message);
        h.finalize().into()
    }
}

/// Errors raised by `SignedApproval::verify`.
#[derive(Debug, Error)]
pub enum ApprovalVerifyError {
    /// The approval references a different request than expected.
    #[error("approval is for a different request_id")]
    WrongRequest,

    /// The approval binds a different message hash than expected.
    #[error("approval is for a different message_hash")]
    WrongMessage,

    /// The approval was signed too long ago.
    #[error("approval is stale")]
    Stale,

    /// The approval is timestamped in the future.
    #[error("approval timestamp is in the future")]
    FromTheFuture,

    /// The underlying signer rejected the signature.
    #[error("signer verification failed: {0}")]
    Signer(#[from] SignerError),
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
