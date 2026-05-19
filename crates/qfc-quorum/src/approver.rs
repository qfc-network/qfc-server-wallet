//! The `QuorumApprover` trait + errors.

use std::time::Duration;

use async_trait::async_trait;
use qfc_wallet_types::RequestId;
use thiserror::Error;

use crate::approval::{ApprovalRequest, ApprovalVerifyError, SignedApproval};
use crate::identity::ApproverIdentity;

/// Errors raised by quorum coordination.
#[derive(Debug, Error)]
pub enum QuorumError {
    /// Underlying transport failed (webhook delivery, queue, etc.).
    #[error("quorum transport error: {0}")]
    Transport(String),

    /// Approval collection timed out before threshold was reached.
    #[error("quorum timed out after {0:?}")]
    Timeout(Duration),

    /// An approval failed verification.
    #[error("invalid approval: {0}")]
    InvalidApproval(#[from] ApprovalVerifyError),

    /// Caller asked for `verify_approval` against an identity the approver
    /// set doesn't include.
    #[error("unknown approver: {0}")]
    UnknownApprover(String),
}

/// Approver-coordination interface.
#[async_trait]
pub trait QuorumApprover: Send + Sync {
    /// Notify the approvers of a pending signing request.
    ///
    /// # Errors
    ///
    /// `QuorumError::Transport` if the notification channel fails.
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError>;

    /// Block until `threshold` *Approve* approvals are collected for
    /// `request_id`, or `timeout` elapses, or any *Reject* arrives.
    /// Returns the collected approvals (only Approve outcomes if the
    /// threshold was reached; the first Reject otherwise propagates as
    /// `Ok(vec![reject])` so callers can audit it).
    ///
    /// # Errors
    ///
    /// `QuorumError::Timeout` if the deadline passes before threshold is
    /// reached. `QuorumError::InvalidApproval` if any candidate approval
    /// fails verification.
    async fn collect_approvals(
        &self,
        request_id: &RequestId,
        threshold: u8,
        timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError>;

    /// Verify a single approval against an expected approver identity.
    /// This is the hook the enclave uses (RFC §4.3) — the enclave does
    /// not trust the host's count, it re-verifies each signature.
    ///
    /// # Errors
    ///
    /// `QuorumError::InvalidApproval` if the signature does not verify or
    /// the request / message / approver does not match.
    fn verify_approval(
        &self,
        approval: &SignedApproval,
        expected: &ApproverIdentity,
        expected_message_hash: &[u8; 32],
        now_unix_ms: i64,
    ) -> Result<(), QuorumError> {
        if expected != &approval.approver {
            return Err(QuorumError::UnknownApprover(approval.approver.key()));
        }
        approval
            .verify(&approval.request_id, expected_message_hash, now_unix_ms)
            .map_err(QuorumError::from)
    }
}
