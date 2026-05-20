//! Approval submission store. Persists `SignedApproval`s with replay
//! protection (unique `(request_id, approver_id)`).
//!
//! See RFC §4.3 and `docs/m4-decisions.md`. The store is independent of
//! the `QuorumApprover` trait: it persists, the approver coordinates.

pub mod memory;
pub mod postgres;

use async_trait::async_trait;
use qfc_wallet_types::{ApproverId, RequestId};
use thiserror::Error;

use crate::approval::SignedApproval;

pub use memory::MemoryApprovalStore;
pub use postgres::PostgresApprovalStore;

/// Errors raised by an `ApprovalStore`.
#[derive(Debug, Error)]
pub enum StoreError {
    /// Underlying I/O failure.
    #[error("approval store I/O: {0}")]
    Io(String),

    /// A *different* approval payload for the same `(request_id,
    /// approver_id)` is already on record. Idempotent re-submission of the
    /// SAME payload is success, not error — implementations compare
    /// `approval_id` to disambiguate.
    #[error("duplicate approval: {0} already recorded a decision for request {1}")]
    DuplicateApproval(ApproverId, RequestId),
}

/// Outcome of `record_approval`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOutcome {
    /// First time we've seen this approval — persisted.
    Inserted,
    /// Already on record with the *same* `approval_id`; treated as
    /// idempotent success.
    AlreadyRecorded,
}

/// Trait for persisting submitted approvals.
#[async_trait]
pub trait ApprovalStore: Send + Sync {
    /// Persist `approval`. Returns whether this is the first persistence
    /// (`Inserted`) or an idempotent re-submission (`AlreadyRecorded`).
    ///
    /// # Errors
    ///
    /// - `StoreError::DuplicateApproval` when a DIFFERENT approval payload
    ///   already exists for the same `(request_id, approver_id)`.
    /// - `StoreError::Io` for backend failures.
    async fn record_approval(
        &self,
        approval: &SignedApproval,
        approver_id: ApproverId,
    ) -> Result<RecordOutcome, StoreError>;

    /// All approvals on record for `request_id`. Order: insertion order.
    async fn list_for_request(
        &self,
        request_id: RequestId,
    ) -> Result<Vec<SignedApproval>, StoreError>;
}
