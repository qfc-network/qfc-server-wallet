//! Trait + data types for the approver registry.

use async_trait::async_trait;
use qfc_wallet_types::{ApproverId, ApproverSetId, OwnerId, SigningScheme, WalletId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::identity::ApproverIdentity;

/// Maximum nesting depth of `NestedWallet` approvers. RFC §2.5 mandates a
/// bounded recursion limit; this is the hard ceiling.
pub const MAX_NESTING_DEPTH: u8 = 3;

/// Lifecycle status of an approver record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverStatus {
    /// Approver is eligible to sign approvals.
    Active,
    /// Approver was revoked. The record is retained for audit; the registry
    /// will not return it from active-only lookups and approver sets that
    /// reference it become unusable until rebuilt.
    Revoked,
}

/// A single registered approver. Carries the identity (incl. public key)
/// and an operator-facing label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRecord {
    /// Stable ULID for this approver (separate from the identity's natural key).
    pub approver_id: ApproverId,
    /// The approver-side identity. Owns the public key the server verifies against.
    pub identity: ApproverIdentity,
    /// Curve. Redundant with `identity.scheme()` but stored for query convenience.
    pub scheme: SigningScheme,
    /// Operator-facing label, e.g. "alice@treasury".
    pub label: String,
    /// Owning tenant.
    pub owner_id: OwnerId,
    /// Optional webhook URL the `WebhookApprover` will POST to. None = approver
    /// is notified out-of-band (e.g. hardware client polls).
    pub webhook_url: Option<String>,
    /// Lifecycle status.
    pub status: ApproverStatus,
    /// Unix-millisecond timestamp of registration.
    pub added_at_unix_ms: i64,
}

/// Approver-set membership: an ordered roster + `(threshold, total)`. This
/// is what `WalletService::sign` looks up when the policy decision is
/// `RequireQuorum { approver_set, .. }`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverSet {
    /// Stable ULID for this set.
    pub id: ApproverSetId,
    /// Human-readable set name.
    pub name: String,
    /// Owning tenant.
    pub owner_id: OwnerId,
    /// Member approver ids. Order is preserved (audit-friendly); membership
    /// must be unique.
    pub members: Vec<ApproverId>,
    /// Minimum approvals required to clear the set (`>= 1`).
    pub threshold: u8,
    /// Total members. `members.len() == total`.
    pub total: u8,
    /// Default quorum-collection timeout in seconds. Falls back to the
    /// service-level default if `None`.
    pub quorum_timeout_secs: Option<u32>,
    /// Unix-millisecond timestamp of creation.
    pub created_at_unix_ms: i64,
}

/// Inputs for `ApproverRegistry::add_approver`. Same shape as
/// `ApproverRecord` but without the bookkeeping fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverCreate {
    /// Identity (incl. public key + scheme).
    pub identity: ApproverIdentity,
    /// Operator-facing label.
    pub label: String,
    /// Owning tenant.
    pub owner_id: OwnerId,
    /// Optional webhook URL.
    pub webhook_url: Option<String>,
}

/// Inputs for `ApproverRegistry::create_approver_set`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverSetCreate {
    /// Human-readable name.
    pub name: String,
    /// Owning tenant.
    pub owner_id: OwnerId,
    /// Member approver ids (ordered, unique).
    pub members: Vec<ApproverId>,
    /// Minimum approvals.
    pub threshold: u8,
    /// Total members. Must equal `members.len()`.
    pub total: u8,
    /// Default per-set quorum timeout (seconds). `None` falls back to the
    /// `WalletService` default.
    pub quorum_timeout_secs: Option<u32>,
}

/// Errors raised by the approver registry.
#[derive(Debug, Error)]
pub enum RegistryError {
    /// Underlying backend I/O failed.
    #[error("registry I/O error: {0}")]
    Io(String),

    /// Approver id not found.
    #[error("approver not found: {0}")]
    ApproverNotFound(ApproverId),

    /// Approver set id not found.
    #[error("approver set not found: {0}")]
    ApproverSetNotFound(ApproverSetId),

    /// One of the listed members is unknown.
    #[error("approver set references unknown approver: {0}")]
    UnknownMember(ApproverId),

    /// One of the listed members has been revoked.
    #[error("approver set references revoked approver: {0}")]
    RevokedMember(ApproverId),

    /// `members.len()` did not match `total`.
    #[error("approver set membership / total mismatch: members={members}, total={total}")]
    MemberCountMismatch {
        /// Number of members supplied.
        members: usize,
        /// Declared total.
        total: u8,
    },

    /// `threshold` was zero or greater than `total`.
    #[error("invalid threshold {threshold} for total {total}")]
    InvalidThreshold {
        /// Supplied threshold.
        threshold: u8,
        /// Declared total.
        total: u8,
    },

    /// Duplicate member in the supplied list.
    #[error("approver set members must be unique; duplicate: {0}")]
    DuplicateMember(ApproverId),

    /// Cycle detected through nested-wallet membership.
    #[error("nested-wallet membership induces a cycle through wallet {0}")]
    NestingCycle(WalletId),

    /// Nesting depth exceeds `MAX_NESTING_DEPTH`.
    #[error("nested-wallet membership exceeds max nesting depth {0}")]
    NestingTooDeep(u8),
}

/// Admin surface for managing approvers and approver-sets.
#[async_trait]
pub trait ApproverRegistry: Send + Sync {
    /// Register a new approver. Returns the freshly-allocated record.
    async fn add_approver(&self, create: ApproverCreate) -> Result<ApproverRecord, RegistryError>;

    /// Mark an approver as revoked. Idempotent.
    async fn revoke_approver(&self, id: ApproverId) -> Result<(), RegistryError>;

    /// Fetch an approver by id. Returns even revoked approvers; callers
    /// inspect `status` to gate behavior.
    async fn get_approver(&self, id: ApproverId) -> Result<ApproverRecord, RegistryError>;

    /// List approvers for an owner. `include_revoked` controls whether
    /// soft-deleted entries are surfaced.
    async fn list_approvers_by_owner(
        &self,
        owner: &OwnerId,
        include_revoked: bool,
    ) -> Result<Vec<ApproverRecord>, RegistryError>;

    /// Create a new approver set. Walks the nested-wallet graph to detect
    /// cycles (rejecting if any member is itself the wallet under
    /// construction or reaches it transitively) and enforces
    /// `MAX_NESTING_DEPTH`.
    async fn create_approver_set(
        &self,
        create: ApproverSetCreate,
    ) -> Result<ApproverSet, RegistryError>;

    /// Fetch an approver set by id.
    async fn get_approver_set(&self, id: ApproverSetId) -> Result<ApproverSet, RegistryError>;

    /// List approver sets owned by `owner`.
    async fn list_approver_sets(&self, owner: &OwnerId) -> Result<Vec<ApproverSet>, RegistryError>;
}

/// Validate `(threshold, total)` against members and shape. Returns
/// `RegistryError::*` on any structural problem.
pub(crate) fn validate_set_shape(create: &ApproverSetCreate) -> Result<(), RegistryError> {
    if create.threshold == 0 || create.threshold > create.total {
        return Err(RegistryError::InvalidThreshold {
            threshold: create.threshold,
            total: create.total,
        });
    }
    if create.members.len() != create.total as usize {
        return Err(RegistryError::MemberCountMismatch {
            members: create.members.len(),
            total: create.total,
        });
    }
    let mut seen = std::collections::HashSet::with_capacity(create.members.len());
    for m in &create.members {
        if !seen.insert(*m) {
            return Err(RegistryError::DuplicateMember(*m));
        }
    }
    Ok(())
}
