//! Approver and approver-set registry. See RFC §2.5 and `docs/m4-decisions.md`.
//!
//! `ApproverRegistry` is the M4 admin surface for:
//!
//! - Adding an approver (a person/key/hardware token/nested-wallet)
//! - Revoking an approver (soft-delete; record retained for audit)
//! - Listing approvers belonging to one tenant (`OwnerId`)
//! - Creating an *approver set*: an ordered roster + `(threshold, total)`
//!   that the policy engine references by `ApproverSetId`
//! - Cycle detection on `NestedWallet` membership at create-set time, plus
//!   a hard cap on nesting depth (`MAX_NESTING_DEPTH = 3`).
//!
//! Two backends ship in M4:
//!
//! - `MemoryApproverRegistry` — `tokio::sync::RwLock<HashMap>` for tests/dev
//! - `PostgresApproverRegistry` — sqlx-backed durable backend with the
//!   `approvers` + `approver_sets` + `approver_set_members` tables (see
//!   `migrations/0002_approvers.sql`).

pub mod memory;
pub mod postgres;
pub mod types;

#[cfg(test)]
mod tests;

pub use memory::MemoryApproverRegistry;
pub use postgres::{PostgresApproverRegistry, REGISTRY_MIGRATOR};
pub use types::{
    ApproverCreate, ApproverRecord, ApproverRegistry, ApproverSet, ApproverSetCreate,
    ApproverStatus, RegistryError, MAX_NESTING_DEPTH,
};
