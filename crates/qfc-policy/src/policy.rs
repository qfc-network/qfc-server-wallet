//! The `Policy` trait.

use async_trait::async_trait;

use crate::decision::{PolicyDecision, PolicyError};
use crate::request::SigningRequest;

/// The policy evaluation surface.
///
/// A `Policy` reads a `SigningRequest` and emits a `PolicyDecision`. The
/// trait is async to leave room for backends that consult an external
/// service (database, remote signer, on-chain state). The M1 in-memory
/// `StaticAllowDenyPolicy` is trivially async.
#[async_trait]
pub trait Policy: Send + Sync {
    /// Evaluate a signing request. Implementations MUST be deterministic
    /// modulo wall-clock time (for time-window rules in M2+).
    ///
    /// # Errors
    ///
    /// `PolicyError::Misconfiguration` if the underlying configuration is
    /// internally inconsistent (e.g. an allow list referencing a chain
    /// not declared in the wallet schema). `PolicyError::Internal` for
    /// unexpected backend failures.
    async fn evaluate(&self, request: &SigningRequest) -> Result<PolicyDecision, PolicyError>;
}
