//! `qfc-quorum` — M-of-N approver coordination. See
//! `docs/server-wallet-rfc.md` §2.5.
//!
//! Status:
//! - M1: `QuorumApprover` trait, `ApproverIdentity` (4 variants per RFC
//!   decision #3), `SignedApproval`, `MockQuorumApprover` for test-time
//!   approval injection.
//! - M4: real notification channels (webhook + email + on-chain), bug-bounty
//!   launch, approver-side reference client.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod approval;
pub mod approver;
pub mod identity;
pub mod mock;

pub use approval::{
    ApprovalDecision, ApprovalRequest, ApprovalVerifyError, SignedApproval, MAX_APPROVAL_AGE_SECS,
};
pub use approver::{QuorumApprover, QuorumError};
pub use identity::{ApproverIdentity, HardwareApproverHandle};
pub use mock::MockQuorumApprover;
