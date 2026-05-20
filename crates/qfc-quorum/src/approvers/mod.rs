//! Real-world `QuorumApprover` backends. Replace the M1 `MockQuorumApprover`.
//!
//! Layout:
//!
//! - `webhook`           — `WebhookApprover`: POSTs JSON with HMAC-SHA256.
//! - `onchain`           — `OnChainQfcEventApprover`: STUB. In-memory channel
//!   today; the real chain submitter ships when `qfc-core` deps land.
//! - `hardware`          — `HardwareApproverNotifier`: notification dispatch
//!   only; the hardware client signs.
//! - `orchestrating`     — `OrchestratingApprover`: composes notifiers + a
//!   single `ApprovalStore`. This is what `WalletService` uses.

pub mod hardware;
pub mod onchain;
pub mod orchestrating;
pub mod webhook;

pub use hardware::HardwareApproverNotifier;
pub use onchain::{OnChainEvent, OnChainQfcEventApprover};
pub use orchestrating::{ApproverNotifier, OrchestratingApprover, OrchestratingApproverBuilder};
pub use webhook::{WebhookApprover, WebhookApproverConfig, WebhookSignatureHeader};
