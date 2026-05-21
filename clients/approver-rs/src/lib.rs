//! `qfc-approver` — reference approver-side client for the QFC server wallet.
//!
//! This library powers the `qfc-approver` binary; it is also exposed so
//! that integrators can embed the webhook receiver / approval signer into
//! their own daemon. The crate is intentionally outside the main
//! `qfc-server-wallet` workspace so forks don't inherit the wallet's
//! dependency tree.
//!
//! See `clients/README.md` for the rationale and security notes.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod audit;
pub mod processor;
pub mod prompt;
pub mod signer_loader;
pub mod webhook_handler;
pub mod wire;

pub use processor::{Decision, DecisionPolicy, ProcessOutcome, Processor, ProcessorConfig};
pub use signer_loader::{load_secret, ApproverSigner};
pub use webhook_handler::{router, AppState, WebhookError};
pub use wire::{ApprovalRequestWire, ApproverIdentityWire, SigningSchemeWire, SubmitApprovalWire};
