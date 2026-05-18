//! Shared types for the QFC server wallet workspace.
//!
//! See `docs/server-wallet-rfc.md` §3 (data model). This crate intentionally
//! contains *only* type definitions — no I/O, no async, no behavior beyond
//! parsing / formatting / zeroization. Subordinate crates (`qfc-enclave`,
//! `qfc-sss`, `qfc-policy`, `qfc-quorum`, `qfc-audit`) depend on this for
//! cross-crate identifiers and primitive enums.
//!
//! Crate status: pre-M1 / M1. Re-exports may grow as M1 lands but the public
//! surface is intentionally small.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

mod errors;
mod hd_path;
mod ids;
mod scheme;
mod secret;

pub use errors::{ParseError, TypeError};
pub use hd_path::{HdPath, HdPathSegment};
pub use ids::{ApprovalId, DecisionId, EventId, OwnerId, PolicyId, RequestId, ShareId, WalletId};
pub use scheme::{HashAlg, SigningScheme};
pub use secret::SecretBytes;
