//! `qfc-server-wallet` — top-level orchestrator.
//!
//! Wires together the five service crates (`qfc-enclave`, `qfc-sss`,
//! `qfc-policy`, `qfc-quorum`, `qfc-audit`) into a single
//! `WalletService` API. See `docs/server-wallet-rfc.md` §1 and §4.
//!
//! M1 ships the in-process happy path:
//!   * `create_wallet` → policy validate → enclave generate → share store persist → audit
//!   * `sign` → audit request → policy evaluate → (quorum if required) →
//!     enclave sign → audit success
//!
//! HTTP / gRPC surfaces land in M2 (RFC §7).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod service;
pub mod wallet;

pub use service::{ServiceError, WalletService};
pub use wallet::{WalletConfig, WalletRecord};
