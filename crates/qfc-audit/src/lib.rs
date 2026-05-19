//! `qfc-audit` — hash-chained audit log. See `docs/server-wallet-rfc.md` §2.6.
//!
//! Status:
//! - M1: `AuditSink` async trait + `FileAuditSink` (append-only NDJSON with
//!   hash chain + ed25519 server signature).
//! - M2: Postgres / Kafka backends, daily on-chain anchor commitment.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod event;
pub mod file;
pub mod sink;

pub use event::{Actor, AuditEvent, AuditKind};
pub use file::FileAuditSink;
pub use sink::{AuditError, AuditSink};
