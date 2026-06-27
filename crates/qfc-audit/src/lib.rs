//! `qfc-audit` — hash-chained audit log. See `docs/server-wallet-rfc.md` §2.6.
//!
//! Status:
//! - M1: `AuditSink` async trait + `FileAuditSink` (append-only NDJSON with
//!   hash chain + ed25519 server signature).
//! - M2 P2: `PostgresAuditSink` + anchor-commit stub. Kafka backend deferred.
//! - On-chain anchor: [`ChainAnchor`] submits the daily commitment via the
//!   EVM JSON-RPC (`eth_sendRawTransaction`) — no `qfc-core` workspace dep.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod anchor;
pub mod chain_anchor;
pub mod event;
pub mod file;
pub mod postgres;
pub mod sink;

pub use anchor::{
    anchor_payload, anchor_preimage, daily_anchor_commit_job, daily_anchor_commit_job_with_reader,
    AnchorJsonl, AnchorPayload, LocalFileAnchor, DEFAULT_ANCHOR_INTERVAL,
};
pub use chain_anchor::{ChainAnchor, DEFAULT_ANCHOR_GAS_LIMIT};
pub use event::{Actor, AuditEvent, AuditKind};
pub use file::{replay_verify, verify_event, FileAuditSink};
pub use postgres::{replay_verify_postgres, PostgresAuditSink};
pub use sink::{AuditError, AuditEventDraft, AuditSink};
