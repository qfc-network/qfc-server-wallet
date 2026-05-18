//! `qfc-audit` — hash-chained audit log. See `docs/server-wallet-rfc.md` §2.6.
//!
//! Status: pre-M1 skeleton; trait + `FileAuditSink` land in M1, Postgres / Kafka in M2.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
