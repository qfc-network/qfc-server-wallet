//! The `AuditSink` trait + `AuditError`.

use async_trait::async_trait;
use thiserror::Error;

use crate::event::AuditEvent;

/// Errors raised by an `AuditSink`.
#[derive(Debug, Error)]
pub enum AuditError {
    /// I/O failure on the underlying backend.
    #[error("audit I/O error: {0}")]
    Io(String),

    /// Serialization failed.
    #[error("audit serialization error: {0}")]
    Serde(String),

    /// Cryptographic failure (server signing key, etc.).
    #[error("audit crypto error: {0}")]
    Crypto(&'static str),
}

/// Append-only audit log. Implementations MUST persist events durably
/// before returning success.
#[async_trait]
pub trait AuditSink: Send + Sync {
    /// Emit a single event. The sink stamps `event_id`, `prev_event_hash`,
    /// `timestamp`, and `server_signature` — the caller fills the rest.
    /// Returns the stamped event so callers can include it in responses.
    ///
    /// # Errors
    ///
    /// `AuditError::Io` / `AuditError::Serde` / `AuditError::Crypto`.
    async fn emit(&self, draft: AuditEventDraft) -> Result<AuditEvent, AuditError>;

    /// Emit a batch. Default impl loops, preserving order.
    ///
    /// # Errors
    ///
    /// Returns the first emit error encountered; events already emitted
    /// remain persisted.
    async fn emit_batch(
        &self,
        drafts: Vec<AuditEventDraft>,
    ) -> Result<Vec<AuditEvent>, AuditError> {
        let mut out = Vec::with_capacity(drafts.len());
        for d in drafts {
            out.push(self.emit(d).await?);
        }
        Ok(out)
    }
}

/// The portion of an audit event the caller supplies. The sink fills in
/// the bookkeeping fields (`event_id`, `prev_event_hash`, `timestamp`,
/// `server_signature`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEventDraft {
    /// Who produced the event.
    pub actor: crate::Actor,
    /// Event classification.
    pub kind: crate::AuditKind,
    /// Optional signing-request reference.
    pub request_id: Option<qfc_wallet_types::RequestId>,
    /// Optional wallet reference.
    pub wallet_id: Option<qfc_wallet_types::WalletId>,
    /// Kind-specific payload.
    pub details: serde_json::Value,
}
