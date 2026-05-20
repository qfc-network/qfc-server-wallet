//! Daily on-chain anchor commit (stub).
//!
//! See `docs/server-wallet-rfc.md` §2.6: every 24h the server publishes the
//! current audit-chain head as a small on-chain transaction so even chain
//! operators cannot quietly rewrite history.
//!
//! M2 P2 ships the **read side** of this contract:
//!
//! 1. [`anchor_payload`] reads the latest row from `audit_events`, recomputes
//!    `SHA256(preimage ‖ signature)` exactly the way [`PostgresAuditSink`]
//!    advances its chain head, and returns the payload an anchor submitter
//!    would publish.
//! 2. [`daily_anchor_commit_job`] spawns a tokio task that wakes at a
//!    configurable cadence (default: every 24 hours) and invokes a
//!    user-supplied submitter callback.
//!
//! M3 wires the submitter to `qfc-core` so the payload actually lands on
//! chain. In M2 the callback is just a `Fn` that callers can stub for tests
//! or use to write the payload to a file / stdout for manual verification.
//!
//! [`PostgresAuditSink`]: crate::postgres::PostgresAuditSink

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPool;
use sqlx::Row;

use crate::event::{AuditEvent, AuditKind};
use crate::sink::AuditError;
use qfc_wallet_types::EventId;

/// One day's worth of anchor commitment, ready to be submitted on-chain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorPayload {
    /// `YYYY-MM-DD` (UTC) — the day this anchor was *built* for. The
    /// scheduler invokes [`anchor_payload`] once per day so this doubles as
    /// a natural primary key.
    pub date_utc: String,
    /// Hex of `SHA256(preimage ‖ signature)` of the latest audit event,
    /// i.e. the value the *next* emit would use for its `prev_event_hash`.
    /// 64 hex chars / 32 bytes. Empty chain returns 64 zero hex chars.
    pub chain_head_hex: String,
    /// `event_id` of the latest event the anchor commits to. `None` if the
    /// chain is empty.
    pub head_event_id: Option<EventId>,
    /// Number of events in the chain at the time the anchor was built. The
    /// submitter typically includes this in the on-chain memo so verifiers
    /// can detect retroactive truncation.
    pub event_count: u64,
}

/// Compute the current anchor payload.
///
/// This is a pure read; the chain head is reconstructed from the row's own
/// fields rather than trusting any cached value. Safe to call concurrently
/// with emits — at worst the returned payload is one event stale.
///
/// # Errors
///
/// `AuditError::Io` on query failure, `AuditError::Serde` on a malformed
/// row.
pub async fn anchor_payload(pool: &PgPool) -> Result<AnchorPayload, AuditError> {
    let date_utc = Utc::now().format("%Y-%m-%d").to_string();

    // Count comes first so it doesn't race with a concurrent emit landing
    // a row right after we read the head — the worst case is `event_count`
    // being one ahead of `chain_head_hex`, which is harmless (the
    // committed chain prefix is still verifiable).
    let count_row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
        .fetch_one(pool)
        .await
        .map_err(|e| AuditError::Io(format!("anchor count: {e}")))?;
    let event_count = u64::try_from(count_row.0)
        .map_err(|_| AuditError::Io("negative count from postgres".into()))?;

    let head_row = sqlx::query(
        "SELECT event_id, kind, details, prev_event_hash, server_signature
           FROM audit_events
          ORDER BY timestamp_unix_ms DESC, event_id DESC
          LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .map_err(|e| AuditError::Io(format!("anchor head select: {e}")))?;

    let (chain_head_hex, head_event_id) = if let Some(row) = head_row {
        let event_id_s: String = row
            .try_get("event_id")
            .map_err(|e| AuditError::Io(format!("anchor head event_id: {e}")))?;
        let kind_i: i16 = row
            .try_get("kind")
            .map_err(|e| AuditError::Io(format!("anchor head kind: {e}")))?;
        let details: serde_json::Value = row
            .try_get("details")
            .map_err(|e| AuditError::Io(format!("anchor head details: {e}")))?;
        let prev: Vec<u8> = row
            .try_get("prev_event_hash")
            .map_err(|e| AuditError::Io(format!("anchor head prev_event_hash: {e}")))?;
        let sig: Vec<u8> = row
            .try_get("server_signature")
            .map_err(|e| AuditError::Io(format!("anchor head signature: {e}")))?;

        let event_id = EventId::from_str(&event_id_s)
            .map_err(|e| AuditError::Serde(format!("anchor head event_id parse: {e}")))?;
        let kind = kind_from_byte_local(
            u8::try_from(kind_i)
                .map_err(|_| AuditError::Serde(format!("anchor head kind byte: {kind_i}")))?,
        )?;
        let prev_arr: [u8; 32] = prev
            .as_slice()
            .try_into()
            .map_err(|_| AuditError::Serde("anchor head prev_event_hash not 32 bytes".into()))?;

        let preimage = AuditEvent::signing_preimage(&prev_arr, &event_id, kind, &details);
        let mut h = Sha256::new();
        h.update(&preimage);
        h.update(&sig);
        let digest: [u8; 32] = h.finalize().into();
        (hex::encode(digest), Some(event_id))
    } else {
        (hex::encode([0u8; 32]), None)
    };

    Ok(AnchorPayload {
        date_utc,
        chain_head_hex,
        head_event_id,
        event_count,
    })
}

// Local copy of `postgres::kind_from_byte` — keeping it private avoids
// re-exporting an internal helper. Tiny enough to duplicate.
fn kind_from_byte_local(b: u8) -> Result<AuditKind, AuditError> {
    Ok(match b {
        1 => AuditKind::WalletCreated,
        2 => AuditKind::WalletRevoked,
        3 => AuditKind::SigningRequested,
        4 => AuditKind::SigningEvaluated,
        5 => AuditKind::QuorumNotified,
        6 => AuditKind::QuorumApprovalReceived,
        7 => AuditKind::QuorumApprovalRejected,
        8 => AuditKind::QuorumTimedOut,
        9 => AuditKind::SigningAttempted,
        10 => AuditKind::SigningSucceeded,
        11 => AuditKind::SigningFailed,
        12 => AuditKind::PolicyChanged,
        13 => AuditKind::ApproverSetChanged,
        14 => AuditKind::SystemError,
        15 => AuditKind::EnclaveAttested,
        other => {
            return Err(AuditError::Serde(format!(
                "anchor: unknown audit kind byte: {other}"
            )))
        }
    })
}

/// Default cadence between anchor submissions. 24h per RFC §2.6.
pub const DEFAULT_ANCHOR_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Spawn the daily anchor-commit loop.
///
/// The returned [`tokio::task::JoinHandle`] runs forever (until cancelled)
/// and invokes `submit` once per `interval` with the most recent
/// [`AnchorPayload`].
///
/// `submit` is an `async` callback so M3 can implement it as a `qfc-core`
/// transaction broadcast; in M2 it's typically a writer that appends to a
/// JSONL audit-anchor log file.
///
/// On submit failure the loop logs at WARN and continues — this is a
/// best-effort cron, not a strong-consistency operation.
pub fn daily_anchor_commit_job<F, Fut>(
    pool: PgPool,
    interval: Duration,
    submit: F,
) -> tokio::task::JoinHandle<()>
where
    F: Fn(AnchorPayload) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Result<(), AuditError>> + Send + 'static,
{
    let submit = Arc::new(submit);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // Fire once immediately so the first tick doesn't wait `interval`.
        // tokio::time::interval is configured this way by default; we set
        // missed-tick policy to Delay so we don't burst on long sleeps.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            match anchor_payload(&pool).await {
                Ok(payload) => {
                    if let Err(e) = (submit)(payload).await {
                        tracing::warn!(error = %e, "anchor submit failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "anchor payload read failed");
                }
            }
        }
    })
}
