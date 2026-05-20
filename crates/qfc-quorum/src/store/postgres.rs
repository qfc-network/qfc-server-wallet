//! Postgres-backed `ApprovalStore`. Uses the `approvals` table from the
//! M4 migration (`migrations/0002_approvers.sql`).
//!
//! Replay protection lives at the schema layer: a UNIQUE constraint on
//! `(request_id, approver_id)`. Idempotent re-submission of the SAME
//! payload is detected by comparing the `approval_id` against the existing
//! row before inserting.

use std::str::FromStr;

use async_trait::async_trait;
use qfc_wallet_types::{ApprovalId, ApproverId, RequestId, SigningScheme};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;

use crate::approval::{ApprovalDecision, SignedApproval};
use crate::identity::ApproverIdentity;
use crate::store::{ApprovalStore, RecordOutcome, StoreError};

/// Postgres-backed approval store.
pub struct PostgresApprovalStore {
    pool: PgPool,
}

impl PostgresApprovalStore {
    /// Connect to Postgres.
    ///
    /// # Errors
    ///
    /// `StoreError::Io` on connect failure.
    pub async fn connect(db_url: &str) -> Result<Self, StoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(db_url)
            .await
            .map_err(|e| StoreError::Io(format!("postgres connect: {e}")))?;
        Ok(Self { pool })
    }

    /// Build from an existing pool. Shared with `PostgresApproverRegistry`.
    #[must_use]
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Borrow the pool.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl ApprovalStore for PostgresApprovalStore {
    async fn record_approval(
        &self,
        approval: &SignedApproval,
        approver_id: ApproverId,
    ) -> Result<RecordOutcome, StoreError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StoreError::Io(format!("begin tx: {e}")))?;

        // Existing row? Either idempotent or duplicate.
        let existing = sqlx::query(
            "SELECT approval_id FROM approvals WHERE request_id = $1 AND approver_id = $2",
        )
        .bind(approval.request_id.to_string())
        .bind(approver_id.to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| StoreError::Io(format!("check duplicate: {e}")))?;
        if let Some(row) = existing {
            let prev_s: String = row
                .try_get("approval_id")
                .map_err(|e| StoreError::Io(format!("approval_id: {e}")))?;
            let prev = ApprovalId::from_str(&prev_s)
                .map_err(|e| StoreError::Io(format!("approval_id parse: {e}")))?;
            tx.rollback().await.ok();
            return if prev == approval.approval_id {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                Err(StoreError::DuplicateApproval(
                    approver_id,
                    approval.request_id,
                ))
            };
        }

        let identity_json = serde_json::to_value(&approval.approver)
            .map_err(|e| StoreError::Io(format!("identity json: {e}")))?;
        sqlx::query(
            "INSERT INTO approvals
                (approval_id, request_id, approver_id, approver_key, approver_identity,
                 message_hash, decision, signature, timestamp_unix_ms, received_at_unix_ms)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(approval.approval_id.to_string())
        .bind(approval.request_id.to_string())
        .bind(approver_id.to_string())
        .bind(approval.approver.key())
        .bind(&identity_json)
        .bind(approval.message_hash.as_slice())
        .bind(i16::from(decision_byte(approval.decision)))
        .bind(&approval.signature)
        .bind(approval.timestamp_unix_ms)
        .bind(now_unix_ms())
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            // Race-condition path: concurrent insert hit the unique
            // constraint between our SELECT and INSERT.
            let s = e.to_string();
            if s.contains("approvals_request_id_approver_id_key") || s.contains("duplicate key") {
                StoreError::DuplicateApproval(approver_id, approval.request_id)
            } else {
                StoreError::Io(format!("insert approval: {e}"))
            }
        })?;

        tx.commit()
            .await
            .map_err(|e| StoreError::Io(format!("commit approval: {e}")))?;
        Ok(RecordOutcome::Inserted)
    }

    async fn list_for_request(
        &self,
        request_id: RequestId,
    ) -> Result<Vec<SignedApproval>, StoreError> {
        let rows = sqlx::query(
            "SELECT approval_id, approver_identity, message_hash, decision, signature,
                    timestamp_unix_ms
               FROM approvals
              WHERE request_id = $1
              ORDER BY received_at_unix_ms ASC, approval_id ASC",
        )
        .bind(request_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StoreError::Io(format!("list approvals: {e}")))?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let approval_id_s: String = row
                .try_get("approval_id")
                .map_err(|e| StoreError::Io(format!("approval_id: {e}")))?;
            let identity_v: serde_json::Value = row
                .try_get("approver_identity")
                .map_err(|e| StoreError::Io(format!("identity: {e}")))?;
            let identity: ApproverIdentity = serde_json::from_value(identity_v)
                .map_err(|e| StoreError::Io(format!("identity decode: {e}")))?;
            let msg_hash_v: Vec<u8> = row
                .try_get("message_hash")
                .map_err(|e| StoreError::Io(format!("message_hash: {e}")))?;
            let msg_hash: [u8; 32] = msg_hash_v.as_slice().try_into().map_err(|_| {
                StoreError::Io(format!(
                    "message_hash must be 32 bytes, got {}",
                    msg_hash_v.len()
                ))
            })?;
            let decision_i: i16 = row
                .try_get("decision")
                .map_err(|e| StoreError::Io(format!("decision: {e}")))?;
            let signature: Vec<u8> = row
                .try_get("signature")
                .map_err(|e| StoreError::Io(format!("signature: {e}")))?;
            let timestamp: i64 = row
                .try_get("timestamp_unix_ms")
                .map_err(|e| StoreError::Io(format!("timestamp: {e}")))?;

            out.push(SignedApproval {
                approval_id: ApprovalId::from_str(&approval_id_s)
                    .map_err(|e| StoreError::Io(format!("approval_id parse: {e}")))?,
                approver: identity,
                request_id,
                message_hash: msg_hash,
                decision: decision_from_byte(
                    u8::try_from(decision_i)
                        .map_err(|_| StoreError::Io(format!("decision out of u8: {decision_i}")))?,
                )?,
                timestamp_unix_ms: timestamp,
                signature,
            });
        }
        Ok(out)
    }
}

fn decision_byte(d: ApprovalDecision) -> u8 {
    match d {
        ApprovalDecision::Approve => 1,
        ApprovalDecision::Reject => 0,
    }
}

fn decision_from_byte(b: u8) -> Result<ApprovalDecision, StoreError> {
    Ok(match b {
        1 => ApprovalDecision::Approve,
        0 => ApprovalDecision::Reject,
        other => return Err(StoreError::Io(format!("unknown decision byte: {other}"))),
    })
}

fn now_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

// Silence the unused-import warning when this file is compiled
// without the testcontainers integration tests.
#[allow(dead_code)]
fn _force_use_scheme(_s: SigningScheme) {}
