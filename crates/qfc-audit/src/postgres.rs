//! `PostgresAuditSink` — Postgres-backed hash-chained audit log.
//!
//! See `docs/server-wallet-rfc.md` §2.6 and `docs/m1-decisions.md` D12/D13.
//!
//! ## Chain-head concurrency
//!
//! Multiple processes (or multiple tasks within one process) may call
//! [`PostgresAuditSink::emit`] concurrently. To guarantee a strictly linear
//! hash chain we wrap every emit in a Postgres transaction that takes a
//! deterministic [transaction-level advisory lock][adv] before reading the
//! chain head and inserting the new row. The lock is released automatically
//! when the transaction commits or rolls back.
//!
//! The advisory-lock key is a fixed `i64` derived from the ASCII bytes
//! `"qFCSSCHN"` (== `0x7146_4353_5343_484E` interpreted as bytes
//! `q F C S S C H N`). Documented choice rather than runtime-hashed so all
//! processes on the same database agree without coordination, and so a stray
//! reuse of the same numeric key by an unrelated component is unlikely.
//!
//! [adv]: https://www.postgresql.org/docs/current/explicit-locking.html#ADVISORY-LOCKS

use std::str::FromStr;

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_wallet_types::{EventId, RequestId, WalletId};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgPool, PgPoolOptions};
use sqlx::Row;
use zeroize::Zeroizing;

use crate::event::{kind_byte, Actor, AuditEvent, AuditKind};
use crate::sink::{AuditError, AuditEventDraft, AuditSink};

/// Deterministic advisory-lock key — see module docs.
///
/// The eight ASCII bytes `qFCSSCHN` packed big-endian. Reinterpreted as
/// `i64` (Postgres' `pg_advisory_xact_lock` argument type) the high bit
/// is clear so it is a positive value on all platforms.
const CHAIN_ADVISORY_LOCK_KEY: i64 = 0x7146_4353_5343_484E_i64;

/// Postgres-backed hash-chained audit sink.
///
/// Construct via [`PostgresAuditSink::connect`] (creates its own pool) or
/// [`PostgresAuditSink::from_pool`] (shares an existing pool — useful if
/// the binary already owns one for the wallet registry).
pub struct PostgresAuditSink {
    pool: PgPool,
    server_key: Zeroizing<[u8; 32]>,
    advisory_lock_key: i64,
}

/// Embedded migrations. See `crates/qfc-audit/migrations/`.
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

impl PostgresAuditSink {
    /// Connect to Postgres and build a sink.
    ///
    /// Caller is responsible for running [`PostgresAuditSink::migrate`]
    /// (or otherwise ensuring the `audit_events` table exists) before the
    /// first emit.
    ///
    /// # Errors
    ///
    /// `AuditError::Io` if the database is unreachable or rejects the
    /// connection.
    pub async fn connect(db_url: &str, server_key: [u8; 32]) -> Result<Self, AuditError> {
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect(db_url)
            .await
            .map_err(|e| AuditError::Io(format!("postgres connect: {e}")))?;
        Self::from_pool(pool, server_key).await
    }

    /// Build a sink from a pre-existing pool. Useful when the binary
    /// already owns a `PgPool` for other tables and wants to share it.
    ///
    /// # Errors
    ///
    /// Currently infallible; signature returns `Result` for API symmetry
    /// with [`PostgresAuditSink::connect`].
    #[allow(clippy::unused_async)] // API symmetry with `connect`; async slot reserved.
    pub async fn from_pool(pool: PgPool, server_key: [u8; 32]) -> Result<Self, AuditError> {
        Ok(Self {
            pool,
            server_key: Zeroizing::new(server_key),
            advisory_lock_key: CHAIN_ADVISORY_LOCK_KEY,
        })
    }

    /// Apply embedded migrations.
    ///
    /// # Errors
    ///
    /// `AuditError::Io` on any sqlx migration failure.
    pub async fn migrate(&self) -> Result<(), AuditError> {
        MIGRATOR
            .run(&self.pool)
            .await
            .map_err(|e| AuditError::Io(format!("migrate: {e}")))
    }

    /// 32-byte ed25519 verifying key — what external verifiers use to
    /// check `server_signature` on stored events.
    #[must_use]
    pub fn server_public_key(&self) -> Vec<u8> {
        SigningKey::from_bytes(&self.server_key)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    /// Borrow the underlying `PgPool`. The anchor job needs read access
    /// without going through the full emit transaction.
    #[must_use]
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Test-only convenience: count rows.
    ///
    /// # Errors
    ///
    /// `AuditError::Io` on query failure.
    pub async fn event_count(&self) -> Result<u64, AuditError> {
        let row: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM audit_events")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| AuditError::Io(format!("count: {e}")))?;
        u64::try_from(row.0).map_err(|_| AuditError::Io("negative count".into()))
    }
}

#[async_trait]
impl AuditSink for PostgresAuditSink {
    async fn emit(&self, draft: AuditEventDraft) -> Result<AuditEvent, AuditError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuditError::Io(format!("begin tx: {e}")))?;

        // Serialize all emits against one another so chain links cannot
        // be reordered. Transaction-scoped — released on commit.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(self.advisory_lock_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuditError::Io(format!("advisory lock: {e}")))?;

        let prev_event_hash = fetch_chain_head(&mut tx).await?;

        // Build, sign, insert the new event.
        let event_id = EventId::new();
        let timestamp_unix_ms = current_unix_ms();
        let preimage =
            AuditEvent::signing_preimage(&prev_event_hash, &event_id, draft.kind, &draft.details);
        let signing_key = SigningKey::from_bytes(&self.server_key);
        let signature = signing_key.sign(&preimage).to_bytes().to_vec();
        if signature.len() != 64 {
            return Err(AuditError::Crypto("ed25519 signature must be 64 bytes"));
        }

        let event = AuditEvent {
            event_id,
            prev_event_hash,
            timestamp_unix_ms,
            actor: draft.actor.clone(),
            kind: draft.kind,
            request_id: draft.request_id,
            wallet_id: draft.wallet_id,
            details: draft.details.clone(),
            server_signature: signature,
        };

        insert_event(&mut tx, &event).await?;

        tx.commit()
            .await
            .map_err(|e| AuditError::Io(format!("commit: {e}")))?;

        Ok(event)
    }
}

/// Read the chain head inside a transaction. Returns `[0u8; 32]` for an
/// empty chain (genesis).
async fn fetch_chain_head(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
) -> Result<[u8; 32], AuditError> {
    let head_row = sqlx::query(
        "SELECT event_id, kind, details, prev_event_hash, server_signature
           FROM audit_events
          ORDER BY timestamp_unix_ms DESC, event_id DESC
          LIMIT 1",
    )
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| AuditError::Io(format!("chain head select: {e}")))?;

    let Some(row) = head_row else {
        return Ok([0u8; 32]);
    };

    let head_event_id_str: String = row
        .try_get("event_id")
        .map_err(|e| AuditError::Io(format!("head event_id: {e}")))?;
    let head_kind_i: i16 = row
        .try_get("kind")
        .map_err(|e| AuditError::Io(format!("head kind: {e}")))?;
    let head_details: serde_json::Value = row
        .try_get("details")
        .map_err(|e| AuditError::Io(format!("head details: {e}")))?;
    let head_prev: Vec<u8> = row
        .try_get("prev_event_hash")
        .map_err(|e| AuditError::Io(format!("head prev_event_hash: {e}")))?;
    let head_sig: Vec<u8> = row
        .try_get("server_signature")
        .map_err(|e| AuditError::Io(format!("head signature: {e}")))?;

    let head_event_id = EventId::from_str(&head_event_id_str)
        .map_err(|e| AuditError::Serde(format!("head event_id ulid parse: {e}")))?;
    let head_kind =
        kind_from_byte(u8::try_from(head_kind_i).map_err(|_| {
            AuditError::Serde(format!("head kind byte out of range: {head_kind_i}"))
        })?)?;
    let head_prev_arr: [u8; 32] = head_prev.as_slice().try_into().map_err(|_| {
        AuditError::Serde(format!(
            "head prev_event_hash must be 32 bytes, got {}",
            head_prev.len()
        ))
    })?;

    let head_preimage =
        AuditEvent::signing_preimage(&head_prev_arr, &head_event_id, head_kind, &head_details);
    let mut h = Sha256::new();
    h.update(&head_preimage);
    h.update(&head_sig);
    Ok(h.finalize().into())
}

/// Insert one fully-stamped event into the open transaction.
async fn insert_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    event: &AuditEvent,
) -> Result<(), AuditError> {
    let (actor_kind, actor_id) = actor_columns(&event.actor);
    sqlx::query(
        "INSERT INTO audit_events
            (event_id, prev_event_hash, timestamp_unix_ms,
             actor_kind, actor_id, kind, request_id, wallet_id,
             details, server_signature)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(event.event_id.to_string())
    .bind(event.prev_event_hash.as_slice())
    .bind(event.timestamp_unix_ms)
    .bind(actor_kind)
    .bind(actor_id)
    .bind(i16::from(kind_byte(event.kind)))
    .bind(event.request_id.map(|r| r.to_string()))
    .bind(event.wallet_id.map(|w| w.to_string()))
    .bind(&event.details)
    .bind(&event.server_signature)
    .execute(&mut **tx)
    .await
    .map_err(|e| AuditError::Io(format!("insert audit_events: {e}")))?;
    Ok(())
}

/// Decode `Actor` into `(actor_kind_smallint, actor_id_text)`.
fn actor_columns(actor: &Actor) -> (i16, Option<String>) {
    match actor {
        Actor::Requester { id } => (1, Some(id.clone())),
        Actor::Approver { id } => (2, Some(id.clone())),
        Actor::System => (3, None),
        Actor::Enclave => (4, None),
    }
}

/// Inverse of [`kind_byte`].
fn kind_from_byte(b: u8) -> Result<AuditKind, AuditError> {
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
                "unknown audit kind byte: {other}"
            )))
        }
    })
}

/// Inverse of `actor_columns`.
fn actor_from_columns(actor_kind: i16, actor_id: Option<String>) -> Result<Actor, AuditError> {
    Ok(match actor_kind {
        1 => Actor::Requester {
            id: actor_id.ok_or(AuditError::Serde(
                "Requester row missing actor_id".to_string(),
            ))?,
        },
        2 => Actor::Approver {
            id: actor_id.ok_or(AuditError::Serde(
                "Approver row missing actor_id".to_string(),
            ))?,
        },
        3 => Actor::System,
        4 => Actor::Enclave,
        other => return Err(AuditError::Serde(format!("unknown actor_kind: {other}"))),
    })
}

fn current_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

/// Load every audit event in chain order (`ORDER BY timestamp_unix_ms,
/// event_id`) and verify the hash chain + every signature against
/// `verifying_key`.
///
/// Returns the number of verified events on success.
///
/// # Errors
///
/// - `AuditError::Io` on query / decode failure.
/// - `AuditError::Crypto` on chain break or signature mismatch.
pub async fn replay_verify_postgres(
    pool: &PgPool,
    verifying_key: &[u8],
) -> Result<u64, AuditError> {
    let rows = sqlx::query(
        "SELECT event_id, prev_event_hash, timestamp_unix_ms,
                actor_kind, actor_id, kind, request_id, wallet_id,
                details, server_signature
           FROM audit_events
          ORDER BY timestamp_unix_ms ASC, event_id ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| AuditError::Io(format!("replay select: {e}")))?;

    let mut prev = [0u8; 32];
    let mut n: u64 = 0;
    for row in rows {
        let event = row_to_event(&row)?;
        if event.prev_event_hash != prev {
            return Err(AuditError::Crypto("hash chain broken"));
        }
        if !crate::file::verify_event(&event, verifying_key)? {
            return Err(AuditError::Crypto("signature mismatch"));
        }
        let preimage = AuditEvent::signing_preimage(
            &event.prev_event_hash,
            &event.event_id,
            event.kind,
            &event.details,
        );
        let mut h = Sha256::new();
        h.update(&preimage);
        h.update(&event.server_signature);
        prev = h.finalize().into();
        n += 1;
    }
    Ok(n)
}

fn row_to_event(row: &sqlx::postgres::PgRow) -> Result<AuditEvent, AuditError> {
    let event_id_str: String = row
        .try_get("event_id")
        .map_err(|e| AuditError::Io(format!("row event_id: {e}")))?;
    let prev_vec: Vec<u8> = row
        .try_get("prev_event_hash")
        .map_err(|e| AuditError::Io(format!("row prev_event_hash: {e}")))?;
    let timestamp_unix_ms: i64 = row
        .try_get("timestamp_unix_ms")
        .map_err(|e| AuditError::Io(format!("row timestamp_unix_ms: {e}")))?;
    let actor_kind: i16 = row
        .try_get("actor_kind")
        .map_err(|e| AuditError::Io(format!("row actor_kind: {e}")))?;
    let actor_id: Option<String> = row
        .try_get("actor_id")
        .map_err(|e| AuditError::Io(format!("row actor_id: {e}")))?;
    let kind_i: i16 = row
        .try_get("kind")
        .map_err(|e| AuditError::Io(format!("row kind: {e}")))?;
    let request_id_s: Option<String> = row
        .try_get("request_id")
        .map_err(|e| AuditError::Io(format!("row request_id: {e}")))?;
    let wallet_id_s: Option<String> = row
        .try_get("wallet_id")
        .map_err(|e| AuditError::Io(format!("row wallet_id: {e}")))?;
    let details: serde_json::Value = row
        .try_get("details")
        .map_err(|e| AuditError::Io(format!("row details: {e}")))?;
    let server_signature: Vec<u8> = row
        .try_get("server_signature")
        .map_err(|e| AuditError::Io(format!("row server_signature: {e}")))?;

    let event_id = EventId::from_str(&event_id_str)
        .map_err(|e| AuditError::Serde(format!("event_id parse: {e}")))?;
    let prev_event_hash: [u8; 32] = prev_vec.as_slice().try_into().map_err(|_| {
        AuditError::Serde(format!(
            "prev_event_hash must be 32 bytes, got {}",
            prev_vec.len()
        ))
    })?;
    let kind = kind_from_byte(
        u8::try_from(kind_i)
            .map_err(|_| AuditError::Serde(format!("kind byte out of range: {kind_i}")))?,
    )?;
    let actor = actor_from_columns(actor_kind, actor_id)?;

    let request_id = request_id_s
        .map(|s| RequestId::from_str(&s))
        .transpose()
        .map_err(|e| AuditError::Serde(format!("request_id parse: {e}")))?;
    let wallet_id = wallet_id_s
        .map(|s| WalletId::from_str(&s))
        .transpose()
        .map_err(|e| AuditError::Serde(format!("wallet_id parse: {e}")))?;

    Ok(AuditEvent {
        event_id,
        prev_event_hash,
        timestamp_unix_ms,
        actor,
        kind,
        request_id,
        wallet_id,
        details,
        server_signature,
    })
}
