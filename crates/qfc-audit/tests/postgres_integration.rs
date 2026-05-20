//! Integration tests for [`PostgresAuditSink`] backed by a real Postgres
//! instance via `testcontainers`. Marked `#[ignore]` so the default
//! `cargo test --workspace` run doesn't depend on Docker; run with
//! `cargo test --workspace -- --ignored` to exercise them.
//!
//! Each test spins up its own container so they're isolated (tradeoff:
//! slower, but no cross-test ordering bugs).

#![cfg(test)]
#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;
use std::time::Duration;

use qfc_audit::{
    anchor_payload, replay_verify_postgres, Actor, AuditEventDraft, AuditKind, AuditSink,
    FileAuditSink, PostgresAuditSink,
};
use qfc_wallet_types::WalletId;
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;

/// Start a Postgres testcontainer, returning the container handle plus a
/// connected `PgPool`. Holding the container handle keeps it alive for
/// the duration of the test; dropping it tears it down.
///
/// Returns `None` if Docker isn't available — the calling test should
/// treat that as a skip with `eprintln!`.
async fn pg_pool() -> Option<(ContainerAsync<PostgresImage>, PgPool)> {
    let image = PostgresImage::default();
    let container = match image.start().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("skipping postgres integration: docker unavailable: {e}");
            return None;
        }
    };
    let host = container.get_host().await.ok()?;
    let port = container.get_host_port_ipv4(5432).await.ok()?;
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    // Retry connect briefly — first-boot Postgres can need a moment.
    let mut attempt = 0;
    let pool = loop {
        match PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await
        {
            Ok(p) => break p,
            Err(e) if attempt < 5 => {
                eprintln!("pg connect retry {attempt}: {e}");
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            Err(e) => {
                eprintln!("pg connect failed after retries: {e}");
                return None;
            }
        }
    };
    Some((container, pool))
}

fn draft(kind: AuditKind) -> AuditEventDraft {
    AuditEventDraft {
        actor: Actor::System,
        kind,
        request_id: None,
        wallet_id: Some(WalletId::new()),
        details: json!({ "note": "pg integration test" }),
    }
}

async fn fresh_sink(pool: PgPool) -> PostgresAuditSink {
    let key = FileAuditSink::random_key();
    let sink = PostgresAuditSink::from_pool(pool, key).await.unwrap();
    sink.migrate().await.unwrap();
    sink
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn emit_fetch_chain_links() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let sink = fresh_sink(pool.clone()).await;

    let a = sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();
    let b = sink.emit(draft(AuditKind::SigningEvaluated)).await.unwrap();
    let c = sink.emit(draft(AuditKind::SigningSucceeded)).await.unwrap();

    assert_eq!(a.prev_event_hash, [0u8; 32]);

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(qfc_audit::AuditEvent::signing_preimage(
        &a.prev_event_hash,
        &a.event_id,
        a.kind,
        &a.details,
    ));
    h.update(&a.server_signature);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(b.prev_event_hash, expected);
    assert_ne!(b.prev_event_hash, c.prev_event_hash);

    assert_eq!(sink.event_count().await.unwrap(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker; run with --ignored"]
async fn concurrent_emits_preserve_chain() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let key = FileAuditSink::random_key();

    // Two sinks sharing the same DB but different connections; both
    // contend via the advisory lock.
    let sink1 = Arc::new(
        PostgresAuditSink::from_pool(pool.clone(), key)
            .await
            .unwrap(),
    );
    sink1.migrate().await.unwrap();
    let sink2 = Arc::new(
        PostgresAuditSink::from_pool(pool.clone(), key)
            .await
            .unwrap(),
    );

    const PAR: usize = 16;
    let mut handles = Vec::new();
    for i in 0..PAR {
        let s = if i % 2 == 0 {
            Arc::clone(&sink1)
        } else {
            Arc::clone(&sink2)
        };
        handles.push(tokio::spawn(async move {
            s.emit(draft(AuditKind::SigningRequested)).await.unwrap()
        }));
    }
    for h in handles {
        h.await.unwrap();
    }

    // Full replay must verify the chain.
    let pubkey = sink1.server_public_key();
    let n = replay_verify_postgres(&pool, &pubkey).await.unwrap();
    assert_eq!(n as usize, PAR);
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn replay_verify_equivalent() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let sink = fresh_sink(pool.clone()).await;

    for k in [
        AuditKind::SigningRequested,
        AuditKind::SigningEvaluated,
        AuditKind::SigningAttempted,
        AuditKind::SigningSucceeded,
    ] {
        sink.emit(draft(k)).await.unwrap();
    }
    let n = replay_verify_postgres(&pool, &sink.server_public_key())
        .await
        .unwrap();
    assert_eq!(n, 4);
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn wrong_server_key_fails_verification() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let sink = fresh_sink(pool.clone()).await;
    sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();

    let other = FileAuditSink::random_key();
    let other_sink = PostgresAuditSink::from_pool(pool.clone(), other)
        .await
        .unwrap();
    let err = replay_verify_postgres(&pool, &other_sink.server_public_key()).await;
    assert!(matches!(err, Err(qfc_audit::AuditError::Crypto(_))));
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn anchor_payload_returns_latest_chain_head() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let sink = fresh_sink(pool.clone()).await;

    // Empty chain.
    let empty = anchor_payload(&pool).await.unwrap();
    assert_eq!(empty.chain_head_hex, hex::encode([0u8; 32]));
    assert!(empty.head_event_id.is_none());
    assert_eq!(empty.event_count, 0);

    let _a = sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();
    let b = sink.emit(draft(AuditKind::SigningEvaluated)).await.unwrap();

    let p = anchor_payload(&pool).await.unwrap();
    assert_eq!(p.event_count, 2);
    assert_eq!(p.head_event_id, Some(b.event_id));

    // The anchor's chain_head_hex should be exactly the prev_event_hash a
    // hypothetical *next* emit would use — i.e. computed off `b`.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(qfc_audit::AuditEvent::signing_preimage(
        &b.prev_event_hash,
        &b.event_id,
        b.kind,
        &b.details,
    ));
    h.update(&b.server_signature);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(p.chain_head_hex, hex::encode(expected));

    // And after another emit the next prev_event_hash should match.
    let c = sink.emit(draft(AuditKind::SigningSucceeded)).await.unwrap();
    assert_eq!(c.prev_event_hash, expected);
}
