//! Integration tests for `PostgresApproverRegistry` + `PostgresApprovalStore`
//! backed by a real Postgres via `testcontainers`. Mirrors the pattern in
//! `qfc-audit/tests/postgres_integration.rs`. Marked `#[ignore]` so the
//! default `cargo test --workspace` run doesn't depend on Docker.

#![cfg(test)]
#![allow(clippy::missing_panics_doc)]

use std::time::Duration;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_quorum::{
    ApprovalDecision, ApprovalStore, ApproverCreate, ApproverIdentity, ApproverRegistry,
    ApproverSetCreate, MemoryApprovalStore, PostgresApprovalStore, PostgresApproverRegistry,
    RecordOutcome, SignedApproval,
};
use qfc_wallet_types::{ApprovalId, ApproverId, OwnerId, RequestId, SigningScheme};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres as PostgresImage;

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

fn ed25519_identity(seed: u8) -> (ApproverIdentity, SigningKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    (
        ApproverIdentity::External {
            id: format!("approver-{seed}"),
            public_key: pk,
            scheme: SigningScheme::Ed25519,
        },
        sk,
    )
}

fn signed(
    identity: &ApproverIdentity,
    sk: &SigningKey,
    request_id: RequestId,
    message_hash: [u8; 32],
    decision: ApprovalDecision,
    timestamp_unix_ms: i64,
) -> SignedApproval {
    let approval_id = ApprovalId::new();
    let pre = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        decision,
        timestamp_unix_ms,
    );
    let sig = sk.sign(&pre).to_bytes().to_vec();
    SignedApproval {
        approval_id,
        approver: identity.clone(),
        request_id,
        message_hash,
        decision,
        timestamp_unix_ms,
        signature: sig,
    }
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn registry_add_get_list_revoke_round_trip() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let registry = PostgresApproverRegistry::from_pool(pool.clone());
    registry.migrate().await.unwrap();

    let owner = OwnerId::new("tenant-pg");
    let (id_a, _sk_a) = ed25519_identity(1);
    let (id_b, _sk_b) = ed25519_identity(2);
    let a = registry
        .add_approver(ApproverCreate {
            identity: id_a,
            label: "alice".into(),
            owner_id: owner.clone(),
            webhook_url: Some("https://hook.example/alice".into()),
        })
        .await
        .unwrap();
    let _b = registry
        .add_approver(ApproverCreate {
            identity: id_b,
            label: "bob".into(),
            owner_id: owner.clone(),
            webhook_url: None,
        })
        .await
        .unwrap();
    let fetched = registry.get_approver(a.approver_id).await.unwrap();
    assert_eq!(fetched.label, "alice");
    let active = registry
        .list_approvers_by_owner(&owner, false)
        .await
        .unwrap();
    assert_eq!(active.len(), 2);
    registry.revoke_approver(a.approver_id).await.unwrap();
    let active = registry
        .list_approvers_by_owner(&owner, false)
        .await
        .unwrap();
    assert_eq!(active.len(), 1);
    let all = registry
        .list_approvers_by_owner(&owner, true)
        .await
        .unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn registry_create_and_get_set() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let registry = PostgresApproverRegistry::from_pool(pool.clone());
    registry.migrate().await.unwrap();
    let owner = OwnerId::new("tenant-pg");
    let mut ids = Vec::new();
    for i in 0..3u8 {
        let (id, _) = ed25519_identity(i + 1);
        let rec = registry
            .add_approver(ApproverCreate {
                identity: id,
                label: format!("approver-{i}"),
                owner_id: owner.clone(),
                webhook_url: None,
            })
            .await
            .unwrap();
        ids.push(rec.approver_id);
    }
    let set = registry
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: owner.clone(),
            members: ids.clone(),
            threshold: 2,
            total: 3,
            quorum_timeout_secs: Some(900),
        })
        .await
        .unwrap();
    let fetched = registry.get_approver_set(set.id).await.unwrap();
    assert_eq!(fetched.threshold, 2);
    assert_eq!(fetched.members, ids);
    let listed = registry.list_approver_sets(&owner).await.unwrap();
    assert_eq!(listed.len(), 1);
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn store_records_and_rejects_duplicate() {
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    // Run the migration via the registry (it owns the migrator).
    let registry = PostgresApproverRegistry::from_pool(pool.clone());
    registry.migrate().await.unwrap();

    let store = PostgresApprovalStore::from_pool(pool.clone());
    let request_id = RequestId::new();
    let (identity, sk) = ed25519_identity(7);
    let approver_id = ApproverId::new();
    let approval = signed(
        &identity,
        &sk,
        request_id,
        [9u8; 32],
        ApprovalDecision::Approve,
        0,
    );
    let outcome = store.record_approval(&approval, approver_id).await.unwrap();
    assert_eq!(outcome, RecordOutcome::Inserted);
    // Idempotent re-submit with the SAME approval_id.
    let outcome = store.record_approval(&approval, approver_id).await.unwrap();
    assert_eq!(outcome, RecordOutcome::AlreadyRecorded);
    // A DIFFERENT approval payload from the same approver for the same
    // request → DuplicateApproval.
    let other = signed(
        &identity,
        &sk,
        request_id,
        [9u8; 32],
        ApprovalDecision::Reject,
        0,
    );
    let err = store.record_approval(&other, approver_id).await;
    assert!(
        matches!(
            err,
            Err(qfc_quorum::ApprovalStoreError::DuplicateApproval(_, _))
        ),
        "expected duplicate, got {err:?}"
    );

    let listed = store.list_for_request(request_id).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].decision, ApprovalDecision::Approve);
}

#[tokio::test]
#[ignore = "requires Docker; run with --ignored"]
async fn store_and_memory_store_have_same_idempotency() {
    // Cross-check: both implementations should agree on the
    // `AlreadyRecorded` / `DuplicateApproval` rules.
    let mem = MemoryApprovalStore::new();
    let Some((_c, pool)) = pg_pool().await else {
        return;
    };
    let registry = PostgresApproverRegistry::from_pool(pool.clone());
    registry.migrate().await.unwrap();
    let pg = PostgresApprovalStore::from_pool(pool.clone());

    let request_id = RequestId::new();
    let (identity, sk) = ed25519_identity(8);
    let approver_id = ApproverId::new();
    let a = signed(
        &identity,
        &sk,
        request_id,
        [0u8; 32],
        ApprovalDecision::Approve,
        0,
    );
    let b = signed(
        &identity,
        &sk,
        request_id,
        [0u8; 32],
        ApprovalDecision::Reject,
        0,
    );

    // First insert succeeds in both.
    assert_eq!(
        mem.record_approval(&a, approver_id).await.unwrap(),
        RecordOutcome::Inserted
    );
    assert_eq!(
        pg.record_approval(&a, approver_id).await.unwrap(),
        RecordOutcome::Inserted
    );

    // Different payload → duplicate in both.
    assert!(mem.record_approval(&b, approver_id).await.is_err());
    assert!(pg.record_approval(&b, approver_id).await.is_err());
}
