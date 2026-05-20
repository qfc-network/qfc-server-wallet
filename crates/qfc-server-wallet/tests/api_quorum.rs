//! HTTP API integration tests for the M4 approver / approval endpoints.
//!
//! Uses the same `tower::ServiceExt::oneshot` pattern as `tests/api.rs`.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use http_body_util::BodyExt;
use qfc_audit::FileAuditSink;
use qfc_enclave::MockEnclave;
use qfc_policy::StaticAllowDenyPolicy;
use qfc_quorum::{ApprovalDecision, MockQuorumApprover, SignedApproval};
use qfc_server_wallet::{router, AppState, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, RequestId};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const API_KEY: &str = "test-key-quorum";

async fn build_state() -> (AppState, TempDir) {
    let enclave: Arc<dyn qfc_enclave::Enclave> =
        Arc::new(MockEnclave::new_for_testing_with_seed([7u8; 32]));
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::allow_all());
    let quorum: Arc<dyn qfc_quorum::QuorumApprover> = Arc::new(MockQuorumApprover::new());

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit = FileAuditSink::open(&audit_path, FileAuditSink::random_key())
        .await
        .unwrap();
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);

    let service = Arc::new(WalletService::new(enclave, shares, policy, quorum, audit));
    let mut set = HashSet::new();
    set.insert(API_KEY.to_string());
    let state = AppState {
        service,
        api_keys: Arc::new(set),
        audit_path,
    };
    (state, dir)
}

fn req(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    if body.is_some() {
        b = b.header(header::CONTENT_TYPE, "application/json");
    }
    b = b.header("x-api-key", API_KEY);
    let body = match body {
        Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
        None => Body::empty(),
    };
    b.body(body).unwrap()
}

async fn body_json(body: Body) -> Value {
    let collected = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&collected).unwrap()
}

fn ed25519_external_identity(seed: u8) -> (Value, SigningKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    (
        json!({
            "kind": "external",
            "id": format!("approver-{seed}"),
            "public_key_hex": hex::encode(&pk),
            "scheme": "ed25519",
        }),
        sk,
    )
}

#[tokio::test]
async fn create_get_revoke_approver_round_trip() {
    let (state, _dir) = build_state().await;
    let app = router(state);
    let (identity_dto, _) = ed25519_external_identity(11);

    // POST /approvers
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/approvers",
            Some(json!({
                "identity": identity_dto,
                "label": "alice",
                "owner_id": "tenant-x",
                "webhook_url": null,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp.into_body()).await;
    let approver_id = v["approver_id"].as_str().unwrap().to_string();

    // GET /approvers/{id}
    let resp = app
        .clone()
        .oneshot(req("GET", &format!("/approvers/{approver_id}"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // DELETE /approvers/{id}
    let resp = app
        .clone()
        .oneshot(req("DELETE", &format!("/approvers/{approver_id}"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET still returns the revoked approver.
    let resp = app
        .oneshot(req("GET", &format!("/approvers/{approver_id}"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(v["status"], "revoked");
}

#[tokio::test]
async fn create_approver_set_happy_path() {
    let (state, _dir) = build_state().await;
    let app = router(state);

    // Register two approvers.
    let mut ids = Vec::new();
    for i in 0..3u8 {
        let (identity_dto, _) = ed25519_external_identity(20 + i);
        let resp = app
            .clone()
            .oneshot(req(
                "POST",
                "/approvers",
                Some(json!({
                    "identity": identity_dto,
                    "label": format!("approver-{i}"),
                    "owner_id": "tenant-y",
                    "webhook_url": null,
                })),
            ))
            .await
            .unwrap();
        let v = body_json(resp.into_body()).await;
        ids.push(v["approver_id"].as_str().unwrap().to_string());
    }

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/approver-sets",
            Some(json!({
                "name": "treasury",
                "owner_id": "tenant-y",
                "members": ids,
                "threshold": 2,
                "total": 3,
                "quorum_timeout_secs": null,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let v = body_json(resp.into_body()).await;
    let set_id = v["approver_set_id"].as_str().unwrap().to_string();

    // GET /approver-sets/{id}
    let resp = app
        .clone()
        .oneshot(req("GET", &format!("/approver-sets/{set_id}"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn create_approver_set_rejects_bad_threshold() {
    let (state, _dir) = build_state().await;
    let app = router(state);

    let (identity_dto, _) = ed25519_external_identity(40);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/approvers",
            Some(json!({
                "identity": identity_dto,
                "label": "solo",
                "owner_id": "tenant-z",
                "webhook_url": null,
            })),
        ))
        .await
        .unwrap();
    let v = body_json(resp.into_body()).await;
    let aid = v["approver_id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(req(
            "POST",
            "/approver-sets",
            Some(json!({
                "name": "bad",
                "owner_id": "tenant-z",
                "members": [aid],
                "threshold": 5,
                "total": 1,
                "quorum_timeout_secs": null,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn submit_approval_signature_verifies() {
    let (state, _dir) = build_state().await;
    let app = router(state);

    let (identity_dto, sk) = ed25519_external_identity(50);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/approvers",
            Some(json!({
                "identity": identity_dto.clone(),
                "label": "bob",
                "owner_id": "tenant-x",
                "webhook_url": null,
            })),
        ))
        .await
        .unwrap();
    let v = body_json(resp.into_body()).await;
    let approver_id = v["approver_id"].as_str().unwrap().to_string();

    // Build a signed approval payload over a fresh request_id.
    let request_id = RequestId::new();
    let approval_id = ApprovalId::new();
    let msg_hash = [42u8; 32];
    let ts = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let ts = i64::try_from(ts).unwrap();
    let preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &msg_hash,
        ApprovalDecision::Approve,
        ts,
    );
    let sig = sk.sign(&preimage).to_bytes().to_vec();

    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/requests/{request_id}/approvals"),
            Some(json!({
                "approver_id": approver_id,
                "approval_id": approval_id.to_string(),
                "decision": "approve",
                "signature_hex": hex::encode(&sig),
                "timestamp_unix_ms": ts,
                "message_hash_hex": hex::encode(msg_hash),
                "identity": identity_dto.clone(),
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(v["recorded"], true);

    // GET /requests/{id}/approvals returns it.
    let resp = app
        .clone()
        .oneshot(req(
            "GET",
            &format!("/requests/{request_id}/approvals"),
            None,
        ))
        .await
        .unwrap();
    let listed = body_json(resp.into_body()).await;
    let arr = listed.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["decision"], "approve");

    // Idempotent re-submit of the same payload returns recorded=false.
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            &format!("/requests/{request_id}/approvals"),
            Some(json!({
                "approver_id": approver_id,
                "approval_id": approval_id.to_string(),
                "decision": "approve",
                "signature_hex": hex::encode(&sig),
                "timestamp_unix_ms": ts,
                "message_hash_hex": hex::encode(msg_hash),
                "identity": identity_dto.clone(),
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let v = body_json(resp.into_body()).await;
    assert_eq!(v["recorded"], false);

    // Different payload from the same approver for the same request → 409.
    let alt_approval_id = ApprovalId::new();
    let alt_preimage = SignedApproval::signing_preimage(
        &alt_approval_id,
        &request_id,
        &msg_hash,
        ApprovalDecision::Reject,
        ts,
    );
    let alt_sig = sk.sign(&alt_preimage).to_bytes().to_vec();
    let resp = app
        .oneshot(req(
            "POST",
            &format!("/requests/{request_id}/approvals"),
            Some(json!({
                "approver_id": approver_id,
                "approval_id": alt_approval_id.to_string(),
                "decision": "reject",
                "signature_hex": hex::encode(&alt_sig),
                "timestamp_unix_ms": ts,
                "message_hash_hex": hex::encode(msg_hash),
                "identity": identity_dto,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn submit_approval_rejects_bad_signature() {
    let (state, _dir) = build_state().await;
    let app = router(state);

    let (identity_dto, _sk) = ed25519_external_identity(60);
    let resp = app
        .clone()
        .oneshot(req(
            "POST",
            "/approvers",
            Some(json!({
                "identity": identity_dto.clone(),
                "label": "carol",
                "owner_id": "tenant-x",
                "webhook_url": null,
            })),
        ))
        .await
        .unwrap();
    let v = body_json(resp.into_body()).await;
    let approver_id = v["approver_id"].as_str().unwrap().to_string();

    // Send a payload with the wrong signature.
    let request_id = RequestId::new();
    let approval_id = ApprovalId::new();
    let msg_hash = [9u8; 32];
    let ts = 0i64;
    let resp = app
        .oneshot(req(
            "POST",
            &format!("/requests/{request_id}/approvals"),
            Some(json!({
                "approver_id": approver_id,
                "approval_id": approval_id.to_string(),
                "decision": "approve",
                "signature_hex": hex::encode([0u8; 64]),
                "timestamp_unix_ms": ts,
                "message_hash_hex": hex::encode(msg_hash),
                "identity": identity_dto,
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// Silence unused-warning on to_bytes if axum versions drift.
#[allow(dead_code)]
async fn _consume(b: Body) -> Vec<u8> {
    to_bytes(b, usize::MAX).await.unwrap().to_vec()
}
