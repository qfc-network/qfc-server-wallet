//! HTTP API integration tests (M2 P1).
//!
//! Drive the `axum::Router` returned by `qfc_server_wallet::router` via
//! `tower::ServiceExt::oneshot` — no real socket binding, no real
//! networking. The full M1 stack is wired with mocks so each test
//! creates its own isolated wallet service.

use std::collections::HashSet;
use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use qfc_audit::FileAuditSink;
use qfc_enclave::MockEnclave;
use qfc_policy::StaticAllowDenyPolicy;
use qfc_quorum::MockQuorumApprover;
use qfc_server_wallet::{router, AppState, WalletService};
use qfc_sss::MockShareStore;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt;

const API_KEY: &str = "test-key-1";

fn allow_all_state(audit_path: std::path::PathBuf, service: Arc<WalletService>) -> AppState {
    let mut set = HashSet::new();
    set.insert(API_KEY.to_string());
    AppState {
        service,
        api_keys: Arc::new(set),
        audit_path,
    }
}

async fn build_state_allow_all() -> (AppState, TempDir) {
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
    (allow_all_state(audit_path, service), dir)
}

async fn build_state_deny_all() -> (AppState, TempDir) {
    let enclave: Arc<dyn qfc_enclave::Enclave> =
        Arc::new(MockEnclave::new_for_testing_with_seed([1u8; 32]));
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::deny_all());
    let quorum: Arc<dyn qfc_quorum::QuorumApprover> = Arc::new(MockQuorumApprover::new());

    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit = FileAuditSink::open(&audit_path, FileAuditSink::random_key())
        .await
        .unwrap();
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);

    let service = Arc::new(WalletService::new(enclave, shares, policy, quorum, audit));
    (allow_all_state(audit_path, service), dir)
}

fn req_with_key(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
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
    serde_json::from_slice(&collected).unwrap_or_else(|e| {
        panic!(
            "expected JSON body, got: {}\nbytes={}",
            e,
            String::from_utf8_lossy(&collected)
        )
    })
}

fn make_wallet_body() -> Value {
    json!({
        "scheme": "ed25519",
        "threshold": 2,
        "total": 3,
        "display_name": "test-wallet",
        "owner_id": "tenant-test",
    })
}

#[tokio::test]
async fn post_wallets_happy_path() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let resp = app
        .oneshot(req_with_key("POST", "/wallets", Some(make_wallet_body())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["scheme"], "ed25519");
    assert_eq!(body["threshold"], 2);
    assert_eq!(body["total"], 3);
    let pk_hex = body["master_public_key_hex"].as_str().unwrap();
    // ed25519 pubkeys are 32 bytes -> 64 hex chars.
    assert_eq!(pk_hex.len(), 64);
}

#[tokio::test]
async fn post_sign_ed25519_happy_path() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    // Create wallet
    let resp = app
        .clone()
        .oneshot(req_with_key("POST", "/wallets", Some(make_wallet_body())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();

    // Sign
    let sign_body = json!({
        "payload": {"kind": "raw", "bytes_hex": "deadbeef"},
        "requester": {"kind": "api_key", "key_id": "alice"},
        "hd_path": null,
        "hash_alg": "none",
    });
    let resp = app
        .oneshot(req_with_key(
            "POST",
            &format!("/wallets/{wallet_id}/sign"),
            Some(sign_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let sig_hex = body["signature_hex"].as_str().unwrap();
    let pk_hex = body["public_key_hex"].as_str().unwrap();
    // ed25519 signatures are 64 bytes -> 128 hex chars; pubkey 64 hex chars.
    assert_eq!(sig_hex.len(), 128);
    assert_eq!(pk_hex.len(), 64);
    assert!(body["attestation"].is_object());
}

#[tokio::test]
async fn missing_api_key_returns_401() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/wallets")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&make_wallet_body()).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error"], "unauthorized");
}

#[tokio::test]
async fn wrong_api_key_returns_401() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/wallets")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-api-key", "not-the-right-key")
        .body(Body::from(serde_json::to_vec(&make_wallet_body()).unwrap()))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn policy_denied_returns_403() {
    let (state, _dir) = build_state_deny_all().await;
    let app = router(state);

    // Create wallet (policy is consulted only at sign time per M1 contract).
    let resp = app
        .clone()
        .oneshot(req_with_key("POST", "/wallets", Some(make_wallet_body())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();

    let sign_body = json!({
        "payload": {"kind": "raw", "bytes_hex": "ab"},
        "requester": {"kind": "api_key", "key_id": "alice"},
        "hd_path": null,
        "hash_alg": "none",
    });
    let resp = app
        .oneshot(req_with_key(
            "POST",
            &format!("/wallets/{wallet_id}/sign"),
            Some(sign_body),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error"], "policy_denied");
}

#[tokio::test]
async fn unknown_wallet_returns_404() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    // Made-up but well-formed ULID.
    let bogus = qfc_wallet_types::WalletId::new();
    let resp = app
        .oneshot(req_with_key("GET", &format!("/wallets/{bogus}"), None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error"], "wallet_not_found");
}

#[tokio::test]
async fn malformed_json_returns_400() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("POST")
        .uri("/wallets")
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-api-key", API_KEY)
        .body(Body::from("{not json"))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn malformed_wallet_id_returns_400() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let resp = app
        .oneshot(req_with_key("GET", "/wallets/not-a-ulid", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_json(resp.into_body()).await;
    assert_eq!(body["error"], "bad_request");
}

#[tokio::test]
async fn health_endpoint_no_auth_required() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn metrics_endpoint_returns_placeholder() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = to_bytes(resp.into_body(), 1024).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();
    assert!(text.contains("placeholder for M2 P5"));
}

#[tokio::test]
async fn openapi_document_served() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    let req = Request::builder()
        .method("GET")
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    // Sanity-check that our endpoints made it in.
    assert!(body["paths"]["/wallets"].is_object());
    assert!(body["paths"]["/wallets/{id}/sign"].is_object());
}

#[tokio::test]
async fn audit_events_reflects_emitted_log() {
    let (state, _dir) = build_state_allow_all().await;
    let app = router(state);

    // Create wallet (emits 1 audit event).
    let resp = app
        .clone()
        .oneshot(req_with_key("POST", "/wallets", Some(make_wallet_body())))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body = body_json(resp.into_body()).await;
    let wallet_id = body["wallet_id"].as_str().unwrap().to_string();

    let resp = app
        .oneshot(req_with_key(
            "GET",
            &format!("/audit/events?wallet_id={wallet_id}&limit=10"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp.into_body()).await;
    let arr = body.as_array().unwrap();
    assert!(!arr.is_empty(), "expected at least the WalletCreated event");
    assert_eq!(arr[0]["kind"], "wallet_created");
    assert_eq!(arr[0]["wallet_id"].as_str().unwrap(), wallet_id);
}
