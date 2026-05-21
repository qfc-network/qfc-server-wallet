//! End-to-end: spin up the webhook router in-process, fire a synthetic
//! webhook with a real HMAC, observe the outbound POST hit a `wiremock`
//! receiver that pretends to be the server.

use std::net::SocketAddr;
use std::sync::Arc;

use hmac::{Hmac, Mac};
use qfc_approver::{router, AppState, ApproverSigner, DecisionPolicy, Processor, ProcessorConfig};
use qfc_wallet_types::{RequestId, SecretBytes, SigningScheme};
use sha2::Sha256;
use wiremock::matchers::{method, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn webhook_in_post_out() {
    // 1. Mock the server-side approval-submission endpoint.
    let server_mock = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_regex(r"/requests/[A-Za-z0-9]+/approvals"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "recorded": true,
            "approval_id": "ignored-by-mock"
        })))
        .expect(1)
        .mount(&server_mock)
        .await;

    // 2. Build the client.
    let signer =
        ApproverSigner::new(SecretBytes::from_slice(&[1u8; 32]), SigningScheme::Ed25519).unwrap();
    let webhook_secret = b"shared-secret-bytes".to_vec();
    let http = Arc::new(reqwest::Client::new());
    let dir = tempfile::tempdir().unwrap();
    let cfg = ProcessorConfig {
        server: server_mock.uri(),
        approver_id: "01HABCDEFGHJKMNPQRSTVWXYZ0".into(),
        policy: DecisionPolicy::AutoApprove,
        audit_path: dir.path().join("audit.log"),
    };
    let processor = Processor::new(signer, http, cfg);
    let state = AppState {
        hmac_secret: Arc::new(webhook_secret.clone()),
        processor,
    };

    // 3. Bind the webhook receiver to an ephemeral port.
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local: SocketAddr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 4. POST a synthetic ApprovalRequest. Body has the same shape the
    //    server emits via WebhookApprover::notify.
    let request_id = RequestId::new();
    let body = serde_json::json!({
        "request_id": request_id.to_string(),
        "message_hash": hex::encode([0xCDu8; 32]),
        "approver_set": [
            {
                "kind": "external",
                "id": "alice",
                "public_key_hex": hex::encode([2u8; 32]),
                "scheme": "ed25519"
            }
        ],
        "threshold": 1
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let sig = {
        let mut mac = Hmac::<Sha256>::new_from_slice(&webhook_secret).unwrap();
        mac.update(&body_bytes);
        hex::encode(mac.finalize().into_bytes())
    };

    let resp = reqwest::Client::new()
        .post(format!("http://{local}/"))
        .header("x-qfc-signature", sig)
        .header("content-type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200, "webhook returned non-200");

    // 5. Confirm the audit log got one "posted" line.
    let log = tokio::fs::read_to_string(dir.path().join("audit.log"))
        .await
        .unwrap();
    assert!(
        log.contains("\"posted\""),
        "audit log missing 'posted' event: {log}"
    );
    assert!(log.contains(&request_id.to_string()));

    server_handle.abort();
}

#[tokio::test]
async fn webhook_rejects_missing_signature() {
    let signer =
        ApproverSigner::new(SecretBytes::from_slice(&[1u8; 32]), SigningScheme::Ed25519).unwrap();
    let http = Arc::new(reqwest::Client::new());
    let dir = tempfile::tempdir().unwrap();
    let cfg = ProcessorConfig {
        server: "http://unused.invalid".into(),
        approver_id: "01H".into(),
        policy: DecisionPolicy::AutoApprove,
        audit_path: dir.path().join("audit.log"),
    };
    let processor = Processor::new(signer, http, cfg);
    let state = AppState {
        hmac_secret: Arc::new(b"k".to_vec()),
        processor,
    };
    let app = router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local: SocketAddr = listener.local_addr().unwrap();
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let resp = reqwest::Client::new()
        .post(format!("http://{local}/"))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    server_handle.abort();
}
