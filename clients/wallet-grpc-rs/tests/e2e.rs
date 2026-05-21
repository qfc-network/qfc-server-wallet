//! End-to-end tests for the SDK.
//!
//! Strategy mirrors the server-side
//! `crates/qfc-server-wallet/tests/grpc_integration.rs`: spin up a real
//! tonic server in-process on an ephemeral port, then drive the SDK
//! against it. This exercises the actual wire path (codecs, metadata
//! interceptor, error mapping) without mocking anything.
//!
//! Coverage:
//!   - Wallet happy path: create → get → sign → list audit events.
//!   - Approver happy path: register → create set → submit approval →
//!     list approvals (+ get_approver, list_approvers, revoke,
//!     list_approver_sets).
//!   - Auth failure: connect without `api_key` → `Unauthenticated`.
//!   - Auth failure: wrong `api_key` → `Unauthenticated`.
//!   - Bad input: malformed wallet_id → `InvalidArgument`.
//!   - Not found: unknown wallet_id → `NotFound`.
//!   - Already exists / idempotent: re-submit approval → `recorded = false`.
//!   - Transport failure: dial a dead port → `Transport`.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_audit::FileAuditSink;
use qfc_enclave::MockEnclave;
use qfc_policy::StaticAllowDenyPolicy;
use qfc_quorum::{ApprovalDecision as DomainApprovalDecision, MockQuorumApprover, SignedApproval};
use qfc_server_wallet::grpc::{build_router, GrpcOptions};
use qfc_server_wallet::{AppState, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, RequestId};
use tempfile::TempDir;

use qfc_wallet_grpc::{
    approver_identity, requester, signing_payload, ApprovalDecision, ApproverClient,
    ApproverIdentity, AuditEventsQuery, AuditKind, CreateApproverSetParams, CreateWalletParams,
    HashAlg, RegisterApproverParams, Requester, SdkError, SignParams, SigningPayload,
    SigningScheme, SubmitApprovalParams, WalletClient,
};

const API_KEY: &str = "grpc-sdk-test-key";

/// Spin up a tonic server in-process on an ephemeral port. The returned
/// shutdown sender terminates the server on drop or on explicit `send`.
async fn spawn_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>, TempDir) {
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
    let mut keys = HashSet::new();
    keys.insert(API_KEY.to_string());
    let state = AppState {
        service,
        api_keys: Arc::new(keys),
        audit_path,
    };

    let shared = Arc::new(state);
    let router = build_router(shared, GrpcOptions { reflection: false });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        router
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = rx.await;
            })
            .await
            .ok();
    });

    // Give the server a beat to be ready before the first dial.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, tx, dir)
}

fn endpoint(addr: SocketAddr) -> String {
    format!("http://{addr}")
}

// ============================================================================
// Wallet flow
// ============================================================================

#[tokio::test]
async fn wallet_happy_path_create_get_sign_audit() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = WalletClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .wallet()
        .await
        .expect("connect");

    // create
    let wallet = client
        .create_wallet(CreateWalletParams {
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            display_name: "sdk-test".into(),
            owner_id: "tenant-sdk".into(),
            policy_id: None,
        })
        .await
        .expect("create_wallet");
    assert_eq!(wallet.threshold, 2);
    assert_eq!(wallet.total, 3);
    assert_eq!(wallet.master_public_key.len(), 32);
    let wallet_id = wallet.wallet_id.clone();

    // get
    let got = client.get_wallet(&wallet_id).await.expect("get_wallet");
    assert_eq!(got.wallet_id, wallet_id);
    assert_eq!(got.scheme, SigningScheme::Ed25519 as i32);

    // sign
    let signed = client
        .sign(SignParams {
            wallet_id: wallet_id.clone(),
            payload: SigningPayload {
                payload: Some(signing_payload::Payload::Raw(signing_payload::Raw {
                    bytes: b"hello sdk".to_vec(),
                })),
            },
            requester: Requester {
                requester: Some(requester::Requester::ApiKey(requester::ApiKey {
                    key_id: "sdk-tester".into(),
                })),
            },
            hd_path: String::new(),
            hash_alg: HashAlg::None,
            context: None,
        })
        .await
        .expect("sign");
    assert_eq!(signed.signature.len(), 64);
    assert_eq!(signed.public_key.len(), 32);
    assert!(!signed.attestation_json.is_empty());

    // audit
    let events = client
        .get_audit_events(AuditEventsQuery {
            wallet_id: Some(wallet_id.clone()),
            limit: Some(100),
        })
        .await
        .expect("get_audit_events");
    assert!(!events.is_empty(), "expected audit events for wallet");
    let kinds: Vec<i32> = events.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&(AuditKind::WalletCreated as i32)));
    assert!(kinds.contains(&(AuditKind::SigningSucceeded as i32)));
}

// ============================================================================
// Approver flow
// ============================================================================

fn ed25519_identity(seed: u8) -> (ApproverIdentity, SigningKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let identity = ApproverIdentity {
        identity: Some(approver_identity::Identity::External(
            approver_identity::External {
                id: format!("sdk-approver-{seed}"),
                public_key: pk,
                scheme: SigningScheme::Ed25519 as i32,
            },
        )),
    };
    (identity, sk)
}

#[tokio::test]
async fn approver_happy_path_register_set_submit_list() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = ApproverClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .approver()
        .await
        .expect("connect");

    // Register two approvers.
    let mut ids = Vec::new();
    let mut keys: Vec<(SigningKey, ApproverIdentity)> = Vec::new();
    for seed in [21u8, 22u8] {
        let (identity, sk) = ed25519_identity(seed);
        let view = client
            .register_approver(RegisterApproverParams {
                identity: identity.clone(),
                label: format!("sdk-{seed}"),
                owner_id: "tenant-sdk".into(),
                webhook_url: None,
            })
            .await
            .expect("register_approver");
        ids.push(view.approver_id);
        keys.push((sk, identity));
    }

    // get_approver round trip
    let got = client.get_approver(&ids[0]).await.expect("get_approver");
    assert_eq!(got.approver_id, ids[0]);

    // create_approver_set
    let set = client
        .create_approver_set(CreateApproverSetParams {
            name: "sdk-treasury".into(),
            owner_id: "tenant-sdk".into(),
            members: ids.clone(),
            threshold: 2,
            total: 2,
            quorum_timeout_secs: None,
        })
        .await
        .expect("create_approver_set");
    assert_eq!(set.threshold, 2);
    assert_eq!(set.total, 2);

    // get_approver_set
    let got = client
        .get_approver_set(&set.approver_set_id)
        .await
        .expect("get_approver_set");
    assert_eq!(got.members, ids);

    // submit_approval
    let request_id = RequestId::new();
    let approval_id = ApprovalId::new();
    let message_hash = [99u8; 32];
    let ts: i64 = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap();
    let preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        DomainApprovalDecision::Approve,
        ts,
    );
    let (sk, identity) = &keys[0];
    let signature = sk.sign(&preimage).to_bytes().to_vec();

    let params = SubmitApprovalParams {
        request_id: request_id.to_string(),
        approver_id: ids[0].clone(),
        approval_id: approval_id.to_string(),
        decision: ApprovalDecision::Approve,
        signature,
        timestamp_unix_ms: ts,
        message_hash: message_hash.to_vec(),
        identity: identity.clone(),
    };
    let (recorded, ack_id) = client
        .submit_approval(params.clone())
        .await
        .expect("submit_approval");
    assert!(recorded, "first submit should be persisted");
    assert_eq!(ack_id, approval_id.to_string());

    // list_approvals shows it
    let listed = client
        .list_approvals(&request_id.to_string())
        .await
        .expect("list_approvals");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].decision, ApprovalDecision::Approve as i32);

    // Idempotent re-submit
    let (recorded2, _) = client
        .submit_approval(params)
        .await
        .expect("submit_approval idempotent");
    assert!(!recorded2, "re-submit must be idempotent");

    // list_approvers
    let listed = client
        .list_approvers("tenant-sdk", false)
        .await
        .expect("list_approvers");
    assert_eq!(listed.len(), 2);

    // revoke + verify
    client
        .revoke_approver(&ids[0])
        .await
        .expect("revoke_approver");
    let got = client.get_approver(&ids[0]).await.expect("get_approver");
    // ApproverStatus::Revoked = 2
    assert_eq!(got.status, 2);

    // list_approver_sets
    let sets = client
        .list_approver_sets("tenant-sdk")
        .await
        .expect("list_approver_sets");
    assert_eq!(sets.len(), 1);
}

// ============================================================================
// Error paths
// ============================================================================

#[tokio::test]
async fn missing_api_key_returns_unauthenticated() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    // Builder without `.api_key(_)` — interceptor injects empty key, server rejects.
    let mut client = WalletClient::connect(endpoint(addr))
        .wallet()
        .await
        .expect("connect");
    let err = client
        .create_wallet(CreateWalletParams {
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            display_name: "x".into(),
            owner_id: "x".into(),
            policy_id: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Unauthenticated(_)), "{err:?}");
}

#[tokio::test]
async fn wrong_api_key_returns_unauthenticated() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = WalletClient::connect(endpoint(addr))
        .api_key("not-the-right-key")
        .wallet()
        .await
        .expect("connect");
    let err = client
        .get_wallet("01HZZZZZZZZZZZZZZZZZZZZZZZ")
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Unauthenticated(_)), "{err:?}");
}

#[tokio::test]
async fn malformed_wallet_id_returns_invalid_argument() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = WalletClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .wallet()
        .await
        .expect("connect");
    let err = client.get_wallet("not-a-ulid").await.unwrap_err();
    assert!(matches!(err, SdkError::InvalidArgument(_)), "{err:?}");
}

#[tokio::test]
async fn unknown_wallet_returns_not_found() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = WalletClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .wallet()
        .await
        .expect("connect");
    let bogus = qfc_wallet_types::WalletId::new().to_string();
    let err = client.get_wallet(&bogus).await.unwrap_err();
    assert!(matches!(err, SdkError::NotFound(_)), "{err:?}");
}

#[tokio::test]
async fn dial_dead_port_returns_transport_error() {
    // Bind + immediately drop a listener so the port is closed.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let err = WalletClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .connect_timeout(Duration::from_millis(500))
        .wallet()
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::Transport(_)), "{err:?}");
}

#[tokio::test]
async fn approver_set_bad_threshold_returns_failed_precondition() {
    let (addr, _shutdown, _dir) = spawn_server().await;
    let mut client = ApproverClient::connect(endpoint(addr))
        .api_key(API_KEY)
        .approver()
        .await
        .expect("connect");
    let (identity, _) = ed25519_identity(31);
    let view = client
        .register_approver(RegisterApproverParams {
            identity,
            label: "solo".into(),
            owner_id: "tenant-bad".into(),
            webhook_url: None,
        })
        .await
        .expect("register_approver");
    // threshold > total — RegistryError::InvalidThreshold maps to
    // FailedPrecondition on the gRPC side.
    let err = client
        .create_approver_set(CreateApproverSetParams {
            name: "bad".into(),
            owner_id: "tenant-bad".into(),
            members: vec![view.approver_id],
            threshold: 5,
            total: 1,
            quorum_timeout_secs: None,
        })
        .await
        .unwrap_err();
    assert!(matches!(err, SdkError::FailedPrecondition(_)), "{err:?}");
}

#[tokio::test]
async fn submit_approval_validates_client_side_first() {
    // Don't even need a server: validate() catches the bad input before
    // we hit the wire.
    let bad = SubmitApprovalParams {
        request_id: "x".into(),
        approver_id: "y".into(),
        approval_id: "z".into(),
        decision: ApprovalDecision::Approve,
        signature: vec![1u8; 64],
        timestamp_unix_ms: 0,
        message_hash: vec![0u8; 31], // wrong length
        identity: ApproverIdentity { identity: None },
    };
    let err = bad.validate().unwrap_err();
    assert!(matches!(err, SdkError::BadInput(_)));
}
