//! gRPC integration tests.
//!
//! Spins up the tonic server in-process on an ephemeral TCP port, then
//! drives the auto-generated client stubs to fire one request per RPC.
//! Auth is exercised end-to-end via the `x-api-key` metadata interceptor.
//!
//! These tests use real sockets (not the `tower::ServiceExt::oneshot`
//! trick the HTTP tests use) because tonic's `serve_with_shutdown` is the
//! supported integration entrypoint and works happily over a `127.0.0.1`
//! ephemeral port.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_audit::FileAuditSink;
use qfc_enclave::MockEnclave;
use qfc_policy::StaticAllowDenyPolicy;
use qfc_quorum::{ApprovalDecision, MockQuorumApprover, SignedApproval};
use qfc_server_wallet::grpc::{build_router, GrpcOptions};
use qfc_server_wallet::{AppState, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, RequestId};
use tempfile::TempDir;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;

use proto::approver_client::ApproverClient;
use proto::wallet_client::WalletClient;
use qfc_server_wallet::grpc::proto;

const API_KEY: &str = "grpc-test-key";

/// Spin up an in-process gRPC server on an ephemeral port. Returns the
/// bind address and a cancellation token-equivalent: dropping the returned
/// `oneshot::Sender` shuts the server down.
async fn spawn_grpc_server() -> (SocketAddr, tokio::sync::oneshot::Sender<()>, TempDir) {
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
    let app_state = AppState {
        service,
        api_keys: Arc::new(set),
        audit_path,
    };

    let shared = Arc::new(app_state);
    let router = build_router(shared, GrpcOptions { reflection: false });

    // Bind to an ephemeral port first so we know the actual address before
    // handing the listener to tonic.
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

    // Give the server a beat to be ready to accept.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, tx, dir)
}

async fn dial(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap()
}

fn with_api_key<T>(req: T) -> Request<T> {
    let mut r = Request::new(req);
    r.metadata_mut()
        .insert("x-api-key", MetadataValue::from_static(API_KEY));
    r
}

fn make_create_wallet_request() -> proto::CreateWalletRequest {
    proto::CreateWalletRequest {
        scheme: proto::SigningScheme::Ed25519 as i32,
        threshold: 2,
        total: 3,
        display_name: "grpc-test-wallet".into(),
        owner_id: "tenant-grpc".into(),
        policy_id: String::new(),
    }
}

#[tokio::test]
async fn wallet_e2e_create_sign_audit() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = WalletClient::new(channel);

    // CreateWallet
    let resp = client
        .create_wallet(with_api_key(make_create_wallet_request()))
        .await
        .unwrap();
    let wallet = resp.into_inner().wallet.unwrap();
    assert_eq!(wallet.scheme, proto::SigningScheme::Ed25519 as i32);
    assert_eq!(wallet.threshold, 2);
    assert_eq!(wallet.total, 3);
    assert_eq!(wallet.master_public_key.len(), 32, "ed25519 pubkey is 32B");
    let wallet_id = wallet.wallet_id.clone();

    // GetWallet
    let got = client
        .get_wallet(with_api_key(proto::GetWalletRequest {
            wallet_id: wallet_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .wallet
        .unwrap();
    assert_eq!(got.wallet_id, wallet_id);

    // Sign
    let sign_req = proto::SignRequest {
        wallet_id: wallet_id.clone(),
        payload: Some(proto::SigningPayload {
            payload: Some(proto::signing_payload::Payload::Raw(
                proto::signing_payload::Raw {
                    bytes: b"\xde\xad\xbe\xef".to_vec(),
                },
            )),
        }),
        requester: Some(proto::Requester {
            requester: Some(proto::requester::Requester::ApiKey(
                proto::requester::ApiKey {
                    key_id: "alice".into(),
                },
            )),
        }),
        hd_path: String::new(),
        hash_alg: proto::HashAlg::None as i32,
        context: None,
    };
    let sig_resp = client
        .sign(with_api_key(sign_req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(sig_resp.signature.len(), 64, "ed25519 sig is 64B");
    assert_eq!(sig_resp.public_key.len(), 32);
    assert!(!sig_resp.attestation_json.is_empty());

    // GetAuditEvents — should contain at least the WalletCreated +
    // SigningRequested events for this wallet.
    let events = client
        .get_audit_events(with_api_key(proto::GetAuditEventsRequest {
            wallet_id: wallet_id.clone(),
            limit: 100,
        }))
        .await
        .unwrap()
        .into_inner()
        .events;
    assert!(!events.is_empty(), "expected audit events for wallet");
    let kinds: Vec<i32> = events.iter().map(|e| e.kind).collect();
    assert!(kinds.contains(&(proto::AuditKind::WalletCreated as i32)));
    assert!(kinds.contains(&(proto::AuditKind::SigningSucceeded as i32)));
}

#[tokio::test]
async fn missing_api_key_returns_unauthenticated() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = WalletClient::new(channel);

    // No metadata.
    let err = client
        .create_wallet(Request::new(make_create_wallet_request()))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn wrong_api_key_returns_unauthenticated() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = WalletClient::new(channel);

    let mut req = Request::new(make_create_wallet_request());
    req.metadata_mut()
        .insert("x-api-key", MetadataValue::from_static("not-the-key"));
    let err = client.create_wallet(req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn malformed_wallet_id_returns_invalid_argument() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = WalletClient::new(channel);

    let err = client
        .get_wallet(with_api_key(proto::GetWalletRequest {
            wallet_id: "not-a-ulid".into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn unknown_wallet_returns_not_found() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = WalletClient::new(channel);

    let bogus = qfc_wallet_types::WalletId::new().to_string();
    let err = client
        .get_wallet(with_api_key(proto::GetWalletRequest { wallet_id: bogus }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::NotFound);
}

// =============================================================================
// Approver flow: RegisterApprover → CreateApproverSet → SubmitApproval
// =============================================================================

fn ed25519_identity(seed: u8) -> (proto::ApproverIdentity, SigningKey) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let identity = proto::ApproverIdentity {
        identity: Some(proto::approver_identity::Identity::External(
            proto::approver_identity::External {
                id: format!("approver-{seed}"),
                public_key: pk,
                scheme: proto::SigningScheme::Ed25519 as i32,
            },
        )),
    };
    (identity, sk)
}

#[tokio::test]
async fn approver_e2e_register_set_submit_approval() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = ApproverClient::new(channel);

    // Register two approvers.
    let mut ids = Vec::new();
    let mut keys = Vec::new();
    for seed in [11u8, 12u8] {
        let (identity, sk) = ed25519_identity(seed);
        let resp = client
            .register_approver(with_api_key(proto::RegisterApproverRequest {
                identity: Some(identity.clone()),
                label: format!("approver-{seed}"),
                owner_id: "tenant-grpc".into(),
                webhook_url: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        let approver = resp.approver.unwrap();
        assert_eq!(approver.status, proto::ApproverStatus::Active as i32);
        ids.push(approver.approver_id);
        keys.push((sk, identity));
    }

    // CreateApproverSet (M=2, N=2).
    let set_resp = client
        .create_approver_set(with_api_key(proto::CreateApproverSetRequest {
            name: "treasury".into(),
            owner_id: "tenant-grpc".into(),
            members: ids.clone(),
            threshold: 2,
            total: 2,
            quorum_timeout_secs: 0,
        }))
        .await
        .unwrap()
        .into_inner();
    let set = set_resp.approver_set.unwrap();
    assert_eq!(set.threshold, 2);
    assert_eq!(set.total, 2);

    // GetApproverSet round-trip.
    let got = client
        .get_approver_set(with_api_key(proto::GetApproverSetRequest {
            approver_set_id: set.approver_set_id.clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .approver_set
        .unwrap();
    assert_eq!(got.approver_set_id, set.approver_set_id);
    assert_eq!(got.members, ids);

    // SubmitApproval: produce a real signed approval from approver-0.
    let request_id = RequestId::new();
    let approval_id = ApprovalId::new();
    let message_hash = [42u8; 32];
    let ts: i64 = (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .unwrap();
    let preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        ApprovalDecision::Approve,
        ts,
    );
    let (sk, identity) = &keys[0];
    let signature = sk.sign(&preimage).to_bytes().to_vec();

    let submit = proto::SubmitApprovalRequest {
        request_id: request_id.to_string(),
        approver_id: ids[0].clone(),
        approval_id: approval_id.to_string(),
        decision: proto::ApprovalDecision::Approve as i32,
        signature,
        timestamp_unix_ms: ts,
        message_hash: message_hash.to_vec(),
        identity: Some(identity.clone()),
    };
    let r = client
        .submit_approval(with_api_key(submit.clone()))
        .await
        .unwrap()
        .into_inner();
    assert!(r.recorded, "newly-recorded approval");
    assert_eq!(r.approval_id, approval_id.to_string());

    // ListApprovals shows it.
    let listed = client
        .list_approvals(with_api_key(proto::ListApprovalsRequest {
            request_id: request_id.to_string(),
        }))
        .await
        .unwrap()
        .into_inner()
        .approvals;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].decision, proto::ApprovalDecision::Approve as i32);

    // Idempotent re-submit (same payload) returns recorded=false.
    let r2 = client
        .submit_approval(with_api_key(submit))
        .await
        .unwrap()
        .into_inner();
    assert!(!r2.recorded, "second identical submit is idempotent");

    // ListApprovers shows both.
    let listed = client
        .list_approvers(with_api_key(proto::ListApproversRequest {
            owner: "tenant-grpc".into(),
            include_revoked: false,
        }))
        .await
        .unwrap()
        .into_inner()
        .approvers;
    assert_eq!(listed.len(), 2);

    // RevokeApprover then GetApprover shows revoked status.
    let _ = client
        .revoke_approver(with_api_key(proto::RevokeApproverRequest {
            approver_id: ids[0].clone(),
        }))
        .await
        .unwrap();
    let got = client
        .get_approver(with_api_key(proto::GetApproverRequest {
            approver_id: ids[0].clone(),
        }))
        .await
        .unwrap()
        .into_inner()
        .approver
        .unwrap();
    assert_eq!(got.status, proto::ApproverStatus::Revoked as i32);

    // ListApproverSets shows the one we created.
    let sets = client
        .list_approver_sets(with_api_key(proto::ListApproverSetsRequest {
            owner: "tenant-grpc".into(),
        }))
        .await
        .unwrap()
        .into_inner()
        .approver_sets;
    assert_eq!(sets.len(), 1);
}

#[tokio::test]
async fn approver_set_bad_threshold_returns_failed_precondition() {
    let (addr, _shutdown, _dir) = spawn_grpc_server().await;
    let channel = dial(addr).await;
    let mut client = ApproverClient::new(channel);

    let (identity, _) = ed25519_identity(20);
    let registered = client
        .register_approver(with_api_key(proto::RegisterApproverRequest {
            identity: Some(identity),
            label: "solo".into(),
            owner_id: "tenant-bad".into(),
            webhook_url: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
        .approver
        .unwrap();

    // threshold > total — RegistryError::InvalidThreshold.
    let err = client
        .create_approver_set(with_api_key(proto::CreateApproverSetRequest {
            name: "bad".into(),
            owner_id: "tenant-bad".into(),
            members: vec![registered.approver_id],
            threshold: 5,
            total: 1,
            quorum_timeout_secs: 0,
        }))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::FailedPrecondition);
}
