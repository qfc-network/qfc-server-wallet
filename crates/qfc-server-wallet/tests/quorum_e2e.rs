//! End-to-end test of the M4 RequireQuorum sign flow with the real
//! `OrchestratingApprover` and `MemoryApprovalStore`.
//!
//! The policy module's `RuleSetPolicy` emits `RequireQuorum` for value-gte
//! rules; we use a tiny policy that always returns `RequireQuorum` so this
//! test stays focused on the orchestrator + service integration.

#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_audit::FileAuditSink;
use qfc_enclave::{MockEnclave, SigningContext};
use qfc_policy::{Policy, PolicyDecision, PolicyError, Requester, SigningPayload, SigningRequest};
use qfc_quorum::{
    ApprovalDecision, ApprovalRequest, ApprovalStore, ApproverCreate, ApproverIdentity,
    ApproverRegistry, ApproverSetCreate, MemoryApprovalStore, MemoryApproverRegistry,
    OrchestratingApprover, RecordOutcome, SignedApproval,
};
use qfc_server_wallet::{WalletConfig, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, ApproverSetId, HashAlg, OwnerId, RequestId, SigningScheme};
use qfc_wallet_types::{DecisionId, PolicyId};

/// A `Policy` that always returns `RequireQuorum(set, threshold)`.
struct QuorumOnlyPolicy {
    set: ApproverSetId,
    threshold: u8,
    total: u8,
}

#[async_trait]
impl Policy for QuorumOnlyPolicy {
    async fn evaluate(&self, _req: &SigningRequest) -> Result<PolicyDecision, PolicyError> {
        Ok(PolicyDecision::RequireQuorum {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::new(),
            threshold: self.threshold,
            total: self.total,
            approver_set: self.set,
            rationale: vec![],
        })
    }
}

fn ed25519_external(seed: u8) -> (ApproverIdentity, SigningKey) {
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

fn signed_approval(
    identity: &ApproverIdentity,
    sk: &SigningKey,
    request_id: RequestId,
    message_hash: [u8; 32],
    decision: ApprovalDecision,
) -> SignedApproval {
    let approval_id = ApprovalId::new();
    let ts = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let ts = i64::try_from(ts).unwrap();
    let pre =
        SignedApproval::signing_preimage(&approval_id, &request_id, &message_hash, decision, ts);
    let sig = sk.sign(&pre).to_bytes().to_vec();
    SignedApproval {
        approval_id,
        approver: identity.clone(),
        request_id,
        message_hash,
        decision,
        timestamp_unix_ms: ts,
        signature: sig,
    }
}

#[tokio::test]
async fn quorum_collect_threshold_unblocks_sign() {
    let owner = OwnerId::new("tenant-quorum");

    // Registry: register two approvers + a 2-of-2 set.
    let registry = Arc::new(MemoryApproverRegistry::new());
    let (id_a, sk_a) = ed25519_external(7);
    let (id_b, sk_b) = ed25519_external(8);
    let a = registry
        .add_approver(ApproverCreate {
            identity: id_a.clone(),
            label: "alice".into(),
            owner_id: owner.clone(),
            webhook_url: None,
        })
        .await
        .unwrap();
    let b = registry
        .add_approver(ApproverCreate {
            identity: id_b.clone(),
            label: "bob".into(),
            owner_id: owner.clone(),
            webhook_url: None,
        })
        .await
        .unwrap();
    let set = registry
        .create_approver_set(ApproverSetCreate {
            name: "treasury".into(),
            owner_id: owner.clone(),
            members: vec![a.approver_id, b.approver_id],
            threshold: 2,
            total: 2,
            quorum_timeout_secs: Some(30),
        })
        .await
        .unwrap();

    // Build the orchestrator with a `MemoryApprovalStore`.
    let store = Arc::new(MemoryApprovalStore::new());
    let orch = Arc::new(
        OrchestratingApprover::builder()
            .with_store(store.clone())
            .with_poll_backoff(Duration::from_millis(20))
            .build(),
    );

    // Build the service with a quorum-only policy referencing our set.
    let policy = Arc::new(QuorumOnlyPolicy {
        set: set.id,
        threshold: 2,
        total: 2,
    });
    let enclave = Arc::new(MockEnclave::new_for_testing_with_seed([7u8; 32]));
    let shares = Arc::new(MockShareStore::new());
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit = Arc::new(
        FileAuditSink::open(&audit_path, FileAuditSink::random_key())
            .await
            .unwrap(),
    );
    let service = Arc::new(
        WalletService::new(enclave, shares, policy, orch.clone(), audit)
            .with_approver_registry(registry.clone())
            .with_approval_store(store.clone())
            .with_quorum_timeout(Duration::from_secs(5)),
    );

    // Create a wallet.
    let wallet = service
        .create_wallet(
            WalletConfig {
                display_name: "treasury".into(),
                owner_id: owner.clone(),
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                policy_id: qfc_wallet_types::PolicyId::new(),
                max_value_per_tx: None,
                contract_allowlist: Vec::new(),
                chain_allowlist: Vec::new(),
            },
            qfc_audit::Actor::System,
        )
        .await
        .unwrap();

    // Pre-stage the two approvals BEFORE the sign call. Because the
    // service generates a fresh request_id per sign, we'd normally need to
    // race the submission. Instead: pre-stage in a parallel task once the
    // sign starts.
    let service_clone = service.clone();
    let wallet_id = wallet.wallet_id;
    let payload_bytes = b"approval flow happy path".to_vec();
    let message_hash = qfc_quorum::ApprovalRequest::message_hash_for(&payload_bytes);

    // We need the request_id that `sign` mints. Easiest path: monkey-patch
    // the orchestrator by submitting approvals using the message_hash and
    // grabbing the request_id from the store, but the orchestrator polls
    // by request_id we don't know yet.
    //
    // Better: pre-supply a SignedApproval that uses a manually-fixed
    // request_id, then make the request a `Raw{bytes}` payload whose
    // canonical bytes hash to `message_hash`, and watch the orchestrator
    // for the *real* request_id via a spy task. The simplest reliable
    // approach: drive sign concurrently and submit when we see the
    // QuorumNotified audit entry.
    //
    // Concrete here: spawn the submitter, then call sign. The submitter
    // polls `service.approval_store().list_for_request(...)` is empty so
    // we can't see request_id that way. Use a notify channel via
    // `OrchestratingApprover::notify_arrival`? No — we need the
    // request_id from the policy. Approach: have the submitter read the
    // audit ndjson file for the QuorumNotified event and extract
    // request_id from there.
    //
    // Cleaner: run sign in a task and submit by tailing the audit file.
    let store_for_submit = store.clone();
    let id_a_clone = id_a.clone();
    let id_b_clone = id_b.clone();
    let approver_a_id = a.approver_id;
    let approver_b_id = b.approver_id;
    let audit_path_clone = audit_path.clone();
    let submitter = tokio::spawn(async move {
        // Poll the audit file for a QuorumNotified event.
        loop {
            if let Ok(bytes) = tokio::fs::read_to_string(&audit_path_clone).await {
                for line in bytes.lines() {
                    let v: serde_json::Value = match serde_json::from_str(line) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    if v["kind"] == "quorum_notified" {
                        if let Some(s) = v["request_id"].as_str() {
                            if let Ok(r) = s.parse::<RequestId>() {
                                return (r, message_hash);
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    });

    // Spawn the sign — the submitter runs in parallel.
    let sign_task = tokio::spawn(async move {
        service_clone
            .sign(
                wallet_id,
                SigningPayload::Raw {
                    bytes: payload_bytes,
                },
                Requester::ApiKey {
                    key_id: "k1".into(),
                },
                None,
                SigningContext::default(),
                HashAlg::None,
            )
            .await
    });

    // Drive the submitter: once it surfaces the request_id, record both
    // approvals into the store and wake the collector.
    let (request_id, msg_hash) = tokio::time::timeout(Duration::from_secs(5), submitter)
        .await
        .unwrap()
        .unwrap();
    let a_app = signed_approval(
        &id_a_clone,
        &sk_a,
        request_id,
        msg_hash,
        ApprovalDecision::Approve,
    );
    let b_app = signed_approval(
        &id_b_clone,
        &sk_b,
        request_id,
        msg_hash,
        ApprovalDecision::Approve,
    );
    store_for_submit
        .record_approval(&a_app, approver_a_id)
        .await
        .unwrap();
    store_for_submit
        .record_approval(&b_app, approver_b_id)
        .await
        .unwrap();
    orch.notify_arrival();

    let resp = tokio::time::timeout(Duration::from_secs(5), sign_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(!resp.signature.is_empty());

    // Audit-log includes both `QuorumApprovalReceived` and
    // `QuorumThresholdReached`.
    let bytes = tokio::fs::read_to_string(&audit_path).await.unwrap();
    let kinds: Vec<String> = bytes
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["kind"].as_str().map(ToString::to_string))
        })
        .collect();
    assert!(kinds.contains(&"quorum_notified".to_string()));
    assert!(kinds.contains(&"quorum_approval_received".to_string()));
    assert!(kinds.contains(&"quorum_threshold_reached".to_string()));
    assert!(kinds.contains(&"signing_succeeded".to_string()));
}

#[tokio::test]
async fn quorum_collect_times_out_when_no_approvals() {
    let owner = OwnerId::new("tenant-timeout");
    let registry = Arc::new(MemoryApproverRegistry::new());
    let (id_a, _sk_a) = ed25519_external(31);
    let a = registry
        .add_approver(ApproverCreate {
            identity: id_a,
            label: "alice".into(),
            owner_id: owner.clone(),
            webhook_url: None,
        })
        .await
        .unwrap();
    let set = registry
        .create_approver_set(ApproverSetCreate {
            name: "single".into(),
            owner_id: owner.clone(),
            members: vec![a.approver_id],
            threshold: 1,
            total: 1,
            quorum_timeout_secs: Some(1),
        })
        .await
        .unwrap();

    let store = Arc::new(MemoryApprovalStore::new());
    let orch = Arc::new(
        OrchestratingApprover::builder()
            .with_store(store.clone())
            .build(),
    );
    let policy = Arc::new(QuorumOnlyPolicy {
        set: set.id,
        threshold: 1,
        total: 1,
    });
    let enclave = Arc::new(MockEnclave::new_for_testing_with_seed([1u8; 32]));
    let shares = Arc::new(MockShareStore::new());
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit = Arc::new(
        FileAuditSink::open(&audit_path, FileAuditSink::random_key())
            .await
            .unwrap(),
    );
    let service = WalletService::new(enclave, shares, policy, orch, audit)
        .with_approver_registry(registry)
        .with_approval_store(store);
    let wallet = service
        .create_wallet(
            WalletConfig {
                display_name: "ttl".into(),
                owner_id: owner,
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                policy_id: qfc_wallet_types::PolicyId::new(),
                max_value_per_tx: None,
                contract_allowlist: Vec::new(),
                chain_allowlist: Vec::new(),
            },
            qfc_audit::Actor::System,
        )
        .await
        .unwrap();

    let err = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw { bytes: vec![0u8] },
            Requester::ApiKey { key_id: "k".into() },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await;
    assert!(
        matches!(
            err,
            Err(qfc_server_wallet::ServiceError::Quorum(
                qfc_quorum::QuorumError::Timeout(_)
            ))
        ),
        "expected timeout, got {err:?}"
    );

    let kinds: Vec<String> = tokio::fs::read_to_string(&audit_path)
        .await
        .unwrap()
        .lines()
        .filter_map(|l| {
            serde_json::from_str::<serde_json::Value>(l)
                .ok()
                .and_then(|v| v["kind"].as_str().map(ToString::to_string))
        })
        .collect();
    assert!(kinds.contains(&"quorum_timed_out".to_string()));
}

// Silence unused import warnings if API drift occurs.
#[allow(dead_code)]
fn _force_use(_: ApprovalRequest, _: RecordOutcome) {}
