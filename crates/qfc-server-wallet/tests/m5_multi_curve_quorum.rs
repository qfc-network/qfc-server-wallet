//! M5 — multi-curve quorum integration test.
//!
//! Pins the property that a wallet on **ML-DSA-65** can be authorised by
//! two **ed25519** approvers. This works because of [M4 D16]: every
//! `ApproverIdentity` carries its own `(scheme, public_key)`, so the
//! enclave-side approval verifier runs `dispatch_signer(approver.scheme)`
//! independently of the wallet's signing scheme.
//!
//! What this test demonstrates:
//! 1. `WalletService::create_wallet` on `SigningScheme::MlDsa65` builds
//!    a 1952-byte master public key (FIPS 204 ML-DSA-65 pk size) and
//!    persists SSS shares.
//! 2. Two ed25519 approvers can produce valid `SignedApproval`s for the
//!    in-flight sign request.
//! 3. The orchestrator collects both, the threshold trips, and the sign
//!    completes against the ML-DSA-65 keys inside the enclave.
//! 4. The returned signature verifies as a real FIPS 204 ML-DSA-65
//!    signature against the wallet's master public key.
//!
//! [M4 D16]: ../../docs/m1-decisions.md#d16

#![allow(clippy::too_many_lines)]

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_audit::FileAuditSink;
use qfc_enclave::{MlDsa65Signer, MockEnclave, Signer as EnclaveSigner, SigningContext};
use qfc_policy::{Policy, PolicyDecision, PolicyError, Requester, SigningPayload, SigningRequest};
use qfc_quorum::{
    ApprovalDecision, ApprovalStore, ApproverCreate, ApproverIdentity, ApproverRegistry,
    ApproverSetCreate, MemoryApprovalStore, MemoryApproverRegistry, OrchestratingApprover,
    SignedApproval,
};
use qfc_server_wallet::{WalletConfig, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, ApproverSetId, HashAlg, OwnerId, RequestId, SigningScheme};
use qfc_wallet_types::{DecisionId, PolicyId};

/// A `Policy` that always demands a quorum from the configured set.
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
            id: format!("ed25519-approver-{seed}"),
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
    let ts_ns = time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
    let ts = i64::try_from(ts_ns).unwrap();
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
async fn ed25519_approvers_can_authorize_ml_dsa_65_wallet() {
    let owner = OwnerId::new("tenant-m5-multi-curve");

    // --- Two ed25519 approvers + a 2-of-2 set ---------------------------
    let registry = Arc::new(MemoryApproverRegistry::new());
    let (id_a, sk_a) = ed25519_external(13);
    let (id_b, sk_b) = ed25519_external(14);
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
            name: "pq-treasury".into(),
            owner_id: owner.clone(),
            members: vec![a.approver_id, b.approver_id],
            threshold: 2,
            total: 2,
            quorum_timeout_secs: Some(30),
        })
        .await
        .unwrap();

    // --- Orchestrator + wallet service ----------------------------------
    let store = Arc::new(MemoryApprovalStore::new());
    let orch = Arc::new(
        OrchestratingApprover::builder()
            .with_store(store.clone())
            .with_poll_backoff(Duration::from_millis(20))
            .build(),
    );

    let policy = Arc::new(QuorumOnlyPolicy {
        set: set.id,
        threshold: 2,
        total: 2,
    });
    let enclave = Arc::new(MockEnclave::new_for_testing_with_seed([42u8; 32]));
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

    // --- Create the ML-DSA-65 wallet ------------------------------------
    let wallet = service
        .create_wallet(
            WalletConfig {
                display_name: "pq-treasury".into(),
                owner_id: owner.clone(),
                // The wallet is on ML-DSA-65 — a 1952-byte FIPS 204
                // public key; non-HD (RFC §9.1).
                scheme: SigningScheme::MlDsa65,
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

    // The wallet's master public key is 1952 bytes (FIPS 204 ML-DSA-65).
    assert_eq!(wallet.master_public_key.len(), 1952);

    // --- Submit approvals once the sign starts --------------------------
    let payload_bytes = b"sign me with PQ keys, please".to_vec();
    let message_hash = qfc_quorum::ApprovalRequest::message_hash_for(&payload_bytes);

    let store_for_submit = store.clone();
    let id_a_clone = id_a.clone();
    let id_b_clone = id_b.clone();
    let approver_a_id = a.approver_id;
    let approver_b_id = b.approver_id;
    let audit_path_clone = audit_path.clone();
    let orch_for_submit = orch.clone();

    let submitter = tokio::spawn(async move {
        // Poll the audit ndjson file for the QuorumNotified event so we
        // can read the freshly-minted request_id.
        let request_id = loop {
            if let Ok(bytes) = tokio::fs::read_to_string(&audit_path_clone).await {
                let mut found = None;
                for line in bytes.lines() {
                    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
                        continue;
                    };
                    if v["kind"] == "quorum_notified" {
                        if let Some(s) = v["request_id"].as_str() {
                            if let Ok(r) = s.parse::<RequestId>() {
                                found = Some(r);
                                break;
                            }
                        }
                    }
                }
                if let Some(r) = found {
                    break r;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };

        // Two ed25519-signed approvals for the ML-DSA-65 sign request.
        let a_app = signed_approval(
            &id_a_clone,
            &sk_a,
            request_id,
            message_hash,
            ApprovalDecision::Approve,
        );
        let b_app = signed_approval(
            &id_b_clone,
            &sk_b,
            request_id,
            message_hash,
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
        orch_for_submit.notify_arrival();
    });

    let service_clone = service.clone();
    let wallet_id = wallet.wallet_id;
    let payload_for_sign = payload_bytes.clone();
    let sign_task = tokio::spawn(async move {
        service_clone
            .sign(
                wallet_id,
                SigningPayload::Raw {
                    bytes: payload_for_sign,
                },
                Requester::ApiKey {
                    key_id: "k1".into(),
                },
                // PQ wallets are non-HD (RFC §9.1): hd_path MUST be None.
                None,
                SigningContext::default(),
                // ML-DSA only accepts HashAlg::None (D40).
                HashAlg::None,
            )
            .await
    });

    submitter.await.unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(5), sign_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    // ML-DSA-65 signatures are 3309 bytes.
    assert_eq!(resp.signature.len(), 3309);
    // Signature verifies against the wallet's ML-DSA-65 master public key.
    MlDsa65Signer
        .verify(
            &resp.public_key,
            &payload_bytes,
            &resp.signature,
            HashAlg::None,
        )
        .expect("ml-dsa-65 signature must verify");
    assert_eq!(resp.public_key, wallet.master_public_key);

    // Audit trail mentions both received approvals and threshold trip.
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
