//! End-to-end integration tests for `WalletService`.
//!
//! These tests wire up the full M1 stack — `MockEnclave`, `MockShareStore`,
//! `StaticAllowDenyPolicy`, `MockQuorumApprover`, `FileAuditSink` — and
//! exercise the create→sign→verify flow described in RFC §4.

use std::sync::Arc;

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_audit::{replay_verify, Actor, FileAuditSink};
use qfc_enclave::{MockEnclave, SigningContext};
use qfc_policy::{Requester, SigningPayload, StaticAllowDenyPolicy};
use qfc_quorum::{
    ApprovalDecision, ApprovalRequest, ApproverIdentity, MockQuorumApprover, SignedApproval,
};
use qfc_server_wallet::{WalletConfig, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{ApprovalId, HashAlg, OwnerId, RequestId, SigningScheme};

/// Build a fully-wired service backed by all in-memory backends + a
/// `FileAuditSink` rooted at a temp file.
async fn build_service() -> (
    WalletService,
    Arc<MockQuorumApprover>,
    tempfile::TempDir,
    Vec<u8>, // audit verifying pubkey
) {
    let enclave: Arc<dyn qfc_enclave::Enclave> =
        Arc::new(MockEnclave::new_for_testing_with_seed([7u8; 32]));
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::allow_all());
    let quorum = Arc::new(MockQuorumApprover::new());
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit_key = FileAuditSink::random_key();
    let audit = FileAuditSink::open(&audit_path, audit_key).await.unwrap();
    let audit_pub = audit.server_public_key();
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);
    let service = WalletService::new(
        enclave,
        shares,
        policy,
        quorum.clone() as Arc<dyn qfc_quorum::QuorumApprover>,
        audit,
    );
    (service, quorum, dir, audit_pub)
}

fn default_config(scheme: SigningScheme) -> WalletConfig {
    WalletConfig {
        display_name: "e2e test wallet".into(),
        owner_id: OwnerId::new("tenant-test"),
        scheme,
        threshold: 2,
        total: 3,
        policy_id: qfc_wallet_types::PolicyId::new(),
    }
}

#[tokio::test]
async fn create_then_sign_ed25519_end_to_end() {
    let (service, _quorum, _tmp, _audit_pub) = build_service().await;

    let cfg = default_config(SigningScheme::Ed25519);
    let wallet = service
        .create_wallet(cfg.clone(), Actor::System)
        .await
        .unwrap();
    assert_eq!(wallet.master_public_key.len(), 32);

    let msg = b"hello qfc end-to-end".to_vec();
    let resp = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw { bytes: msg.clone() },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await
        .unwrap();

    // Public key matches the wallet's master pubkey.
    assert_eq!(resp.public_key, wallet.master_public_key);

    // Signature verifies externally.
    qfc_enclave::Ed25519Signer
        .verify_helper(&resp.public_key, &msg, &resp.signature)
        .expect("external ed25519 verify");

    // Attestation verifies.
    resp.attestation.verify().expect("attestation verifies");
}

#[tokio::test]
async fn create_then_sign_secp256k1_end_to_end() {
    let (service, _quorum, _tmp, _audit_pub) = build_service().await;

    let cfg = default_config(SigningScheme::Secp256k1);
    let wallet = service.create_wallet(cfg, Actor::System).await.unwrap();
    assert_eq!(wallet.master_public_key.len(), 33);

    let msg = b"secp256k1 e2e payload".to_vec();
    let resp = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw { bytes: msg.clone() },
            Requester::ApiKey {
                key_id: "bob".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::Sha256,
        )
        .await
        .unwrap();

    assert_eq!(resp.public_key, wallet.master_public_key);
    qfc_enclave::Secp256k1Signer
        .verify_helper_with_hash(&resp.public_key, &msg, &resp.signature, HashAlg::Sha256)
        .expect("external secp256k1 verify");
    resp.attestation.verify().unwrap();
}

#[tokio::test]
async fn policy_deny_blocks_signing() {
    let enclave: Arc<dyn qfc_enclave::Enclave> =
        Arc::new(MockEnclave::new_for_testing_with_seed([1u8; 32]));
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::deny_all());
    let quorum: Arc<dyn qfc_quorum::QuorumApprover> = Arc::new(MockQuorumApprover::new());
    let dir = tempfile::tempdir().unwrap();
    let audit = FileAuditSink::open(dir.path().join("audit.ndjson"), FileAuditSink::random_key())
        .await
        .unwrap();
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);
    let service = WalletService::new(enclave, shares, policy, quorum, audit);

    // Wallet creation does not consult policy in M1 — it's a config-time
    // operation. So we still create one.
    let wallet = service
        .create_wallet(default_config(SigningScheme::Ed25519), Actor::System)
        .await
        .unwrap();

    let err = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw {
                bytes: b"x".to_vec(),
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await;
    assert!(matches!(
        err,
        Err(qfc_server_wallet::ServiceError::PolicyDenied(_))
    ));
}

#[tokio::test]
async fn audit_log_replay_verifies_after_full_flow() {
    let (service, _q, tmp, audit_pub) = build_service().await;
    let wallet = service
        .create_wallet(default_config(SigningScheme::Ed25519), Actor::System)
        .await
        .unwrap();

    for i in 0..3 {
        service
            .sign(
                wallet.wallet_id,
                SigningPayload::Raw {
                    bytes: format!("msg-{i}").into_bytes(),
                },
                Requester::ApiKey {
                    key_id: "alice".into(),
                },
                None,
                SigningContext::default(),
                HashAlg::None,
            )
            .await
            .unwrap();
    }

    let n = replay_verify(tmp.path().join("audit.ndjson"), &audit_pub)
        .await
        .unwrap();
    // 1 WalletCreated + 3 * (SigningRequested + SigningEvaluated +
    // SigningAttempted + SigningSucceeded) = 13 events.
    assert_eq!(n, 13);
}

#[tokio::test]
async fn unknown_wallet_returns_not_found() {
    let (service, _q, _tmp, _ap) = build_service().await;
    let err = service
        .sign(
            qfc_wallet_types::WalletId::new(),
            SigningPayload::Raw {
                bytes: b"x".to_vec(),
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await;
    assert!(matches!(
        err,
        Err(qfc_server_wallet::ServiceError::WalletNotFound(_))
    ));
}

#[tokio::test]
async fn quorum_approval_unblocks_sign() {
    // Bespoke service with a policy that always requires quorum (M1
    // simplest way: simulate by submitting pre-staged approvals and
    // wrapping the service quorum config to require 1-of-1). Since
    // StaticAllowDenyPolicy doesn't emit RequireQuorum (M2 territory),
    // we test the quorum subsystem's verify-path directly.
    //
    // This guards the QuorumApprover trait contract; the full
    // policy-driven RequireQuorum integration lands in M4.

    let q = MockQuorumApprover::new();
    let sk = SigningKey::from_bytes(&[42u8; 32]);
    let pk = sk.verifying_key().to_bytes().to_vec();
    let approver = ApproverIdentity::External {
        id: "external-1".into(),
        public_key: pk,
        scheme: SigningScheme::Ed25519,
    };
    let request_id = RequestId::new();
    let msg_hash = [0u8; 32];
    let now_ms = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64 / 1_000_000;

    let approval_id = ApprovalId::new();
    let preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &msg_hash,
        ApprovalDecision::Approve,
        now_ms,
    );
    let signature = sk.sign(&preimage).to_bytes().to_vec();
    let approval = SignedApproval {
        approval_id,
        approver: approver.clone(),
        request_id,
        message_hash: msg_hash,
        decision: ApprovalDecision::Approve,
        timestamp_unix_ms: now_ms,
        signature,
    };

    q.request_approval(&ApprovalRequest {
        request_id,
        message_hash: msg_hash,
        approver_set: vec![approver.clone()],
        threshold: 1,
    })
    .await
    .unwrap();
    q.submit(approval.clone()).await;

    let collected = q
        .collect_approvals(&request_id, 1, std::time::Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(collected.len(), 1);

    use qfc_quorum::QuorumApprover;
    q.verify_approval(&approval, &approver, &msg_hash, now_ms)
        .expect("approval verifies under live trait");
}

// Small re-export helpers so the e2e tests can verify externally without
// reaching into qfc-enclave's private surface.
mod helpers {
    use qfc_enclave::{Ed25519Signer, Secp256k1Signer, Signer, SignerError};
    use qfc_wallet_types::HashAlg;

    pub trait Ed25519External {
        fn verify_helper(
            &self,
            pk: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), SignerError>;
    }
    impl Ed25519External for Ed25519Signer {
        fn verify_helper(
            &self,
            pk: &[u8],
            message: &[u8],
            signature: &[u8],
        ) -> Result<(), SignerError> {
            self.verify(pk, message, signature, HashAlg::None)
        }
    }

    pub trait Secp256k1External {
        fn verify_helper_with_hash(
            &self,
            pk: &[u8],
            message: &[u8],
            signature: &[u8],
            hash: HashAlg,
        ) -> Result<(), SignerError>;
    }
    impl Secp256k1External for Secp256k1Signer {
        fn verify_helper_with_hash(
            &self,
            pk: &[u8],
            message: &[u8],
            signature: &[u8],
            hash: HashAlg,
        ) -> Result<(), SignerError> {
            self.verify(pk, message, signature, hash)
        }
    }
}

use helpers::{Ed25519External, Secp256k1External};
