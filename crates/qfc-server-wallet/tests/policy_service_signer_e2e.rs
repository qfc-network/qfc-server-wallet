//! M3 §3.4 follow-up — end-to-end tests for `PolicyServiceSigner` wired
//! through `WalletService::sign` into `MockEnclave`'s hybrid verifier.
//!
//! Coverage:
//! - Happy path: signer wired, mock enclave has matching pubkey, hybrid
//!   verifier accepts, signature returned, audit chain contains
//!   `PolicyDecisionSigned`.
//! - Wrong key: signer signs with key A, mock enclave pins key B's pubkey
//!   → verifier rejects with `InvalidPolicyServiceSignature`.
//! - Stale decision: backdated signer → verifier rejects with
//!   `DecisionStale`.
//! - Hard ceiling violation: wallet has `max_value_per_tx = Some(100)`;
//!   EVM payload encodes `value = 200` → verifier rejects with
//!   `ValueCapExceeded`.
//! - Back-compat: no signer wired → sign still works
//!   (`policy_decision: None` passed through; enclave skips the hybrid
//!   verifier and signs as before).

use std::sync::Arc;

use alloy_rlp::Encodable;
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use qfc_audit::{replay_verify, Actor, FileAuditSink};
use qfc_enclave::{MockEnclave, SigningContext};
use qfc_policy::{
    LocalPolicyServiceSigner, PolicyDecision, PolicyServiceSigner, PolicyServiceSignerError,
    Requester, SignedPolicyDecision, SigningPayload, StaticAllowDenyPolicy, VmType,
};
use qfc_quorum::MockQuorumApprover;
use qfc_server_wallet::{ServiceError, WalletConfig, WalletService};
use qfc_sss::MockShareStore;
use qfc_wallet_types::{HashAlg, OwnerId, RequestId, SigningScheme, WalletId};

/// Build a fully-wired service + (optionally) a `PolicyServiceSigner`
/// + (optionally) a configured `MockEnclave` (with a pinned pubkey).
async fn build_service(
    signer: Option<Arc<dyn PolicyServiceSigner>>,
    mock_pubkey: Option<Vec<u8>>,
    require_signed: bool,
) -> (
    WalletService,
    tempfile::TempDir,
    Vec<u8>, // audit verifying pubkey
) {
    let mut enclave = MockEnclave::new_for_testing_with_seed([7u8; 32]);
    if let Some(pk) = mock_pubkey {
        enclave = enclave.with_policy_service_pubkey(pk);
    }
    if require_signed {
        enclave = enclave.with_require_signed_decision(true);
    }
    let enclave: Arc<dyn qfc_enclave::Enclave> = Arc::new(enclave);
    let shares: Arc<dyn qfc_sss::ShareStore> = Arc::new(MockShareStore::new());
    let policy: Arc<dyn qfc_policy::Policy> = Arc::new(StaticAllowDenyPolicy::allow_all());
    let quorum: Arc<dyn qfc_quorum::QuorumApprover> = Arc::new(MockQuorumApprover::new());
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit.ndjson");
    let audit = FileAuditSink::open(&audit_path, FileAuditSink::random_key())
        .await
        .unwrap();
    let audit_pub = audit.server_public_key();
    let audit: Arc<dyn qfc_audit::AuditSink> = Arc::new(audit);
    let mut service = WalletService::new(enclave, shares, policy, quorum, audit);
    if let Some(s) = signer {
        service = service.with_policy_service_signer(s);
    }
    (service, dir, audit_pub)
}

fn default_config(scheme: SigningScheme) -> WalletConfig {
    WalletConfig {
        display_name: "policy-signer-e2e".into(),
        owner_id: OwnerId::new("tenant-test"),
        scheme,
        threshold: 2,
        total: 3,
        policy_id: qfc_wallet_types::PolicyId::new(),
        max_value_per_tx: None,
        contract_allowlist: Vec::new(),
        chain_allowlist: Vec::new(),
    }
}

/// Minimal EVM legacy tx encoder (mirrors the one in the verifier unit tests).
fn encode_evm_legacy_tx_with_value(to: [u8; 20], value: u64) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    let nonce: u64 = 0;
    let gas_price: u64 = 1;
    let gas_limit: u64 = 21_000;
    let data: Vec<u8> = Vec::new();
    let v: u64 = 0;
    let r: u64 = 0;
    let s: u64 = 0;
    nonce.encode(&mut payload);
    gas_price.encode(&mut payload);
    gas_limit.encode(&mut payload);
    to.as_slice().encode(&mut payload);
    value.encode(&mut payload);
    data.as_slice().encode(&mut payload);
    v.encode(&mut payload);
    r.encode(&mut payload);
    s.encode(&mut payload);
    let mut out = Vec::with_capacity(payload.len() + 4);
    let header = alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    };
    header.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

// -----------------------------------------------------------------------------
// Test 1: happy path — signer + matching enclave pubkey → sign succeeds, audit
// chain contains PolicyDecisionSigned.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn happy_path_sign_with_policy_service_signer() {
    let signer = LocalPolicyServiceSigner::new(SigningKey::from_bytes(&[7u8; 32]));
    let pubkey = signer.public_key().to_vec();
    let signer: Arc<dyn PolicyServiceSigner> = Arc::new(signer);

    let (service, tmp, audit_pub) = build_service(Some(signer), Some(pubkey), true).await;
    let wallet = service
        .create_wallet(default_config(SigningScheme::Ed25519), Actor::System)
        .await
        .unwrap();

    let resp = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw {
                bytes: b"hello hybrid".to_vec(),
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await
        .expect("happy path signs");
    assert_eq!(resp.public_key, wallet.master_public_key);

    // Audit chain replays, AND contains a PolicyDecisionSigned event.
    let path = tmp.path().join("audit.ndjson");
    let n = replay_verify(&path, &audit_pub).await.unwrap();
    // Expect: WalletCreated + SigningRequested + SigningEvaluated +
    // PolicyDecisionSigned + SigningAttempted + SigningSucceeded = 6.
    assert_eq!(n, 6, "expected 6 audit events, got {n}");

    // Read the ndjson file and confirm PolicyDecisionSigned was emitted.
    let body = std::fs::read_to_string(&path).unwrap();
    assert!(
        body.contains("policy_decision_signed"),
        "expected policy_decision_signed in audit log; got:\n{body}"
    );
}

// -----------------------------------------------------------------------------
// Test 2: wrong key — signer is key A, enclave pins key B.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn wrong_policy_service_key_is_rejected() {
    let key_a = SigningKey::from_bytes(&[1u8; 32]);
    let key_b = SigningKey::from_bytes(&[2u8; 32]);
    let signer: Arc<dyn PolicyServiceSigner> = Arc::new(LocalPolicyServiceSigner::new(key_a));
    let wrong_pubkey = key_b.verifying_key().to_bytes().to_vec();

    let (service, _tmp, _audit_pub) = build_service(Some(signer), Some(wrong_pubkey), true).await;
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
        .await
        .expect_err("verifier rejects mismatched key");
    let msg = err.to_string();
    assert!(
        msg.contains("hybrid policy verification failed")
            && msg.contains("policy-service signature invalid"),
        "expected hybrid verification failure mentioning invalid signature, got: {msg}"
    );
}

// -----------------------------------------------------------------------------
// Test 3: stale decision — shim a signer that backdates `signed_at_unix_ms`
// to make every signed decision look ancient (older than `max_age_secs * 2`).
// -----------------------------------------------------------------------------

/// Test-only signer that pre-dates the signature timestamp into the past.
struct StaleSigner {
    inner: LocalPolicyServiceSigner,
    /// How far in the past (in ms) the signed_at gets moved.
    backdate_ms: i64,
}

#[async_trait]
impl PolicyServiceSigner for StaleSigner {
    async fn sign_decision(
        &self,
        decision: PolicyDecision,
        request_id: RequestId,
        wallet_id: WalletId,
        max_age_secs: u32,
    ) -> Result<SignedPolicyDecision, PolicyServiceSignerError> {
        // Reach into the inner signer, then rewrite signed_at_unix_ms and
        // re-sign so the raw_payload + signature match the new timestamp.
        let mut signed = self
            .inner
            .sign_decision(decision, request_id, wallet_id, max_age_secs)
            .await?;
        let new_ts = signed.signed_at_unix_ms - self.backdate_ms;
        // Re-derive preimage with the stale timestamp.
        let preimage = SignedPolicyDecision::build_preimage(
            &signed.decision,
            &signed.request_id,
            &signed.wallet_id,
            new_ts,
            signed.max_age_secs,
        );
        use ed25519_dalek::Signer as _;
        let sk = stale_signer_key();
        let sig = sk.sign(&preimage).to_bytes().to_vec();
        signed.signed_at_unix_ms = new_ts;
        signed.raw_payload = preimage;
        signed.policy_service_signature = sig;
        Ok(signed)
    }

    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }
}

fn stale_signer_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

#[tokio::test]
async fn stale_signed_decision_is_rejected() {
    let inner = LocalPolicyServiceSigner::new(stale_signer_key());
    let pubkey = inner.public_key().to_vec();
    // Backdate by 2 * default max_age_secs (60s) = 120s → stale.
    let signer: Arc<dyn PolicyServiceSigner> = Arc::new(StaleSigner {
        inner,
        backdate_ms: 120_000,
    });
    let (service, _tmp, _ap) = build_service(Some(signer), Some(pubkey), true).await;
    let wallet = service
        .create_wallet(default_config(SigningScheme::Ed25519), Actor::System)
        .await
        .unwrap();
    let err = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw {
                bytes: b"stale-test".to_vec(),
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await
        .expect_err("verifier rejects stale decisions");
    let msg = err.to_string();
    assert!(
        msg.contains("stale"),
        "expected stale-decision rejection, got: {msg}"
    );
}

// -----------------------------------------------------------------------------
// Test 4: hard ceiling violation — wallet has max_value_per_tx = 100, EVM
// payload encodes value = 200 → verifier rejects with ValueCapExceeded.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn value_cap_violation_is_rejected() {
    let signer = LocalPolicyServiceSigner::new(SigningKey::from_bytes(&[9u8; 32]));
    let pubkey = signer.public_key().to_vec();
    let signer: Arc<dyn PolicyServiceSigner> = Arc::new(signer);
    let (service, _tmp, _ap) = build_service(Some(signer), Some(pubkey), true).await;

    // Wallet has a value cap of 100.
    let mut cfg = default_config(SigningScheme::Secp256k1);
    cfg.max_value_per_tx = Some(100);
    let wallet = service.create_wallet(cfg, Actor::System).await.unwrap();

    let to = [0x11u8; 20];
    let raw_tx = encode_evm_legacy_tx_with_value(to, 200);
    let err = service
        .sign(
            wallet.wallet_id,
            SigningPayload::VmTransaction {
                vm: VmType::Evm,
                chain_id: 1,
                to: Some(to.to_vec()),
                raw: raw_tx,
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::Keccak256,
        )
        .await
        .expect_err("verifier enforces wallet hard ceiling");
    let msg = err.to_string();
    assert!(
        msg.contains("value cap exceeded"),
        "expected ValueCapExceeded, got: {msg}"
    );
}

// -----------------------------------------------------------------------------
// Test 5: back-compat — no signer wired, no enclave pubkey pinned → sign
// still works (the verifier is not invoked).
// -----------------------------------------------------------------------------

#[tokio::test]
async fn sign_without_policy_service_signer_still_works() {
    let (service, _tmp, _ap) = build_service(None, None, false).await;
    let wallet = service
        .create_wallet(default_config(SigningScheme::Ed25519), Actor::System)
        .await
        .unwrap();
    let resp = service
        .sign(
            wallet.wallet_id,
            SigningPayload::Raw {
                bytes: b"legacy".to_vec(),
            },
            Requester::ApiKey {
                key_id: "alice".into(),
            },
            None,
            SigningContext::default(),
            HashAlg::None,
        )
        .await
        .expect("unsigned-decision path still signs");
    assert_eq!(resp.public_key, wallet.master_public_key);
}

// -----------------------------------------------------------------------------
// Test 6: signer's preimage round-trips through the verifier byte-for-byte.
// Property-ish: every PolicyDecision signed by LocalPolicyServiceSigner must
// produce a raw_payload accepted by the verifier when binding matches.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn signer_preimage_round_trips_through_verifier() {
    use qfc_enclave::hybrid_verifier::{HybridVerifier, WalletCeilings};
    use qfc_policy::{RuleHit, SigningRequest};
    use qfc_wallet_types::{DecisionId, PolicyId};

    let signer = LocalPolicyServiceSigner::new(SigningKey::from_bytes(&[123u8; 32]));
    let pubkey = signer.public_key().to_vec();

    let request_id = RequestId::new();
    let wallet_id = WalletId::new();
    let decision = PolicyDecision::Allow {
        decision_id: DecisionId::new(),
        policy_id: PolicyId::default(),
        rationale: Vec::<RuleHit>::new(),
    };
    let signed = PolicyServiceSigner::sign_decision(&signer, decision, request_id, wallet_id, 60)
        .await
        .unwrap();
    let now = signed.signed_at_unix_ms;
    let verifier = HybridVerifier::new(pubkey);
    let sr = SigningRequest {
        request_id,
        wallet_id,
        requester: Requester::ApiKey {
            key_id: "test".into(),
        },
        payload: SigningPayload::Raw {
            bytes: b"x".to_vec(),
        },
        hd_path: None,
        received_at_unix_ms: now,
    };
    let ceilings = WalletCeilings {
        wallet_id,
        ..Default::default()
    };
    verifier
        .verify(Some(&signed), &[], &sr, &ceilings, now)
        .expect("signer preimage round-trips through verifier");
}

// -----------------------------------------------------------------------------
// Test 7: ServiceError surface contract — error path doesn't accidentally
// hide hybrid verification failures.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn hybrid_verification_failure_surfaces_as_enclave_error() {
    let key_a = SigningKey::from_bytes(&[1u8; 32]);
    let key_b = SigningKey::from_bytes(&[2u8; 32]);
    let signer: Arc<dyn PolicyServiceSigner> = Arc::new(LocalPolicyServiceSigner::new(key_a));
    let wrong_pubkey = key_b.verifying_key().to_bytes().to_vec();

    let (service, _tmp, _ap) = build_service(Some(signer), Some(wrong_pubkey), true).await;
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
        .await
        .unwrap_err();
    assert!(
        matches!(err, ServiceError::Enclave(_)),
        "hybrid verification failures must surface as ServiceError::Enclave (got {err:?})"
    );
}
