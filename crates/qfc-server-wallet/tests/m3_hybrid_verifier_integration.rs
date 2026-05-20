//! M3 integration tests for the hybrid verifier.
//!
//! Per `docs/m3-decisions.md` D32: this test asserts the byte-layout
//! pre-image computed by `qfc_enclave::hybrid_verifier` matches what
//! `qfc_quorum::SignedApproval::signing_preimage` would produce. If the
//! two crates ever drift, an approver would sign one thing and the
//! verifier would check another.

use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_enclave::enclave::SigningContext;
use qfc_enclave::hybrid_verifier::{HybridVerifier, WalletCeilings};
use qfc_enclave::{EnclaveApproval, EnclaveApprovalDecision};
use qfc_policy::{
    DenyReason, PolicyDecision, RuleHit, SignedPolicyDecision, SigningPayload, SigningRequest,
};
use qfc_quorum::{ApprovalDecision, SignedApproval};
use qfc_wallet_types::{
    ApprovalId, ApproverSetId, DecisionId, HashAlg, PolicyId, RequestId, SigningScheme, WalletId,
};
use sha2::{Digest, Sha256};

fn sha256_32(msg: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg);
    h.finalize().into()
}

#[test]
fn enclave_approval_preimage_matches_qfc_quorum_signing_preimage() {
    // Pick fixed values so the test is deterministic.
    let approval_id = ApprovalId::new();
    let request_id = RequestId::new();
    let message_hash = sha256_32(b"hello qfc");
    let ts: i64 = 1_700_000_000_000;

    // `qfc_quorum::SignedApproval::signing_preimage` is the canonical
    // pre-image the approver client signs.
    let quorum_preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        ApprovalDecision::Approve,
        ts,
    );

    // The enclave's verifier rebuilds the same bytes. We exercise it
    // indirectly via a round-trip: sign with an approver key, hand the
    // EnclaveApproval to the verifier, observe Ok.
    let approver_sk = SigningKey::from_bytes(&[42u8; 32]);
    let approver_pk = approver_sk.verifying_key().to_bytes().to_vec();
    let signature = approver_sk.sign(&quorum_preimage).to_bytes().to_vec();

    let approval = EnclaveApproval {
        approval_id,
        approver_public_key: approver_pk,
        approver_scheme: SigningScheme::Ed25519,
        request_id,
        message_hash,
        decision: EnclaveApprovalDecision::Approve,
        timestamp_unix_ms: ts,
        signature,
    };

    // Build a quorum policy decision and a signing request.
    let policy_sk = SigningKey::from_bytes(&[7u8; 32]);
    let policy_pk = policy_sk.verifying_key().to_bytes().to_vec();
    let verifier = HybridVerifier::new(policy_pk);

    let wallet_id = WalletId::new();
    let signed_at = ts;
    let decision = PolicyDecision::RequireQuorum {
        decision_id: DecisionId::new(),
        policy_id: PolicyId::default(),
        threshold: 1,
        total: 1,
        approver_set: ApproverSetId::new(),
        rationale: Vec::<RuleHit>::new(),
    };
    let preimage =
        SignedPolicyDecision::build_preimage(&decision, &request_id, &wallet_id, signed_at, 60);
    let pol_sig = policy_sk.sign(&preimage).to_bytes().to_vec();
    let signed = SignedPolicyDecision {
        decision,
        request_id,
        wallet_id,
        raw_payload: preimage,
        policy_service_signature: pol_sig,
        signed_at_unix_ms: signed_at,
        max_age_secs: 60,
    };

    let sr = SigningRequest {
        request_id,
        wallet_id,
        requester: qfc_policy::Requester::ApiKey {
            key_id: "test".into(),
        },
        payload: SigningPayload::Raw {
            bytes: b"hello qfc".to_vec(),
        },
        hd_path: None,
        received_at_unix_ms: ts,
    };
    let ceilings = WalletCeilings {
        wallet_id,
        ..Default::default()
    };

    // If the verifier's internal `approval_preimage` does not match
    // `qfc_quorum::SignedApproval::signing_preimage`, the approver's
    // signature will not verify and the test fails.
    verifier
        .verify(Some(&signed), &[approval], &sr, &ceilings, ts)
        .expect("verifier accepts a signed-via-qfc_quorum-preimage approval");
}

#[test]
fn deny_decision_blocks_signing_via_verifier() {
    let policy_sk = SigningKey::from_bytes(&[7u8; 32]);
    let policy_pk = policy_sk.verifying_key().to_bytes().to_vec();
    let verifier = HybridVerifier::new(policy_pk);

    let wallet_id = WalletId::new();
    let request_id = RequestId::new();
    let now_ms = 1_700_000_000_000_i64;

    let decision = PolicyDecision::Deny {
        decision_id: DecisionId::new(),
        policy_id: PolicyId::default(),
        reason: DenyReason::ChainDenied,
        rationale: Vec::new(),
    };
    let preimage =
        SignedPolicyDecision::build_preimage(&decision, &request_id, &wallet_id, now_ms, 60);
    let pol_sig = policy_sk.sign(&preimage).to_bytes().to_vec();
    let signed = SignedPolicyDecision {
        decision,
        request_id,
        wallet_id,
        raw_payload: preimage,
        policy_service_signature: pol_sig,
        signed_at_unix_ms: now_ms,
        max_age_secs: 60,
    };
    let sr = SigningRequest {
        request_id,
        wallet_id,
        requester: qfc_policy::Requester::ApiKey { key_id: "t".into() },
        payload: SigningPayload::Raw {
            bytes: b"x".to_vec(),
        },
        hd_path: None,
        received_at_unix_ms: now_ms,
    };
    let ceilings = WalletCeilings {
        wallet_id,
        ..Default::default()
    };
    let err = verifier.verify(Some(&signed), &[], &sr, &ceilings, now_ms);
    assert!(err.is_err());
}

#[test]
fn enclave_sign_request_keeps_m1_callers_compiling() {
    // Sanity that the additive fields don't force every caller to update —
    // construction with explicit None/Vec::new() is what the orchestrator
    // does in service.rs. If a future refactor removes the Option, this
    // test fails fast.
    let req = qfc_enclave::EnclaveSignRequest {
        request_id: RequestId::new(),
        wallet_id: WalletId::new(),
        shares: Vec::new(),
        scheme: SigningScheme::Ed25519,
        hd_path: None,
        message: b"m".to_vec(),
        hash_alg: HashAlg::None,
        context: SigningContext::default(),
        policy_decision: None,
        approvals: Vec::new(),
    };
    let _ = req;
}
