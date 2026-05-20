//! Enclave-side hybrid policy + approval verifier.
//!
//! See `docs/server-wallet-rfc.md` §2.1 (decision #2) and the M1+M2 retro
//! §3.4 — promoted from "open hook" to "hard M3 GA blocker".
//!
//! The hybrid scheme splits responsibilities:
//!
//! - **Policy service**: full DSL evaluation (rate limits, time windows,
//!   custom rules). Output is a `PolicyDecision` plus a service signature.
//! - **Enclave (this module)**: re-verifies that the signed decision is
//!   authentic, fresh, and binds the *specific* signing request — and
//!   re-checks a small, fixed set of *hard ceilings* against the wallet
//!   record (value cap, contract allowlist, chain allowlist).
//!
//! Flexible rules iterate without rebuilding the EIF. Hard ceilings change
//! the EIF and require a new attestation.
//!
//! ## Why the ceilings are re-checked inside the enclave
//!
//! If only the policy service decided, a compromised policy service could
//! issue an Allow for any value to any target. The enclave's job is to
//! refuse to sign when the decision violates the wallet's own constraints
//! (`max_value_per_tx`, `contract_allowlist`, `chain_allowlist`). Those
//! constraints are stored as enclave-attested data — they cannot be
//! changed without re-attesting the wallet's PCR.
//!
//! ## Wallet ceiling shape (M3 minimum)
//!
//! The enclave doesn't import `WalletRecord` directly (that lives in
//! `qfc-server-wallet` and the enclave should be cleanly testable without
//! it). Instead the orchestrator hands the verifier a `WalletCeilings`
//! struct that projects only the fields the verifier cares about.

use ed25519_dalek::{Signature as EdSignature, Verifier as EdVerifier, VerifyingKey};
use primitive_types::U256;
use qfc_policy::{
    PolicyDecision, SignedPolicyDecision, SigningPayload, SigningRequest, VmType,
    POLICY_DECISION_DOMAIN,
};
use qfc_wallet_types::{RequestId, SigningScheme, WalletId};
use thiserror::Error;

use crate::enclave::{EnclaveApproval, EnclaveApprovalDecision};
use crate::error::SignerError;
use crate::signer::dispatch_signer;

/// Projection of `WalletRecord` carrying only the M3 hard ceilings.
///
/// Constructing this struct directly inside tests is the supported way to
/// exercise the verifier in isolation; `qfc-server-wallet::WalletService`
/// derives it from `WalletConfig` before calling into the enclave.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WalletCeilings {
    /// Wallet id — must match `SignedPolicyDecision.wallet_id`.
    pub wallet_id: WalletId,
    /// Maximum value (in wei / native unit) the wallet may sign per tx.
    /// `None` means no constraint.
    pub max_value_per_tx: Option<u128>,
    /// EVM 20-byte addresses the wallet may sign for. Empty = no constraint.
    pub contract_allowlist: Vec<[u8; 20]>,
    /// Chain IDs the wallet may sign for. Empty = no constraint.
    pub chain_allowlist: Vec<u64>,
}

/// Hard limit on policy-decision age the verifier accepts even if the
/// `max_age_secs` field on the decision itself is larger.
///
/// 24 hours. RFC §5.2 — "Cross-instance replay" is mitigated by binding the
/// `request_id` to the decision; this constant is the belt-and-braces
/// upper bound to keep mis-issued decisions from being long-lived.
pub const MAX_DECISION_AGE_SECS: u32 = 24 * 60 * 60;

/// The maximum number of approvals the verifier processes in one call.
/// A safety bound against denial-of-service via approval flood.
pub const MAX_APPROVALS: usize = 64;

/// Hard limit on approval age the verifier accepts. Matches
/// `qfc_quorum::MAX_APPROVAL_AGE_SECS` so the in-enclave check is no looser
/// than the orchestrator-side check.
pub const MAX_APPROVAL_AGE_SECS_VERIFIER: i64 = 3600;

/// Errors raised by `HybridVerifier::verify`. Every variant is fail-closed.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum HybridVerifyError {
    /// No `SignedPolicyDecision` was provided but the verifier was built
    /// with `require_signed_decision = true`.
    #[error("no signed policy decision provided")]
    MissingPolicyDecision,

    /// Policy-service signature did not verify against the pinned key.
    #[error("policy-service signature invalid")]
    InvalidPolicyServiceSignature,

    /// The decision's raw_payload does not match the canonical preimage
    /// of (decision, request_id, wallet_id, signed_at, max_age).
    #[error("policy decision raw_payload does not match canonical preimage")]
    PolicyDecisionRawPayloadMismatch,

    /// `request_id` on the decision does not match the sign request.
    #[error("policy decision request_id mismatch (expected {expected}, got {got})")]
    RequestIdMismatch {
        /// What the sign request carried.
        expected: RequestId,
        /// What the policy decision carried.
        got: RequestId,
    },

    /// `wallet_id` on the decision does not match the wallet whose shares
    /// are being reconstructed.
    #[error("policy decision wallet_id mismatch (expected {expected}, got {got})")]
    WalletIdMismatch {
        /// What the wallet ceilings carry.
        expected: WalletId,
        /// What the policy decision carried.
        got: WalletId,
    },

    /// The decision is older than `max_age_secs`.
    #[error("policy decision is stale (age {age_secs}s > max_age {max_age_secs}s)")]
    DecisionStale {
        /// Observed age in seconds.
        age_secs: u32,
        /// Configured maximum age.
        max_age_secs: u32,
    },

    /// The decision is timestamped in the future.
    #[error("policy decision timestamp is in the future (signed_at_ms={signed_at_ms})")]
    DecisionFromTheFuture {
        /// Observed timestamp.
        signed_at_ms: i64,
    },

    /// The decision was a hard deny.
    #[error("policy decision is Deny")]
    PolicyDeny,

    /// The signing-request payload exceeds the wallet's `max_value_per_tx`.
    #[error("value cap exceeded: payload {payload} > wallet cap {cap}")]
    ValueCapExceeded {
        /// Decoded payload value (formatted decimal).
        payload: String,
        /// Wallet hard ceiling.
        cap: u128,
    },

    /// The signing-request target is not on the wallet's contract allowlist.
    #[error("target not on allowlist: target={target_hex}")]
    TargetNotAllowed {
        /// Hex of the target address that was rejected.
        target_hex: String,
    },

    /// The signing-request chain_id is not on the wallet's chain allowlist.
    #[error("chain {chain_id} not on wallet allowlist")]
    ChainNotAllowed {
        /// Chain id that was rejected.
        chain_id: u64,
    },

    /// The decision was `RequireQuorum` but not enough valid approvals were
    /// supplied.
    #[error("not enough approvals: {provided} provided, {threshold} required")]
    NotEnoughApprovals {
        /// Approvals that passed validation.
        provided: u8,
        /// Approvals required.
        threshold: u8,
    },

    /// An approval payload was malformed (signature didn't verify, wrong
    /// request_id, etc.).
    #[error("invalid approval: {0}")]
    InvalidApproval(&'static str),

    /// Approval count exceeded `MAX_APPROVALS`. Defensive against caller
    /// flooding the enclave.
    #[error("too many approvals supplied: {count} > {limit}")]
    TooManyApprovals {
        /// Observed approval count.
        count: usize,
        /// Configured maximum.
        limit: usize,
    },

    /// Approval signature couldn't be checked because the underlying signer
    /// rejected it.
    #[error("approval signer error: {0}")]
    ApprovalSignerError(String),

    /// The decoded VM type does not match what the verifier expected (e.g.
    /// the policy decision was for an EVM tx but the payload is non-EVM).
    #[error("unsupported vm type for hard-ceiling re-check: {vm:?}")]
    UnsupportedVmForCeilings {
        /// The unexpected VM tag.
        vm: VmType,
    },
}

impl From<SignerError> for HybridVerifyError {
    fn from(value: SignerError) -> Self {
        Self::ApprovalSignerError(value.to_string())
    }
}

/// In-enclave verifier. Pin the policy-service public key at construction
/// time — in production this would be baked into the EIF (RFC §2.1).
///
/// The verifier is intentionally cheap to construct so test code can
/// re-instantiate per case.
#[derive(Clone)]
pub struct HybridVerifier {
    policy_service_pubkey: Vec<u8>,
    require_signed_decision: bool,
}

impl HybridVerifier {
    /// Construct with a pinned policy-service public key.
    ///
    /// `require_signed_decision = true` forces every sign call to carry a
    /// `SignedPolicyDecision`. The default `new()` enables it; tests that
    /// want to exercise the "no decision" path use
    /// `with_require_signed_decision(false)`.
    #[must_use]
    pub fn new(policy_service_pubkey: Vec<u8>) -> Self {
        Self {
            policy_service_pubkey,
            require_signed_decision: true,
        }
    }

    /// Disable the "missing signed decision is fatal" check (testing /
    /// migration only).
    #[must_use]
    pub fn with_require_signed_decision(mut self, require: bool) -> Self {
        self.require_signed_decision = require;
        self
    }

    /// Borrow the pinned policy-service public key bytes.
    #[must_use]
    pub fn policy_service_pubkey(&self) -> &[u8] {
        &self.policy_service_pubkey
    }

    /// Run all hybrid checks. Returns `Ok(())` if every gate passes.
    ///
    /// The verifier reads the wallet ceilings out-of-band (carried by the
    /// orchestrator), and a fresh `signing_request` so it can do its own
    /// payload-level checks rather than trusting the policy decision's
    /// description.
    ///
    /// # Errors
    ///
    /// Returns the first failure encountered. Fail-closed.
    pub fn verify(
        &self,
        signed_decision: Option<&SignedPolicyDecision>,
        approvals: &[EnclaveApproval],
        signing_request: &SigningRequest,
        wallet: &WalletCeilings,
        now_unix_ms: i64,
    ) -> Result<(), HybridVerifyError> {
        // 0. Bound the input.
        if approvals.len() > MAX_APPROVALS {
            return Err(HybridVerifyError::TooManyApprovals {
                count: approvals.len(),
                limit: MAX_APPROVALS,
            });
        }

        // 1. Signed decision presence.
        let signed = match (signed_decision, self.require_signed_decision) {
            (Some(sd), _) => sd,
            (None, true) => return Err(HybridVerifyError::MissingPolicyDecision),
            (None, false) => {
                // No decision and the verifier is lax — fall through to
                // ceiling checks against the raw signing_request.
                self.check_hard_ceilings(signing_request, wallet)?;
                return Ok(());
            }
        };

        // 2. Re-derive canonical preimage and verify the raw_payload matches.
        let canonical = SignedPolicyDecision::build_preimage(
            &signed.decision,
            &signed.request_id,
            &signed.wallet_id,
            signed.signed_at_unix_ms,
            signed.max_age_secs,
        );
        if canonical != signed.raw_payload {
            return Err(HybridVerifyError::PolicyDecisionRawPayloadMismatch);
        }
        // 2a. Domain-separation prefix is present (defense in depth — the
        //     canonical preimage must always include it).
        if !signed
            .raw_payload
            .starts_with(POLICY_DECISION_DOMAIN.as_bytes())
        {
            return Err(HybridVerifyError::PolicyDecisionRawPayloadMismatch);
        }

        // 3. Verify the policy-service signature over raw_payload.
        verify_ed25519(
            &self.policy_service_pubkey,
            &signed.raw_payload,
            &signed.policy_service_signature,
        )?;

        // 4. Bind to this sign request.
        if signed.request_id != signing_request.request_id {
            return Err(HybridVerifyError::RequestIdMismatch {
                expected: signing_request.request_id,
                got: signed.request_id,
            });
        }
        if signed.wallet_id != wallet.wallet_id {
            return Err(HybridVerifyError::WalletIdMismatch {
                expected: wallet.wallet_id,
                got: signed.wallet_id,
            });
        }

        // 5. Freshness.
        let age_ms = now_unix_ms.saturating_sub(signed.signed_at_unix_ms);
        if age_ms < 0 {
            return Err(HybridVerifyError::DecisionFromTheFuture {
                signed_at_ms: signed.signed_at_unix_ms,
            });
        }
        let age_secs = u32::try_from(age_ms / 1000).unwrap_or(u32::MAX);
        let effective_max = signed.max_age_secs.min(MAX_DECISION_AGE_SECS);
        if age_secs > effective_max {
            return Err(HybridVerifyError::DecisionStale {
                age_secs,
                max_age_secs: effective_max,
            });
        }

        // 6. The decision itself.
        match &signed.decision {
            PolicyDecision::Deny { .. } => return Err(HybridVerifyError::PolicyDeny),
            PolicyDecision::RequireQuorum { threshold, .. } => {
                self.check_approvals(approvals, signing_request, *threshold, now_unix_ms)?;
            }
            PolicyDecision::Allow { .. } => { /* fall through */ }
        }

        // 7. Hard ceilings re-check against the actual payload.
        self.check_hard_ceilings(signing_request, wallet)?;

        Ok(())
    }

    fn check_hard_ceilings(
        &self,
        request: &SigningRequest,
        wallet: &WalletCeilings,
    ) -> Result<(), HybridVerifyError> {
        // Chain allowlist.
        if !wallet.chain_allowlist.is_empty() {
            if let Some(chain_id) = request.payload.chain_id() {
                if !wallet.chain_allowlist.contains(&chain_id) {
                    return Err(HybridVerifyError::ChainNotAllowed { chain_id });
                }
            }
        }

        // Target allowlist — only enforced for EVM-style payloads carrying a
        // 20-byte `to`. QVM minimal / WASM / non-VM payloads bypass this
        // check; they have their own ceiling mechanism in future PRs.
        if !wallet.contract_allowlist.is_empty() {
            if let SigningPayload::VmTransaction {
                vm: VmType::Evm,
                to: Some(to_bytes),
                ..
            } = &request.payload
            {
                if to_bytes.len() != 20 {
                    return Err(HybridVerifyError::TargetNotAllowed {
                        target_hex: hex::encode(to_bytes),
                    });
                }
                let mut to_arr = [0u8; 20];
                to_arr.copy_from_slice(to_bytes);
                if !wallet.contract_allowlist.contains(&to_arr) {
                    return Err(HybridVerifyError::TargetNotAllowed {
                        target_hex: hex::encode(to_bytes),
                    });
                }
            }
        }

        // Value cap — requires decoding the payload `raw`. For M3 we accept
        // an optional pre-decoded `value` field. The orchestrator extracts
        // it via `qfc_policy::decode_evm_tx` before calling the verifier;
        // here we re-decode if the payload is EVM so the enclave doesn't
        // have to trust the host's decoding.
        if let Some(cap) = wallet.max_value_per_tx {
            if let SigningPayload::VmTransaction {
                vm: VmType::Evm,
                raw,
                ..
            } = &request.payload
            {
                let decoded = qfc_policy::decode_evm_tx(raw).map_err(|_| {
                    HybridVerifyError::InvalidApproval("could not decode EVM tx for ceiling check")
                })?;
                if decoded.value > U256::from(cap) {
                    return Err(HybridVerifyError::ValueCapExceeded {
                        payload: decoded.value.to_string(),
                        cap,
                    });
                }
            }
        }

        Ok(())
    }

    fn check_approvals(
        &self,
        approvals: &[EnclaveApproval],
        signing_request: &SigningRequest,
        threshold: u8,
        now_unix_ms: i64,
    ) -> Result<(), HybridVerifyError> {
        // Re-derive the message_hash the approvals should bind to. The
        // orchestrator uses SHA-256 of the canonical signing payload
        // (`qfc_server_wallet::service::canonical_message_bytes`); the
        // enclave does the same — keep them in sync by re-implementing the
        // canonicalization here.
        let canonical_msg = canonical_signing_message(&signing_request.payload);
        let expected_hash = sha256_32(&canonical_msg);

        let mut valid: u8 = 0;
        for ap in approvals {
            // Bind to this request.
            if ap.request_id != signing_request.request_id {
                return Err(HybridVerifyError::InvalidApproval("wrong request_id"));
            }
            if ap.message_hash != expected_hash {
                return Err(HybridVerifyError::InvalidApproval("wrong message_hash"));
            }
            // Reject from-the-future.
            let age_ms = now_unix_ms.saturating_sub(ap.timestamp_unix_ms);
            if age_ms < 0 {
                return Err(HybridVerifyError::InvalidApproval(
                    "approval timestamp is in the future",
                ));
            }
            if age_ms / 1000 > MAX_APPROVAL_AGE_SECS_VERIFIER {
                return Err(HybridVerifyError::InvalidApproval("approval is stale"));
            }
            // Reject explicit rejects.
            if ap.decision == EnclaveApprovalDecision::Reject {
                return Err(HybridVerifyError::InvalidApproval("approver rejected"));
            }
            // Verify the curve signature.
            let preimage = approval_preimage(ap);
            let hash_alg = approval_hash_alg(ap.approver_scheme);
            dispatch_signer(ap.approver_scheme, |signer| {
                signer.verify(&ap.approver_public_key, &preimage, &ap.signature, hash_alg)
            })?;
            valid = valid.saturating_add(1);
        }

        if valid < threshold {
            return Err(HybridVerifyError::NotEnoughApprovals {
                provided: valid,
                threshold,
            });
        }
        Ok(())
    }
}

/// Re-implementation of `qfc_quorum::SignedApproval::signing_preimage` —
/// kept in-crate to avoid the qfc-enclave → qfc-quorum cycle. MUST agree
/// byte-for-byte with the qfc-quorum version; tested by an integration test
/// in `qfc-server-wallet`.
fn approval_preimage(ap: &EnclaveApproval) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26 + 26 + 32 + 1 + 8);
    buf.extend_from_slice(ap.approval_id.to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(ap.request_id.to_string().as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(&ap.message_hash);
    buf.push(b'|');
    buf.push(match ap.decision {
        EnclaveApprovalDecision::Approve => 0x01,
        EnclaveApprovalDecision::Reject => 0x00,
    });
    buf.push(b'|');
    buf.extend_from_slice(&ap.timestamp_unix_ms.to_be_bytes());
    buf
}

/// Hash alg the approver uses to sign their preimage. Mirrors
/// `qfc_quorum::approval::hash_alg_for`.
fn approval_hash_alg(scheme: SigningScheme) -> qfc_wallet_types::HashAlg {
    use qfc_wallet_types::HashAlg;
    match scheme {
        SigningScheme::Ed25519
        | SigningScheme::MlDsa44
        | SigningScheme::MlDsa65
        | SigningScheme::MlDsa87 => HashAlg::None,
        SigningScheme::Secp256k1 | SigningScheme::Secp256k1Recoverable => HashAlg::Sha256,
    }
}

/// Mirror of `qfc_server_wallet::service::canonical_message_bytes`. Kept
/// in-crate so the enclave does not need to depend on `qfc-server-wallet`.
fn canonical_signing_message(payload: &SigningPayload) -> Vec<u8> {
    match payload {
        SigningPayload::Raw { bytes } | SigningPayload::PersonalSign { bytes } => bytes.clone(),
        SigningPayload::TypedData { json } => serde_json::to_vec(json).unwrap_or_default(),
        SigningPayload::VmTransaction { raw, .. } => raw.clone(),
    }
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn verify_ed25519(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), HybridVerifyError> {
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| HybridVerifyError::InvalidPolicyServiceSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| HybridVerifyError::InvalidPolicyServiceSignature)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| HybridVerifyError::InvalidPolicyServiceSignature)?;
    vk.verify(message, &EdSignature::from_bytes(&sig_bytes))
        .map_err(|_| HybridVerifyError::InvalidPolicyServiceSignature)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as EdSigner;
    use ed25519_dalek::SigningKey;
    use qfc_policy::{DenyReason, PolicyDecision, RuleHit};
    use qfc_wallet_types::{DecisionId, HashAlg, PolicyId, RequestId, WalletId};

    fn pol_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    fn pol_pubkey() -> Vec<u8> {
        pol_key().verifying_key().to_bytes().to_vec()
    }

    fn build_signed_decision(
        decision: PolicyDecision,
        request_id: RequestId,
        wallet_id: WalletId,
        signed_at_unix_ms: i64,
        max_age_secs: u32,
    ) -> SignedPolicyDecision {
        let preimage = SignedPolicyDecision::build_preimage(
            &decision,
            &request_id,
            &wallet_id,
            signed_at_unix_ms,
            max_age_secs,
        );
        let sig = pol_key().sign(&preimage).to_bytes().to_vec();
        SignedPolicyDecision {
            decision,
            request_id,
            wallet_id,
            raw_payload: preimage,
            policy_service_signature: sig,
            signed_at_unix_ms,
            max_age_secs,
        }
    }

    fn allow(decision_id: DecisionId) -> PolicyDecision {
        PolicyDecision::Allow {
            decision_id,
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        }
    }

    fn req(request_id: RequestId, wallet_id: WalletId) -> SigningRequest {
        SigningRequest {
            request_id,
            wallet_id,
            requester: qfc_policy::Requester::ApiKey {
                key_id: "test".into(),
            },
            payload: qfc_policy::SigningPayload::Raw {
                bytes: b"msg".to_vec(),
            },
            hd_path: None,
            received_at_unix_ms: 0,
        }
    }

    fn ceilings(wallet_id: WalletId) -> WalletCeilings {
        WalletCeilings {
            wallet_id,
            ..Default::default()
        }
    }

    #[test]
    fn happy_path_allow_passes() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now)
            .expect("happy path");
    }

    #[test]
    fn rejects_wrong_policy_service_signature() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let mut sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        sd.policy_service_signature[0] ^= 0xFF;
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert_eq!(err, Err(HybridVerifyError::InvalidPolicyServiceSignature));
    }

    #[test]
    fn rejects_wrong_pinned_key() {
        let now = 1_000_000;
        let other = SigningKey::from_bytes(&[8u8; 32]);
        let v = HybridVerifier::new(other.verifying_key().to_bytes().to_vec());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert_eq!(err, Err(HybridVerifyError::InvalidPolicyServiceSignature));
    }

    #[test]
    fn rejects_request_id_mismatch() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let signing_request_id = RequestId::new();
        let signed_request_id = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), signed_request_id, w, now, 60);
        let err = v.verify(
            Some(&sd),
            &[],
            &req(signing_request_id, w),
            &ceilings(w),
            now,
        );
        assert!(matches!(
            err,
            Err(HybridVerifyError::RequestIdMismatch { .. })
        ));
    }

    #[test]
    fn rejects_wallet_id_mismatch() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let signed_wallet = WalletId::new();
        let actual_wallet = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, signed_wallet, now, 60);
        let err = v.verify(
            Some(&sd),
            &[],
            &req(r, actual_wallet),
            &ceilings(actual_wallet),
            now,
        );
        assert!(matches!(
            err,
            Err(HybridVerifyError::WalletIdMismatch { .. })
        ));
    }

    #[test]
    fn rejects_stale_decision() {
        let signed_at = 1_000_000_i64;
        let now = signed_at + 70_000; // 70s later, max_age=60s
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, signed_at, 60);
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert!(matches!(err, Err(HybridVerifyError::DecisionStale { .. })));
    }

    #[test]
    fn rejects_from_the_future() {
        let signed_at = 1_000_000_i64;
        let now = signed_at - 5_000; // signed 5s in the future
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, signed_at, 60);
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::DecisionFromTheFuture { .. })
        ));
    }

    #[test]
    fn rejects_explicit_deny() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let deny = PolicyDecision::Deny {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            reason: DenyReason::ChainDenied,
            rationale: Vec::new(),
        };
        let sd = build_signed_decision(deny, r, w, now, 60);
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert_eq!(err, Err(HybridVerifyError::PolicyDeny));
    }

    #[test]
    fn rejects_value_cap_exceeded() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        // Build a real EVM legacy tx with value = 1000.
        let raw_tx = encode_evm_legacy_tx_with_value([0x11u8; 20], 1_000);
        let mut sr = req(r, w);
        sr.payload = SigningPayload::VmTransaction {
            vm: VmType::Evm,
            chain_id: 1,
            to: Some([0x11u8; 20].to_vec()),
            raw: raw_tx,
        };
        let mut c = ceilings(w);
        c.max_value_per_tx = Some(500); // payload exceeds
        let err = v.verify(Some(&sd), &[], &sr, &c, now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::ValueCapExceeded { .. })
        ));
    }

    #[test]
    fn rejects_target_not_in_allowlist() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        let mut sr = req(r, w);
        sr.payload = SigningPayload::VmTransaction {
            vm: VmType::Evm,
            chain_id: 1,
            to: Some([0x22u8; 20].to_vec()),
            raw: encode_evm_legacy_tx_with_value([0x22u8; 20], 1),
        };
        let mut c = ceilings(w);
        c.contract_allowlist = vec![[0x99u8; 20]]; // not 0x22
        let err = v.verify(Some(&sd), &[], &sr, &c, now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::TargetNotAllowed { .. })
        ));
    }

    #[test]
    fn rejects_chain_not_in_allowlist() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        let mut sr = req(r, w);
        sr.payload = SigningPayload::VmTransaction {
            vm: VmType::Evm,
            chain_id: 42,
            to: None,
            raw: vec![],
        };
        let mut c = ceilings(w);
        c.chain_allowlist = vec![1, 137]; // 42 not on it
        let err = v.verify(Some(&sd), &[], &sr, &c, now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::ChainNotAllowed { .. })
        ));
    }

    #[test]
    fn missing_signed_decision_fails_closed_by_default() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let err = v.verify(None, &[], &req(r, w), &ceilings(w), now);
        assert_eq!(err, Err(HybridVerifyError::MissingPolicyDecision));
    }

    #[test]
    fn missing_signed_decision_passes_when_explicitly_relaxed() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey()).with_require_signed_decision(false);
        let r = RequestId::new();
        let w = WalletId::new();
        v.verify(None, &[], &req(r, w), &ceilings(w), now)
            .expect("relaxed verifier accepts missing decision");
    }

    #[test]
    fn quorum_decision_rejects_when_too_few_approvals() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let quorum = PolicyDecision::RequireQuorum {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            threshold: 2,
            total: 3,
            approver_set: qfc_wallet_types::ApproverSetId::new(),
            rationale: Vec::new(),
        };
        let sd = build_signed_decision(quorum, r, w, now, 60);
        // Provide only 1 approval (need 2).
        let one_approval = build_test_approval(r, b"msg", now, &[1u8; 32]);
        let err = v.verify(Some(&sd), &[one_approval], &req(r, w), &ceilings(w), now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::NotEnoughApprovals { .. })
        ));
    }

    #[test]
    fn quorum_decision_passes_with_enough_valid_approvals() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let quorum = PolicyDecision::RequireQuorum {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            threshold: 2,
            total: 3,
            approver_set: qfc_wallet_types::ApproverSetId::new(),
            rationale: Vec::new(),
        };
        let sd = build_signed_decision(quorum, r, w, now, 60);
        let a1 = build_test_approval(r, b"msg", now, &[1u8; 32]);
        let a2 = build_test_approval(r, b"msg", now, &[2u8; 32]);
        v.verify(Some(&sd), &[a1, a2], &req(r, w), &ceilings(w), now)
            .expect("two valid approvals satisfy 2-of-N");
    }

    #[test]
    fn approval_with_tampered_signature_fails_signer_verify() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let quorum = PolicyDecision::RequireQuorum {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            threshold: 1,
            total: 1,
            approver_set: qfc_wallet_types::ApproverSetId::new(),
            rationale: Vec::new(),
        };
        let sd = build_signed_decision(quorum, r, w, now, 60);
        let mut a = build_test_approval(r, b"msg", now, &[1u8; 32]);
        a.signature[0] ^= 0xFF;
        let err = v.verify(Some(&sd), &[a], &req(r, w), &ceilings(w), now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::ApprovalSignerError(_))
        ));
    }

    #[test]
    fn approval_with_wrong_request_id_rejected() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let other_r = RequestId::new();
        let w = WalletId::new();
        let quorum = PolicyDecision::RequireQuorum {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            threshold: 1,
            total: 1,
            approver_set: qfc_wallet_types::ApproverSetId::new(),
            rationale: Vec::new(),
        };
        let sd = build_signed_decision(quorum, r, w, now, 60);
        let a = build_test_approval(other_r, b"msg", now, &[1u8; 32]);
        let err = v.verify(Some(&sd), &[a], &req(r, w), &ceilings(w), now);
        assert!(matches!(err, Err(HybridVerifyError::InvalidApproval(_))));
    }

    #[test]
    fn too_many_approvals_rejected_for_safety() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        let approvals: Vec<_> = (0..(MAX_APPROVALS + 1))
            .map(|i| {
                build_test_approval(r, b"msg", now, &[u8::try_from(i & 0xFF).unwrap_or(1); 32])
            })
            .collect();
        let err = v.verify(Some(&sd), &approvals, &req(r, w), &ceilings(w), now);
        assert!(matches!(
            err,
            Err(HybridVerifyError::TooManyApprovals { .. })
        ));
    }

    #[test]
    fn raw_payload_tamper_rejected() {
        let now = 1_000_000;
        let v = HybridVerifier::new(pol_pubkey());
        let r = RequestId::new();
        let w = WalletId::new();
        let mut sd = build_signed_decision(allow(DecisionId::new()), r, w, now, 60);
        // Flip a byte in raw_payload — preimage check should reject before
        // the signature check.
        let n = sd.raw_payload.len() / 2;
        sd.raw_payload[n] ^= 0x80;
        let err = v.verify(Some(&sd), &[], &req(r, w), &ceilings(w), now);
        assert_eq!(
            err,
            Err(HybridVerifyError::PolicyDecisionRawPayloadMismatch)
        );
    }

    // ---- test helpers ----------------------------------------------------

    fn build_test_approval(
        request_id: RequestId,
        message: &[u8],
        now_unix_ms: i64,
        approver_seed: &[u8; 32],
    ) -> EnclaveApproval {
        let approver_sk = SigningKey::from_bytes(approver_seed);
        let approver_pk = approver_sk.verifying_key().to_bytes().to_vec();
        let approval_id = qfc_wallet_types::ApprovalId::new();
        let message_hash = sha256_32(message);
        let decision = EnclaveApprovalDecision::Approve;

        // Build the exact preimage the verifier expects.
        let mut preimage_buf = Vec::with_capacity(26 + 26 + 32 + 1 + 8);
        preimage_buf.extend_from_slice(approval_id.to_string().as_bytes());
        preimage_buf.push(b'|');
        preimage_buf.extend_from_slice(request_id.to_string().as_bytes());
        preimage_buf.push(b'|');
        preimage_buf.extend_from_slice(&message_hash);
        preimage_buf.push(b'|');
        preimage_buf.push(0x01); // approve
        preimage_buf.push(b'|');
        preimage_buf.extend_from_slice(&now_unix_ms.to_be_bytes());

        // ed25519 signs raw bytes (HashAlg::None).
        let sig = approver_sk.sign(&preimage_buf).to_bytes().to_vec();

        EnclaveApproval {
            approval_id,
            approver_public_key: approver_pk,
            approver_scheme: SigningScheme::Ed25519,
            request_id,
            message_hash,
            decision,
            timestamp_unix_ms: now_unix_ms,
            signature: sig,
        }
    }

    // Minimal EVM legacy tx encoder for value-cap tests. Uses alloy-rlp.
    fn encode_evm_legacy_tx_with_value(to: [u8; 20], value: u64) -> Vec<u8> {
        use alloy_rlp::Encodable;
        // RLP list: [nonce, gas_price, gas_limit, to, value, data, v, r, s]
        // Build via Vec<RlpEncodable>. To keep things simple, write the
        // bytes by hand.
        let mut payload: Vec<u8> = Vec::new();
        // Each item rlp-encoded:
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
        // Wrap in list header.
        let mut out = Vec::with_capacity(payload.len() + 4);
        let header = alloy_rlp::Header {
            list: true,
            payload_length: payload.len(),
        };
        header.encode(&mut out);
        out.extend_from_slice(&payload);
        // The legacy decoder expects raw RLP — what `decode_evm_tx`
        // accepts for non-typed envelopes.
        out
    }

    // Unused but kept for future ceiling helpers.
    #[allow(dead_code)]
    fn _hash_alg_check() -> HashAlg {
        approval_hash_alg(SigningScheme::Ed25519)
    }
}
