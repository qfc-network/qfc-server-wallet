//! `SignedPolicyDecision` — the hybrid-scheme artifact (RFC §2.1, decision #2).
//!
//! The policy service emits a `PolicyDecision` plus a signature over a
//! canonical preimage so the enclave can re-verify the decision was issued
//! by a trusted authority and bind it to a specific signing request.
//!
//! ## Why this lives in `qfc-policy`
//!
//! `PolicyDecision` is the policy-engine output. The signed wrapper is one
//! pin away from that output — same conceptual layer. Putting it here means
//! `qfc-enclave` can depend on `qfc-policy` for *types*, while still letting
//! the enclave-side verifier (which lives in `qfc-enclave::hybrid_verifier`)
//! own the verification logic.
//!
//! ## Canonical preimage layout
//!
//! The signature covers the byte-string:
//!
//! ```text
//! "qfc-policy-decision-v1"
//!     || 0x00 || serde_json::to_vec(&decision)
//!     || 0x00 || request_id (ULID, ASCII)
//!     || 0x00 || wallet_id  (ULID, ASCII)
//!     || 0x00 || signed_at_unix_ms (i64 big-endian)
//!     || 0x00 || max_age_secs       (u32 big-endian)
//! ```
//!
//! `serde_json::to_vec` of `PolicyDecision` is canonical-enough for M3:
//! the inner `rationale: Vec<RuleHit>` carries `String` IDs and an enum
//! tag, all of which serialize predictably. If we ever need bit-exact
//! canonicalization we can swap to CBOR — `raw_payload` exists to make
//! that swap a non-breaking change.

use qfc_wallet_types::{RequestId, WalletId};
use serde::{Deserialize, Serialize};

use crate::decision::PolicyDecision;

/// Domain-separation prefix for the signature pre-image. Bumping the suffix
/// is a breaking change to every deployed enclave.
pub const POLICY_DECISION_DOMAIN: &str = "qfc-policy-decision-v1";

/// A `PolicyDecision` signed by the policy service, ready for enclave
/// re-verification per RFC §2.1.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyDecision {
    /// The decision itself.
    pub decision: PolicyDecision,
    /// Request the decision was issued for. Bound into the signature.
    pub request_id: RequestId,
    /// Wallet the decision was issued for. Bound into the signature.
    pub wallet_id: WalletId,
    /// Byte-exact serialization of (decision || `request_id` || `wallet_id` ||
    /// `signed_at` || `max_age`). Carried so the verifier never has to
    /// re-serialize anything (which would risk canonicalization drift).
    #[serde(with = "serde_bytes")]
    pub raw_payload: Vec<u8>,
    /// Signature over `raw_payload` by the policy service's key. The
    /// verifier must pin the expected public key out of band (RFC: baked
    /// into the EIF at build time).
    #[serde(with = "serde_bytes")]
    pub policy_service_signature: Vec<u8>,
    /// Issuance timestamp.
    pub signed_at_unix_ms: i64,
    /// How long the decision is valid for (seconds). The verifier rejects
    /// decisions older than this.
    pub max_age_secs: u32,
}

impl SignedPolicyDecision {
    /// Build the canonical preimage that `policy_service_signature` covers.
    ///
    /// Exposed as a free helper so the policy-service signer and the
    /// enclave-side verifier can call into the same code.
    #[must_use]
    pub fn build_preimage(
        decision: &PolicyDecision,
        request_id: &RequestId,
        wallet_id: &WalletId,
        signed_at_unix_ms: i64,
        max_age_secs: u32,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(POLICY_DECISION_DOMAIN.as_bytes());
        buf.push(0x00);
        // serde_json::to_vec is infallible for typed PolicyDecision.
        let decision_bytes = serde_json::to_vec(decision).unwrap_or_default();
        buf.extend_from_slice(&decision_bytes);
        buf.push(0x00);
        buf.extend_from_slice(request_id.to_string().as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(wallet_id.to_string().as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&signed_at_unix_ms.to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&max_age_secs.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{PolicyDecision, RuleHit};
    use qfc_wallet_types::{DecisionId, PolicyId};

    #[test]
    fn preimage_changes_with_request_id() {
        let decision = PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        };
        let w = WalletId::new();
        let r1 = RequestId::new();
        let r2 = RequestId::new();
        let p1 = SignedPolicyDecision::build_preimage(&decision, &r1, &w, 1, 60);
        let p2 = SignedPolicyDecision::build_preimage(&decision, &r2, &w, 1, 60);
        assert_ne!(p1, p2);
    }

    #[test]
    fn preimage_changes_with_wallet_id() {
        let decision = PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        };
        let r = RequestId::new();
        let w1 = WalletId::new();
        let w2 = WalletId::new();
        let p1 = SignedPolicyDecision::build_preimage(&decision, &r, &w1, 1, 60);
        let p2 = SignedPolicyDecision::build_preimage(&decision, &r, &w2, 1, 60);
        assert_ne!(p1, p2);
    }

    #[test]
    fn preimage_changes_with_timestamp() {
        let decision = PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        };
        let r = RequestId::new();
        let w = WalletId::new();
        let p1 = SignedPolicyDecision::build_preimage(&decision, &r, &w, 1, 60);
        let p2 = SignedPolicyDecision::build_preimage(&decision, &r, &w, 2, 60);
        assert_ne!(p1, p2);
    }

    #[test]
    fn preimage_starts_with_domain() {
        let decision = PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        };
        let r = RequestId::new();
        let w = WalletId::new();
        let p = SignedPolicyDecision::build_preimage(&decision, &r, &w, 1, 60);
        assert!(p.starts_with(POLICY_DECISION_DOMAIN.as_bytes()));
    }
}
