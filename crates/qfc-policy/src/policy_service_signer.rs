//! Policy-service signer — produces `SignedPolicyDecision` artifacts.
//!
//! This is the "signer side" of the hybrid scheme. The verifier side lives
//! in `qfc-enclave::hybrid_verifier`. Together they close the M3 §3.4 GA
//! loop: the orchestrator (`qfc-server-wallet::WalletService::sign`) calls
//! a `PolicyServiceSigner` after policy evaluation; the resulting
//! `SignedPolicyDecision` is threaded into `EnclaveSignRequest`, and the
//! enclave re-verifies it before any SSS combine or curve sign happens.
//!
//! ## Production deployment expectation
//!
//! In production the signer is a separate policy-service process holding a
//! KMS-backed ed25519 key, not the orchestrator's own key. The
//! [`LocalPolicyServiceSigner`] in this module is a process-local
//! convenience for dev / tests / single-host deployments; production
//! deployments swap it for a remote-signer impl behind the same trait
//! (e.g. `KmsPolicyServiceSigner`) when that lands.
//!
//! ## Why `max_age_secs` is a per-call parameter
//!
//! See `docs/m3-decisions.md` D33. The freshness ceiling is an
//! operational dial — different signing flows tolerate different replay
//! windows. Embedding it in the signer struct would force one global
//! value; threading it per call lets the orchestrator pick a tight value
//! for normal flows and looser values for batch / scheduled signing.
//! The in-enclave verifier still caps with `MAX_DECISION_AGE_SECS` (24h)
//! so a buggy caller can't bypass the hard ceiling.

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use qfc_wallet_types::{RequestId, WalletId};
use rand_core::{CryptoRng, RngCore};
use thiserror::Error;

use crate::decision::PolicyDecision;
use crate::signed_decision::SignedPolicyDecision;

/// Errors raised by [`PolicyServiceSigner::sign_decision`].
#[derive(Debug, Error)]
pub enum PolicyServiceSignerError {
    /// System clock could not be read (Unix-epoch math overflowed, etc.).
    #[error("could not read system time: {0}")]
    Clock(String),

    /// Backend (KMS, remote signer, ...) refused or could not produce a
    /// signature. The `String` is intentionally narrow — error detail goes
    /// in logs, not into the audit chain.
    #[error("policy-service signer backend failed: {0}")]
    Backend(String),
}

/// Pluggable signer for policy decisions.
///
/// Implementations bind a [`PolicyDecision`] to a specific signing request
/// + wallet, timestamp it, and sign with the policy-service identity key.
/// The returned [`SignedPolicyDecision`] is what the enclave-side
/// `HybridVerifier` consumes (after being threaded through
/// `EnclaveSignRequest`).
///
/// Implementations MUST produce a `raw_payload` byte-identical to the one
/// the verifier rebuilds from `(decision, request_id, wallet_id,
/// signed_at_unix_ms, max_age_secs)` via
/// [`SignedPolicyDecision::build_preimage`]. The default
/// [`LocalPolicyServiceSigner`] does this — alternative impls (KMS, remote
/// signer) MUST call into the same helper.
#[async_trait]
pub trait PolicyServiceSigner: Send + Sync + 'static {
    /// Bind a `PolicyDecision` to a specific signing request + wallet,
    /// timestamp it, and sign with the policy-service identity key.
    ///
    /// Production callers typically pass `max_age_secs` of 30-120 seconds.
    /// Anything larger than [`crate::POLICY_DECISION_DOMAIN`]-implied 24h
    /// is silently capped by the in-enclave verifier
    /// (`MAX_DECISION_AGE_SECS`), so a misconfigured caller can't bypass
    /// the hard ceiling.
    ///
    /// # Errors
    ///
    /// `PolicyServiceSignerError::Backend` when the signer backend
    /// refuses; `PolicyServiceSignerError::Clock` if the system clock
    /// fails.
    async fn sign_decision(
        &self,
        decision: PolicyDecision,
        request_id: RequestId,
        wallet_id: WalletId,
        max_age_secs: u32,
    ) -> Result<SignedPolicyDecision, PolicyServiceSignerError>;

    /// The pinned public key the enclave verifier was constructed with.
    /// Used by tests + ops to confirm the signer<->verifier are paired.
    fn public_key(&self) -> &[u8];
}

/// Process-local `PolicyServiceSigner` backed by an in-memory ed25519
/// signing key. Suitable for dev / tests / single-host deployments.
///
/// Production deployments should use a KMS-backed implementation behind
/// the same trait (see module docs).
pub struct LocalPolicyServiceSigner {
    signing_key: SigningKey,
    public_key: Vec<u8>,
}

impl LocalPolicyServiceSigner {
    /// Construct from an existing ed25519 signing key.
    #[must_use]
    pub fn new(signing_key: SigningKey) -> Self {
        let public_key = signing_key.verifying_key().to_bytes().to_vec();
        Self {
            signing_key,
            public_key,
        }
    }

    /// Generate a fresh signing key from `rng`. Test / dev helper.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        let signing_key = SigningKey::from_bytes(&secret);
        // Best-effort zeroize of the local copy. `SigningKey` itself
        // zeroizes on drop.
        secret.iter_mut().for_each(|b| *b = 0);
        Self::new(signing_key)
    }

    /// Borrow the public key as raw bytes (32-byte ed25519).
    #[must_use]
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

#[async_trait]
impl PolicyServiceSigner for LocalPolicyServiceSigner {
    async fn sign_decision(
        &self,
        decision: PolicyDecision,
        request_id: RequestId,
        wallet_id: WalletId,
        max_age_secs: u32,
    ) -> Result<SignedPolicyDecision, PolicyServiceSignerError> {
        let signed_at_unix_ms = current_unix_ms()?;
        let preimage = SignedPolicyDecision::build_preimage(
            &decision,
            &request_id,
            &wallet_id,
            signed_at_unix_ms,
            max_age_secs,
        );
        let signature = self.signing_key.sign(&preimage).to_bytes().to_vec();
        Ok(SignedPolicyDecision {
            decision,
            request_id,
            wallet_id,
            raw_payload: preimage,
            policy_service_signature: signature,
            signed_at_unix_ms,
            max_age_secs,
        })
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

fn current_unix_ms() -> Result<i64, PolicyServiceSignerError> {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|e| PolicyServiceSignerError::Clock(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{PolicyDecision, RuleHit};
    use ed25519_dalek::{Verifier as DalekVerifier, VerifyingKey};
    use qfc_wallet_types::{DecisionId, PolicyId};

    fn allow() -> PolicyDecision {
        PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        }
    }

    #[tokio::test]
    async fn signs_with_canonical_preimage() {
        let policy_signer = LocalPolicyServiceSigner::new(SigningKey::from_bytes(&[7u8; 32]));
        let request_id = RequestId::new();
        let wallet_id = WalletId::new();
        let decision = allow();
        let bundle = policy_signer
            .sign_decision(decision.clone(), request_id, wallet_id, 60)
            .await
            .unwrap();

        // raw_payload is exactly what the verifier rebuilds.
        let expected = SignedPolicyDecision::build_preimage(
            &decision,
            &request_id,
            &wallet_id,
            bundle.signed_at_unix_ms,
            60,
        );
        assert_eq!(bundle.raw_payload, expected);

        // Signature verifies under the pinned public key.
        let pk_bytes: [u8; 32] = policy_signer.public_key().try_into().unwrap();
        let vk = VerifyingKey::from_bytes(&pk_bytes).unwrap();
        let sig_bytes: [u8; 64] = bundle
            .policy_service_signature
            .as_slice()
            .try_into()
            .unwrap();
        vk.verify(
            &bundle.raw_payload,
            &ed25519_dalek::Signature::from_bytes(&sig_bytes),
        )
        .expect("signature verifies");
    }

    #[tokio::test]
    async fn bound_to_request_and_wallet_ids() {
        let policy_signer = LocalPolicyServiceSigner::new(SigningKey::from_bytes(&[3u8; 32]));
        let r = RequestId::new();
        let w = WalletId::new();
        let bundle = policy_signer
            .sign_decision(allow(), r, w, 60)
            .await
            .unwrap();
        assert_eq!(bundle.request_id, r);
        assert_eq!(bundle.wallet_id, w);
        assert_eq!(bundle.max_age_secs, 60);
    }

    #[tokio::test]
    async fn generate_yields_unique_keys() {
        use rand::rngs::OsRng;
        let s1 = LocalPolicyServiceSigner::generate(&mut OsRng);
        let s2 = LocalPolicyServiceSigner::generate(&mut OsRng);
        assert_ne!(s1.public_key(), s2.public_key());
    }
}
