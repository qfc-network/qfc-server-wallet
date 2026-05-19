//! Attestation documents.
//!
//! See `docs/server-wallet-rfc.md` §3.4 and §5.3.
//!
//! ## What an attestation actually proves
//!
//! Per the RFC §5.3 honesty clause: a TEE attestation document is **not**
//! a per-computation proof. It is a signed statement of the form
//!
//! > "An enclave whose measurement is PCRs=… had `user_data` = X at time T."
//!
//! The security argument is: if PCR0 binds reproducible code that only
//! emits attestations after performing the corresponding signing
//! operation, then "`user_data` binds the inputs" combined with "PCR0 binds
//! the code" gives you the chain of trust.
//!
//! ## What this M1 layer is
//!
//! `AttestationDoc` is the cross-backend envelope. `MockAttestationKey` is
//! the M1 stand-in: an ed25519 keypair held in-process that signs
//! attestation payloads. `MockEnclave` instances each own one. There is
//! no real PCR binding here; the `pcrs` field reports a sentinel value
//! (see `pcr_mock_sentinel()`) so any code that mistakenly treats a mock
//! attestation as production-grade will fail an obvious comparison.

use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Sentinel PCR byte pattern emitted by `MockAttestationKey`. Production
/// verifiers MUST refuse PCRs whose contents match this pattern — its
/// appearance means the attestation came from the mock backend, not a
/// real TEE. PCRs are 48 bytes wide on Nitro; we mirror that shape.
pub const PCR_MOCK_SENTINEL_LEN: usize = 48;

/// Length of a Nitro-shaped PCR value, in bytes.
pub const PCR_LEN: usize = 48;

/// Construct the mock PCR sentinel as a fresh `Vec<u8>`.
#[must_use]
pub fn pcr_mock_sentinel() -> Vec<u8> {
    vec![0xCD; PCR_MOCK_SENTINEL_LEN]
}

/// Parsed attestation payload. Serialized via JSON (canonical-key-ordered
/// by `BTreeMap`) so the same payload bytes are produced everywhere.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationPayload {
    /// Backend identifier. `"mock"` for `MockAttestationKey`.
    pub backend: String,
    /// Issuance timestamp.
    pub timestamp_unix_ms: i64,
    /// Caller-supplied or backend-generated nonce. For `attest(nonce)` this
    /// is the caller's value; for sign-time attestations it is freshly
    /// random and carried alongside `user_data`.
    pub nonce: [u8; 32],
    /// Platform Configuration Register measurements. The map is `BTreeMap`
    /// so serialization is canonical (sorted u8 keys). For `MockEnclave`,
    /// PCRs 0..=2 carry `pcr_mock_sentinel()`. Each value is `PCR_LEN`
    /// bytes wide.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// Enclave's identity / signing public key (ed25519 32 B for the mock).
    pub attestation_public_key: Vec<u8>,
    /// Arbitrary bytes bound by the attestation. Sign-time attestations put
    /// `(request_id || message_hash || signature_hash || ...)` here per
    /// RFC §4.2 step 16.
    pub user_data: Vec<u8>,
}

/// A signed attestation document. `raw_payload` is the exact bytes that
/// `signature` covers — preserved so any third party can re-verify
/// without re-serializing (which would risk canonicalization drift).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationDoc {
    /// JSON serialization of `payload`. Verifiers MUST sign-verify these
    /// bytes; the `payload` field is provided as a convenience.
    pub raw_payload: Vec<u8>,
    /// Parsed `AttestationPayload` corresponding to `raw_payload`.
    pub payload: AttestationPayload,
    /// Signature over `raw_payload` by the enclave's attestation key.
    pub signature: Vec<u8>,
}

impl AttestationDoc {
    /// Verify the document. Returns `Ok(())` if the embedded signature
    /// validates against the embedded public key.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError::InvalidKey` for a malformed public key,
    /// `AttestationError::InvalidSignature` for a non-verifying signature,
    /// or `AttestationError::PayloadMismatch` if `raw_payload` does not
    /// canonically deserialize to `payload`.
    pub fn verify(&self) -> Result<(), AttestationError> {
        // Sanity: raw_payload must round-trip to payload.
        let reparsed: AttestationPayload = serde_json::from_slice(&self.raw_payload)
            .map_err(|e| AttestationError::PayloadParse(e.to_string()))?;
        if reparsed != self.payload {
            return Err(AttestationError::PayloadMismatch);
        }
        let pk_bytes: [u8; 32] = self
            .payload
            .attestation_public_key
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidKey("expected 32-byte ed25519 pubkey"))?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| AttestationError::InvalidKey("malformed ed25519 pubkey"))?;
        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| AttestationError::InvalidSignature)?;
        vk.verify(
            &self.raw_payload,
            &ed25519_dalek::Signature::from_bytes(&sig_bytes),
        )
        .map_err(|_| AttestationError::InvalidSignature)
    }
}

/// Errors raised when verifying an `AttestationDoc`.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// `raw_payload` failed to deserialize.
    #[error("attestation payload parse error: {0}")]
    PayloadParse(String),

    /// `payload` does not match `raw_payload` (canonicalization drift).
    #[error("attestation payload mismatch")]
    PayloadMismatch,

    /// Public key is malformed.
    #[error("invalid attestation key: {0}")]
    InvalidKey(&'static str),

    /// Signature failed to verify.
    #[error("invalid attestation signature")]
    InvalidSignature,
}

/// In-process attestation key used by `MockEnclave`. Holds an ed25519
/// keypair and produces / signs `AttestationDoc`s.
///
/// NOT for production. Real Nitro / SGX attestation uses platform-rooted
/// keys whose public side has a certificate chain back to the platform
/// vendor (AWS Nitro root, Intel attestation, etc.). The mock has none of
/// that. Production verifiers MUST refuse attestations whose `backend`
/// is `"mock"`.
pub struct MockAttestationKey {
    sk: SigningKey,
    vk: VerifyingKey,
}

impl MockAttestationKey {
    /// Generate a fresh mock attestation key.
    #[must_use]
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        Self { sk, vk }
    }

    /// Construct from an explicit 32-byte seed (deterministic for tests).
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        Self { sk, vk }
    }

    /// Borrow the public attestation key as raw bytes.
    #[must_use]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.vk.to_bytes().to_vec()
    }

    /// Produce an `AttestationDoc` for the given user data and nonce.
    ///
    /// # Errors
    ///
    /// Returns `AttestationError::PayloadParse` if serialization fails
    /// (should be impossible for well-typed inputs).
    pub fn sign_attestation(
        &self,
        nonce: [u8; 32],
        user_data: Vec<u8>,
    ) -> Result<AttestationDoc, AttestationError> {
        let mut pcrs = BTreeMap::new();
        pcrs.insert(0u8, pcr_mock_sentinel());
        pcrs.insert(1u8, pcr_mock_sentinel());
        pcrs.insert(2u8, pcr_mock_sentinel());

        let payload = AttestationPayload {
            backend: "mock".to_string(),
            timestamp_unix_ms: now_unix_ms(),
            nonce,
            pcrs,
            attestation_public_key: self.public_key_bytes(),
            user_data,
        };
        let raw_payload = serde_json::to_vec(&payload)
            .map_err(|e| AttestationError::PayloadParse(e.to_string()))?;
        let signature = self.sk.sign(&raw_payload).to_bytes().to_vec();
        Ok(AttestationDoc {
            raw_payload,
            payload,
            signature,
        })
    }
}

/// Convenience: SHA-256 of `bytes`, as a 32-byte array. Used by callers to
/// pre-hash large blobs before pushing them through `user_data`.
#[must_use]
pub fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn now_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_sign_then_verify() {
        let key = MockAttestationKey::from_seed([7u8; 32]);
        let doc = key.sign_attestation([1u8; 32], b"abc".to_vec()).unwrap();
        doc.verify().expect("doc verifies");
    }

    #[test]
    fn pcr_sentinel_is_present() {
        let key = MockAttestationKey::from_seed([0u8; 32]);
        let doc = key.sign_attestation([0u8; 32], vec![]).unwrap();
        let expected = pcr_mock_sentinel();
        for pcr_idx in 0..=2u8 {
            assert_eq!(
                doc.payload.pcrs.get(&pcr_idx),
                Some(&expected),
                "PCR{pcr_idx} should be the mock sentinel"
            );
        }
    }

    #[test]
    fn modified_payload_rejects() {
        let key = MockAttestationKey::from_seed([7u8; 32]);
        let mut doc = key.sign_attestation([1u8; 32], b"abc".to_vec()).unwrap();
        // Tweak the parsed payload but leave raw_payload intact.
        doc.payload.user_data = b"changed".to_vec();
        assert!(matches!(
            doc.verify(),
            Err(AttestationError::PayloadMismatch)
        ));
    }

    #[test]
    fn modified_raw_payload_rejects() {
        let key = MockAttestationKey::from_seed([7u8; 32]);
        let mut doc = key.sign_attestation([1u8; 32], b"abc".to_vec()).unwrap();
        // Flip a byte deep inside the raw payload; the signature won't match.
        let n = doc.raw_payload.len() / 2;
        doc.raw_payload[n] ^= 0xFF;
        // Verification fails: either PayloadParse if we destroyed JSON, or
        // PayloadMismatch / InvalidSignature otherwise.
        let err = doc.verify();
        assert!(matches!(
            err,
            Err(AttestationError::InvalidSignature
                | AttestationError::PayloadMismatch
                | AttestationError::PayloadParse(_))
        ));
    }

    #[test]
    fn modified_signature_rejects() {
        let key = MockAttestationKey::from_seed([7u8; 32]);
        let mut doc = key.sign_attestation([1u8; 32], b"abc".to_vec()).unwrap();
        doc.signature[0] ^= 0xFF;
        assert!(matches!(
            doc.verify(),
            Err(AttestationError::InvalidSignature)
        ));
    }

    #[test]
    fn distinct_keys_produce_unverifiable_docs_against_each_other() {
        let k1 = MockAttestationKey::from_seed([1u8; 32]);
        let k2 = MockAttestationKey::from_seed([2u8; 32]);
        // Doc signed by k1...
        let mut doc = k1.sign_attestation([0u8; 32], b"x".to_vec()).unwrap();
        // ...but verifier asked to check against k2's pubkey: swap pubkey + re-serialize
        // pyld and tell the doc to use k2's pubkey. Should fail.
        doc.payload.attestation_public_key = k2.public_key_bytes();
        doc.raw_payload = serde_json::to_vec(&doc.payload).unwrap();
        assert!(matches!(
            doc.verify(),
            Err(AttestationError::InvalidSignature)
        ));
    }

    #[test]
    fn deterministic_seed_yields_stable_pubkey() {
        let k1 = MockAttestationKey::from_seed([42u8; 32]);
        let k2 = MockAttestationKey::from_seed([42u8; 32]);
        assert_eq!(k1.public_key_bytes(), k2.public_key_bytes());
    }
}
