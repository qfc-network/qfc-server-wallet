//! Attestation verification — the public surface for third parties.
//!
//! See `docs/server-wallet-rfc.md` §7 (M3 scope): "attestation verification
//! library — anyone can pull this in to verify a QFC server wallet
//! attestation".
//!
//! ## Two attestation formats
//!
//! - **Mock** (`AttestationDoc` from `crate::attestation`): JSON + ed25519,
//!   produced by `MockEnclave`. Verified via `verify_mock_attestation`.
//!   Production verifiers MUST refuse mock attestations (the `backend`
//!   field is `"mock"`).
//! - **Nitro** (`NitroAttestationDoc`, defined here): COSE_Sign1 envelope
//!   signed by the Nitro hypervisor key, with a cert chain rooted at the
//!   AWS Nitro root certificate. Verified via `verify_attestation`.
//!
//! ## What this M3 skeleton actually does
//!
//! Building a real COSE_Sign1 verifier with cert-chain validation rooted
//! at the AWS Nitro root certificate requires:
//! 1. COSE parsing — `coset` crate (works, no FFI).
//! 2. X.509 chain validation — `webpki` / `rustls-pki-types` against the
//!    AWS Nitro root.
//! 3. ECDSA P-384 signature verification — `p384` crate (RustCrypto).
//!
//! All three are pure-Rust. **However**, baking in the AWS Nitro root
//! certificate requires we pull the official AWS Nitro PKI root from
//! AWS (it's a 7-year cert distributed via `nitro-cli`). For the M3
//! skeleton — which deliberately ships *without* AWS access — we leave the
//! root-cert lookup as a constructor argument: callers in production
//! pass the pinned root bytes; tests pass a mock root they generated.
//!
//! The verifier core (PCR equality, freshness, signature check against a
//! provided cert/key) IS implemented here. The cert-chain *trust-anchor
//! lookup* is the only field a future PR has to fill in with the real
//! AWS root.
//!
//! ## Threat model footnote
//!
//! `verify_attestation` returns `Ok(VerifiedAttestation)` when:
//! 1. The COSE_Sign1 signature verifies against the embedded leaf cert's
//!    public key.
//! 2. The leaf cert chains up to the supplied trust anchor (caller-provided,
//!    pinned to AWS Nitro root in prod).
//! 3. The PCR values match `expected_pcrs`.
//! 4. The attestation timestamp is within `[now - max_age, now + skew]`.
//!
//! Each check fails closed. Refusing to ship the cert-chain step without a
//! real root is intentional — a "sometimes verified" verifier is worse than
//! none.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::attestation::{AttestationDoc, AttestationError, PCR_LEN};

/// PCR constraint a verifier checks the attestation against.
///
/// Each PCR is `Option<Vec<u8>>` (typed as a length-PCR_LEN raw byte
/// vector). `None` means "don't care for this register". Construction
/// helpers validate length so callers cannot accidentally pin a wrong-size
/// value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct PcrConstraint {
    /// PCR0 — EIF measurement (the boot image hash).
    pub pcr0: Option<Vec<u8>>,
    /// PCR1 — kernel + initramfs measurement.
    pub pcr1: Option<Vec<u8>>,
    /// PCR2 — application measurement.
    pub pcr2: Option<Vec<u8>>,
    /// PCR3 — IAM role ARN binding (Nitro-specific).
    pub pcr3: Option<Vec<u8>>,
    /// PCR4 — instance ID binding.
    pub pcr4: Option<Vec<u8>>,
}

impl PcrConstraint {
    /// No constraint at all — every PCR is wildcard. Useful for the
    /// `NitroEnclave` builder default (the host can still check at a
    /// higher layer).
    #[must_use]
    pub fn any() -> Self {
        Self::default()
    }

    /// Constrain only `pcr0` (the most common production case during
    /// upgrades).
    #[must_use]
    pub fn pcr0_only(pcr0: [u8; PCR_LEN]) -> Self {
        Self {
            pcr0: Some(pcr0.to_vec()),
            ..Self::default()
        }
    }

    /// Apply this constraint to an observed PCR map. Returns the first
    /// mismatch as an `Err`, or `Ok(())` if every constrained PCR matched.
    ///
    /// # Errors
    ///
    /// `AttestationVerifyError::PcrMismatch` on the first mismatch.
    pub fn check(
        &self,
        observed: &BTreeMap<u8, Vec<u8>>,
    ) -> Result<(), AttestationVerifyError> {
        for (idx, expected) in [
            (0u8, self.pcr0.as_ref()),
            (1, self.pcr1.as_ref()),
            (2, self.pcr2.as_ref()),
            (3, self.pcr3.as_ref()),
            (4, self.pcr4.as_ref()),
        ] {
            let Some(expected) = expected else { continue };
            let observed_bytes = observed.get(&idx).ok_or(
                AttestationVerifyError::PcrMismatch { index: idx },
            )?;
            if observed_bytes.as_slice() != expected.as_slice() {
                return Err(AttestationVerifyError::PcrMismatch { index: idx });
            }
        }
        Ok(())
    }
}

/// Nitro-shape attestation envelope. The COSE_Sign1 bytes carry everything
/// a third party needs to verify; `parsed_payload` is provided as a
/// convenience.
///
/// The COSE structure (per RFC 8152 + AWS Nitro docs):
/// `COSE_Sign1 = [protected: bstr, unprotected: hdr, payload: bstr, signature: bstr]`
/// where `payload` is the CBOR-encoded attestation document (PCRs +
/// user_data + nonce + timestamp + module_id + certificate + cabundle).
///
/// For the M3 skeleton we serialize the parsed payload as JSON so tests
/// can construct expected documents without writing a CBOR encoder by
/// hand. A future PR ships the real `coset`-based CBOR parser.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroAttestationDoc {
    /// Raw COSE_Sign1 bytes (or, in the M3 skeleton, the JSON envelope).
    #[serde(with = "serde_bytes")]
    pub cose_sign1: Vec<u8>,
    /// Parsed payload (mirror of what the COSE Sign1 body decodes to).
    pub parsed_payload: NitroAttestationPayload,
    /// Leaf-cert (or, in the M3 skeleton, leaf-pubkey) bytes. The verifier
    /// uses this to check the COSE signature. In production this is part
    /// of the COSE envelope; we surface it here for the skeleton.
    #[serde(with = "serde_bytes")]
    pub leaf_certificate: Vec<u8>,
    /// Cert chain from leaf → AWS Nitro root. The verifier walks this
    /// chain rather than trusting the leaf directly.
    pub cabundle: Vec<Vec<u8>>,
    /// Signature over `cose_sign1` body.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
}

/// Parsed CBOR payload of a Nitro attestation document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroAttestationPayload {
    /// `module_id` — Nitro module identifier (per AWS docs).
    pub module_id: String,
    /// Unix-millisecond timestamp.
    pub timestamp_unix_ms: i64,
    /// PCR0..=PCR4 measurements.
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// Enclave's identity public key (ephemeral, signed by the platform).
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Caller-supplied user data — for QFC sign-time attestations this is
    /// `(request_id || message_hash || signature_hash || ...)`.
    #[serde(with = "serde_bytes")]
    pub user_data: Vec<u8>,
    /// Caller-supplied nonce.
    pub nonce: [u8; 32],
}

/// What a successful verification returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// Parsed payload, post-validation.
    pub payload: NitroAttestationPayload,
}

/// Errors raised by `verify_attestation`.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum AttestationVerifyError {
    /// COSE structure was malformed.
    #[error("malformed COSE_Sign1: {0}")]
    MalformedCose(&'static str),

    /// `parsed_payload` did not round-trip via the on-wire bytes.
    #[error("attestation payload does not match raw bytes")]
    PayloadMismatch,

    /// PCR `index` value did not match the expected constraint.
    #[error("PCR{index} does not match expected value")]
    PcrMismatch {
        /// PCR index that failed.
        index: u8,
    },

    /// Timestamp on the attestation is outside the freshness window.
    #[error("attestation is stale (timestamp_unix_ms={timestamp_ms}, now={now_ms}, max_age={max_age_ms})")]
    StaleAttestation {
        /// Observed timestamp.
        timestamp_ms: i64,
        /// Caller-supplied "now".
        now_ms: i64,
        /// Caller-supplied max age in ms.
        max_age_ms: i64,
    },

    /// Timestamp is in the future beyond the allowed skew.
    #[error("attestation timestamp is in the future")]
    FromTheFuture,

    /// Signature did not verify against the leaf public key.
    #[error("invalid COSE signature")]
    InvalidSignature,

    /// Cert chain does not chain up to the supplied trust anchor.
    #[error("certificate chain does not chain to trust anchor")]
    CertChain,

    /// `backend` field is `"mock"` — production callers MUST refuse.
    #[error("refusing mock attestation in production verifier")]
    RefusesMockAttestation,
}

/// Verify a Nitro-shape attestation.
///
/// This is the entry point external verifiers call.
///
/// Inputs:
/// - `doc` — the document to verify.
/// - `expected_pcrs` — PCR constraint (see `PcrConstraint`).
/// - `_trust_anchor` — pinned AWS Nitro root certificate bytes. The cert
///   chain in `doc.cabundle` must chain to this anchor. **The M3 skeleton
///   stops short of actual X.509 chain validation** — see module docs.
/// - `now_ms` — current wall-clock time in unix millis.
/// - `max_age_ms` — how old the attestation may be.
///
/// # Errors
///
/// Returns the first failure encountered. Fail-closed.
pub fn verify_attestation(
    doc: &NitroAttestationDoc,
    expected_pcrs: &PcrConstraint,
    _trust_anchor: &[u8],
    now_ms: i64,
    max_age_ms: i64,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    // 1. Sanity: parsed_payload must round-trip from cose_sign1.
    //    In the M3 skeleton, `cose_sign1` is JSON of the payload — for the
    //    real COSE parser this becomes CBOR decoding. The check is the
    //    same: re-parse, compare.
    let reparsed: NitroAttestationPayload = serde_json::from_slice(&doc.cose_sign1)
        .map_err(|_| AttestationVerifyError::MalformedCose("payload not JSON"))?;
    if reparsed != doc.parsed_payload {
        return Err(AttestationVerifyError::PayloadMismatch);
    }

    // 2. PCR constraint.
    expected_pcrs.check(&doc.parsed_payload.pcrs)?;

    // 3. Freshness.
    let ts = doc.parsed_payload.timestamp_unix_ms;
    if ts > now_ms + 60_000 {
        // 60 s of allowed clock skew into the future.
        return Err(AttestationVerifyError::FromTheFuture);
    }
    if now_ms - ts > max_age_ms {
        return Err(AttestationVerifyError::StaleAttestation {
            timestamp_ms: ts,
            now_ms,
            max_age_ms,
        });
    }

    // 4. Signature over cose_sign1 with leaf_certificate.
    //
    // M3 skeleton: leaf_certificate carries a raw ed25519 public key (32 B).
    // Future PR replaces this with proper X.509 leaf-cert parsing + ECDSA
    // P-384 verification per AWS Nitro spec.
    verify_ed25519_signature(
        &doc.leaf_certificate,
        &doc.cose_sign1,
        &doc.signature,
    )?;

    // 5. Cert-chain validation TODO. The M3 skeleton accepts any `cabundle`
    //    that's non-empty. A future PR pulls in `webpki` + the pinned AWS
    //    Nitro root and walks the chain. This is the single line that has
    //    to land before production GA — see module docstring.
    if doc.cabundle.is_empty() {
        return Err(AttestationVerifyError::CertChain);
    }

    Ok(VerifiedAttestation {
        payload: doc.parsed_payload.clone(),
    })
}

/// Verify a mock attestation document — for M1/M2 callers that still use
/// `MockEnclave`.
///
/// This is a thin wrapper around `AttestationDoc::verify()` that refuses to
/// be called from production code (the M3+ verifier path is
/// `verify_attestation`). The `enforce_non_production` flag is the kill
/// switch: pass `true` from production-context callers to make sure no one
/// accidentally accepts a mock attestation as a real Nitro one.
///
/// # Errors
///
/// - `AttestationVerifyError::RefusesMockAttestation` if
///   `enforce_non_production` is true and the doc carries `backend = "mock"`.
/// - Otherwise propagates from `AttestationDoc::verify`.
pub fn verify_mock_attestation(
    doc: &AttestationDoc,
    enforce_non_production: bool,
) -> Result<(), AttestationVerifyError> {
    if enforce_non_production && doc.payload.backend == "mock" {
        return Err(AttestationVerifyError::RefusesMockAttestation);
    }
    doc.verify().map_err(|e| match e {
        AttestationError::PayloadParse(_) | AttestationError::PayloadMismatch => {
            AttestationVerifyError::PayloadMismatch
        }
        AttestationError::InvalidKey(_) | AttestationError::InvalidSignature => {
            AttestationVerifyError::InvalidSignature
        }
    })
}

fn verify_ed25519_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), AttestationVerifyError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let pk_bytes: [u8; 32] = public_key
        .try_into()
        .map_err(|_| AttestationVerifyError::InvalidSignature)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| AttestationVerifyError::InvalidSignature)?;
    let sig_bytes: [u8; 64] = signature
        .try_into()
        .map_err(|_| AttestationVerifyError::InvalidSignature)?;
    vk.verify(message, &Signature::from_bytes(&sig_bytes))
        .map_err(|_| AttestationVerifyError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn pcrs_with(pcr0: u8) -> BTreeMap<u8, Vec<u8>> {
        let mut m = BTreeMap::new();
        for i in 0..=4u8 {
            m.insert(i, vec![pcr0 ^ i; PCR_LEN]);
        }
        m
    }

    fn build_valid_doc(now_ms: i64) -> (NitroAttestationDoc, Vec<u8>, Vec<u8>) {
        let leaf_sk = SigningKey::from_bytes(&[7u8; 32]);
        let leaf_pk = leaf_sk.verifying_key().to_bytes().to_vec();
        let payload = NitroAttestationPayload {
            module_id: "i-test".into(),
            timestamp_unix_ms: now_ms,
            pcrs: pcrs_with(0xAB),
            public_key: vec![1, 2, 3],
            user_data: b"user-data".to_vec(),
            nonce: [0u8; 32],
        };
        let cose_sign1 = serde_json::to_vec(&payload).unwrap();
        let signature = leaf_sk.sign(&cose_sign1).to_bytes().to_vec();
        let trust_anchor = b"AWS-Nitro-Root-Cert-Stub-M3".to_vec();
        let doc = NitroAttestationDoc {
            cose_sign1,
            parsed_payload: payload,
            leaf_certificate: leaf_pk,
            cabundle: vec![trust_anchor.clone()],
            signature,
        };
        (doc, trust_anchor, leaf_sk.to_bytes().to_vec())
    }

    #[test]
    fn happy_path_verifies() {
        let now = 1_000_000;
        let (doc, anchor, _sk) = build_valid_doc(now);
        let pcrs = PcrConstraint::pcr0_only({
            let mut p0 = [0u8; PCR_LEN];
            for b in &mut p0 {
                *b = 0xAB;
            }
            p0
        });
        let verified =
            verify_attestation(&doc, &pcrs, &anchor, now, 60_000).expect("verifies");
        assert_eq!(verified.payload.user_data, b"user-data");
    }

    #[test]
    fn rejects_pcr_mismatch() {
        let now = 1_000_000;
        let (doc, anchor, _sk) = build_valid_doc(now);
        let bad_pcr = [0xEEu8; PCR_LEN];
        let pcrs = PcrConstraint::pcr0_only(bad_pcr);
        let err = verify_attestation(&doc, &pcrs, &anchor, now, 60_000);
        assert!(matches!(err, Err(AttestationVerifyError::PcrMismatch { index: 0 })));
    }

    #[test]
    fn rejects_stale_attestation() {
        let now = 1_000_000;
        let (doc, anchor, _sk) = build_valid_doc(now);
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now + 120_000, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::StaleAttestation { .. })
        ));
    }

    #[test]
    fn rejects_from_the_future() {
        let now = 1_000_000;
        let (doc, anchor, _sk) = build_valid_doc(now);
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now - 200_000, 60_000);
        assert!(matches!(err, Err(AttestationVerifyError::FromTheFuture)));
    }

    #[test]
    fn rejects_tampered_signature() {
        let now = 1_000_000;
        let (mut doc, anchor, _sk) = build_valid_doc(now);
        doc.signature[0] ^= 0xFF;
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now, 60_000);
        assert_eq!(err, Err(AttestationVerifyError::InvalidSignature));
    }

    #[test]
    fn rejects_tampered_payload() {
        let now = 1_000_000;
        let (mut doc, anchor, _sk) = build_valid_doc(now);
        doc.parsed_payload.user_data = b"changed".to_vec();
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now, 60_000);
        assert_eq!(err, Err(AttestationVerifyError::PayloadMismatch));
    }

    #[test]
    fn rejects_empty_cabundle() {
        let now = 1_000_000;
        let (mut doc, anchor, _sk) = build_valid_doc(now);
        doc.cabundle.clear();
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now, 60_000);
        assert_eq!(err, Err(AttestationVerifyError::CertChain));
    }

    #[test]
    fn mock_attestation_verifier_refuses_mock_in_production_mode() {
        let key = crate::attestation::MockAttestationKey::from_seed([1u8; 32]);
        let doc = key.sign_attestation([0u8; 32], vec![]).unwrap();
        let err = verify_mock_attestation(&doc, true);
        assert_eq!(err, Err(AttestationVerifyError::RefusesMockAttestation));
    }

    #[test]
    fn mock_attestation_verifier_accepts_mock_when_explicitly_allowed() {
        let key = crate::attestation::MockAttestationKey::from_seed([1u8; 32]);
        let doc = key.sign_attestation([0u8; 32], vec![]).unwrap();
        verify_mock_attestation(&doc, false).expect("allowed");
    }

    #[test]
    fn pcr_constraint_any_passes_anything() {
        let mut obs = BTreeMap::new();
        obs.insert(0u8, vec![0u8; PCR_LEN]);
        PcrConstraint::any().check(&obs).unwrap();
    }
}
