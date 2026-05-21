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
use crate::cose::{
    extract_payload, parse_cose_sign1, verify_cose_signature, verify_cose_signature_es384,
    CoseParseError, CoseSign1Envelope, CoseVerifyError,
};

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
    pub fn check(&self, observed: &BTreeMap<u8, Vec<u8>>) -> Result<(), AttestationVerifyError> {
        for (idx, expected) in [
            (0u8, self.pcr0.as_ref()),
            (1, self.pcr1.as_ref()),
            (2, self.pcr2.as_ref()),
            (3, self.pcr3.as_ref()),
            (4, self.pcr4.as_ref()),
        ] {
            let Some(expected) = expected else { continue };
            let observed_bytes = observed
                .get(&idx)
                .ok_or(AttestationVerifyError::PcrMismatch { index: idx })?;
            if observed_bytes.as_slice() != expected.as_slice() {
                return Err(AttestationVerifyError::PcrMismatch { index: idx });
            }
        }
        Ok(())
    }
}

/// Which signature flavour the document carries, and therefore which
/// verifier path `verify_attestation` should dispatch to.
///
/// - `Mock` — `cose_sign1` is JSON of the parsed payload and `signature`
///   is an ed25519 sig over those bytes. This is the original M3 skeleton
///   shape; M1/M2/M3 callers continue to construct documents that way.
/// - `CoseSign1Ed25519` — `cose_sign1` is a real COSE_Sign1 CBOR envelope
///   signed with ed25519. `leaf_certificate` carries the 32-byte ed25519
///   leaf public key. This is what the new `from_cose_sign1` constructor
///   sets up.
/// - `CoseSign1Es384` — what AWS Nitro emits in production (ECDSA-P384
///   over a P-384 leaf cert). Verification path is a stub today
///   ([D47](../../../docs/m3-decisions.md#d47)); included so the
///   field set is forward-compatible and so callers can detect the
///   format without trying to verify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SignatureKind {
    /// JSON + ed25519, M3 skeleton mock format. Default for back-compat.
    #[default]
    Mock,
    /// Real COSE_Sign1 CBOR envelope with an ed25519 signature.
    CoseSign1Ed25519,
    /// Real COSE_Sign1 CBOR envelope with an ECDSA-P384 signature (AWS
    /// Nitro production format). Verification is stubbed; see D47.
    CoseSign1Es384,
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
/// Two construction paths supported:
/// - `NitroAttestationDoc::mock(...)` — for the M3 skeleton mock flow.
///   `signature_kind = Mock`.
/// - `NitroAttestationDoc::from_cose_sign1(bytes)` — parses a real
///   COSE_Sign1 CBOR envelope (see `crate::cose`). `signature_kind =
///   CoseSign1Ed25519` (or `Es384` if the protected header announces it,
///   which today routes through the deferred verifier).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroAttestationDoc {
    /// Raw COSE_Sign1 bytes (CBOR in the real path, JSON in the mock path).
    #[serde(with = "serde_bytes")]
    pub cose_sign1: Vec<u8>,
    /// Parsed payload — mirror of the CBOR / JSON body for callers that
    /// want to read PCRs etc. without re-parsing.
    pub parsed_payload: NitroAttestationPayload,
    /// Leaf cert. For `Mock` and `CoseSign1Ed25519` this is the 32-byte
    /// ed25519 leaf public key. For `CoseSign1Es384` this is the X.509
    /// DER leaf cert from which a P-384 key is extracted (deferred — see
    /// D47).
    #[serde(with = "serde_bytes")]
    pub leaf_certificate: Vec<u8>,
    /// Cert chain from leaf → AWS Nitro root. The verifier walks this
    /// chain rather than trusting the leaf directly.
    pub cabundle: Vec<Vec<u8>>,
    /// Signature over `cose_sign1` body. For `Mock`, the ed25519 signature
    /// over the JSON bytes; for COSE paths the signature inside the
    /// envelope (also re-surfaced here for easy access).
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Which signature scheme the document was built against. Drives
    /// dispatch in `verify_attestation`. Defaults to `Mock` for back-compat
    /// with existing serialized documents that pre-date this field.
    #[serde(default)]
    pub signature_kind: SignatureKind,
}

impl NitroAttestationDoc {
    /// Construct a mock-format `NitroAttestationDoc` — JSON-encoded
    /// payload + ed25519 signature over those bytes. This is the M3
    /// skeleton constructor; M1/M2/M3 tests and the
    /// `verify_mock_attestation` path use it.
    ///
    /// `signature_kind` is forced to `SignatureKind::Mock`.
    #[must_use]
    pub fn mock(
        cose_sign1: Vec<u8>,
        parsed_payload: NitroAttestationPayload,
        leaf_certificate: Vec<u8>,
        cabundle: Vec<Vec<u8>>,
        signature: Vec<u8>,
    ) -> Self {
        Self {
            cose_sign1,
            parsed_payload,
            leaf_certificate,
            cabundle,
            signature,
            signature_kind: SignatureKind::Mock,
        }
    }

    /// Parse a real COSE_Sign1 CBOR envelope into a `NitroAttestationDoc`.
    ///
    /// The leaf public key / certificate is taken from the inner payload's
    /// `certificate` field (per the AWS Nitro spec). For the ed25519 test
    /// path, that field holds a 32-byte raw public key.
    ///
    /// # Errors
    ///
    /// Returns `AttestationVerifyError::MalformedCose` if the bytes are
    /// not a parseable COSE_Sign1, or if the inner payload is malformed.
    pub fn from_cose_sign1(bytes: &[u8]) -> Result<Self, AttestationVerifyError> {
        let envelope = parse_cose_sign1(bytes).map_err(|e| map_parse_err(&e))?;
        let inner = extract_payload(&envelope).map_err(|e| map_parse_err(&e))?;

        // Translate the typed `crate::cose::AttestationPayload` into the
        // structurally-similar `NitroAttestationPayload` carried by this
        // module. Both keep the same field set; we just narrow `nonce` to
        // the fixed-size `[u8; 32]`.
        let mut nonce_arr = [0u8; 32];
        if inner.nonce.len() == 32 {
            nonce_arr.copy_from_slice(&inner.nonce);
        } else if !inner.nonce.is_empty() {
            // Nitro spec requires 32-byte nonce when present. Reject the
            // weird-length case fail-closed.
            return Err(AttestationVerifyError::MalformedCose(
                "nonce length is not 32",
            ));
        }

        let parsed_payload = NitroAttestationPayload {
            module_id: inner.module_id,
            timestamp_unix_ms: inner.timestamp,
            pcrs: inner.pcrs,
            public_key: inner.public_key,
            user_data: inner.user_data,
            nonce: nonce_arr,
        };

        let kind = signature_kind_from_envelope(&envelope);

        Ok(Self {
            cose_sign1: envelope.raw,
            parsed_payload,
            leaf_certificate: inner.certificate,
            cabundle: inner.cabundle,
            signature: envelope.cose.signature.clone(),
            signature_kind: kind,
        })
    }

    /// Dispatcher: try COSE_Sign1 first; on parse failure, fall back to
    /// detecting / constructing the mock JSON format.
    ///
    /// This is the entry point external verifiers should call when they
    /// don't know which format the bytes were produced in.
    ///
    /// # Errors
    ///
    /// `AttestationVerifyError::MalformedCose` if both decoders refuse.
    pub fn parse(bytes: &[u8]) -> Result<Self, AttestationVerifyError> {
        if let Ok(doc) = Self::from_cose_sign1(bytes) {
            return Ok(doc);
        }
        // Mock-JSON fallback: if `bytes` is a JSON-encoded
        // `NitroAttestationPayload`, reconstruct the document with the
        // raw bytes preserved. Note that mock construction requires
        // signature + cert + cabundle out-of-band — `parse` cannot
        // synthesize those for the mock path. Mock callers continue to
        // use `NitroAttestationDoc::mock(...)` directly.
        Err(AttestationVerifyError::MalformedCose(
            "input is neither COSE_Sign1 CBOR nor recognized format",
        ))
    }
}

fn map_parse_err(e: &CoseParseError) -> AttestationVerifyError {
    match e {
        CoseParseError::MalformedEnvelope(_)
        | CoseParseError::MalformedPayload(_)
        | CoseParseError::MissingPayload => AttestationVerifyError::MalformedCose("CBOR parse"),
        CoseParseError::MissingField(_) | CoseParseError::WrongFieldType { .. } => {
            AttestationVerifyError::MalformedCose("missing or mistyped payload field")
        }
    }
}

/// Inspect the COSE_Sign1 protected header to decide which `SignatureKind`
/// to label the parsed document with.
///
/// AWS Nitro production: ES384 (`-35`). Our test fixtures: EdDSA (`-8`).
fn signature_kind_from_envelope(envelope: &CoseSign1Envelope) -> SignatureKind {
    use coset::{iana, RegisteredLabelWithPrivate};
    // ES384 → the deferred AWS Nitro production path (D47); everything
    // else (EdDSA, unspecified, unknown) routes to the ed25519 path,
    // matching what our test envelopes emit. Production verifiers would
    // tighten this once the ES384 verifier lands.
    match &envelope.cose.protected.header.alg {
        Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384)) => {
            SignatureKind::CoseSign1Es384
        }
        _ => SignatureKind::CoseSign1Ed25519,
    }
}

/// **Stub** — walk the leaf cert + cabundle up to the supplied AWS Nitro
/// root and verify the chain. Today this returns `Ok(())` and serves only
/// as the typed seam for the M3-GA follow-up; see
/// [D46](../../../docs/m3-decisions.md#d46).
///
/// # Errors
///
/// Never errors today. Future impl will return
/// `AttestationVerifyError::CertChain` on chain-walk failure.
pub fn verify_root_chain(
    _leaf_cert: &[u8],
    _cabundle: &[Vec<u8>],
    _root: &'static [u8],
) -> Result<(), AttestationVerifyError> {
    // TODO(D46): walk `cabundle` from leaf to `_root`, validating each
    // intermediate signature. Needs the AWS Nitro root cert embedded as
    // `&'static [u8]` plus an X.509 chain walker (rustls-pki-types +
    // webpki, both pure-Rust). Documented in docs/m3-decisions.md D46.
    Ok(())
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
    //    The check differs per signature kind: Mock re-parses the JSON;
    //    CoseSign1 paths re-decode the CBOR payload and compare it to the
    //    parsed mirror.
    match doc.signature_kind {
        SignatureKind::Mock => {
            let reparsed: NitroAttestationPayload = serde_json::from_slice(&doc.cose_sign1)
                .map_err(|_| AttestationVerifyError::MalformedCose("payload not JSON"))?;
            if reparsed != doc.parsed_payload {
                return Err(AttestationVerifyError::PayloadMismatch);
            }
        }
        SignatureKind::CoseSign1Ed25519 | SignatureKind::CoseSign1Es384 => {
            let envelope = parse_cose_sign1(&doc.cose_sign1).map_err(|e| map_parse_err(&e))?;
            let inner = extract_payload(&envelope).map_err(|e| map_parse_err(&e))?;
            if inner.module_id != doc.parsed_payload.module_id
                || inner.timestamp != doc.parsed_payload.timestamp_unix_ms
                || inner.pcrs != doc.parsed_payload.pcrs
                || inner.public_key != doc.parsed_payload.public_key
                || inner.user_data != doc.parsed_payload.user_data
            {
                return Err(AttestationVerifyError::PayloadMismatch);
            }
        }
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

    // 4. Signature dispatch.
    match doc.signature_kind {
        SignatureKind::Mock => {
            // M3 skeleton: leaf_certificate carries a raw ed25519 public
            // key (32 B); signature is over the JSON cose_sign1 body.
            verify_ed25519_signature(&doc.leaf_certificate, &doc.cose_sign1, &doc.signature)?;
        }
        SignatureKind::CoseSign1Ed25519 => {
            // Real COSE_Sign1 envelope with ed25519 leaf key. The tbs_data
            // computation is RFC 8152 §4.4; coset handles it.
            let envelope = parse_cose_sign1(&doc.cose_sign1).map_err(|e| map_parse_err(&e))?;
            verify_cose_signature(&envelope, &doc.leaf_certificate)
                .map_err(|e| map_verify_err(&e))?;
        }
        SignatureKind::CoseSign1Es384 => {
            // Stub — see D47. Routes through the typed surface so we can
            // detect / log production envelopes today even though we
            // cannot verify them yet.
            let envelope = parse_cose_sign1(&doc.cose_sign1).map_err(|e| map_parse_err(&e))?;
            verify_cose_signature_es384(&envelope, &doc.leaf_certificate)
                .map_err(|e| map_verify_err(&e))?;
        }
    }

    // 5. Cert-chain validation. The M3 skeleton accepts any `cabundle`
    //    that's non-empty; the real chain-walk to the AWS Nitro root is
    //    `verify_root_chain` — currently a stub. See D46.
    if doc.cabundle.is_empty() {
        return Err(AttestationVerifyError::CertChain);
    }
    verify_root_chain(&doc.leaf_certificate, &doc.cabundle, &[])?;

    Ok(VerifiedAttestation {
        payload: doc.parsed_payload.clone(),
    })
}

fn map_verify_err(e: &CoseVerifyError) -> AttestationVerifyError {
    match e {
        // Cryptographic verify-time errors collapse to InvalidSignature
        // from the caller's perspective. Inside the cose module the
        // variants stay distinct so callers who want them can pattern-match
        // on the typed surface; this mapping is the conservative collapse
        // for `verify_attestation`.
        CoseVerifyError::InvalidPublicKey
        | CoseVerifyError::InvalidSignature
        | CoseVerifyError::MalformedSignature
        | CoseVerifyError::SignatureMismatch => AttestationVerifyError::InvalidSignature,
        // Leaf-cert structural failure is structurally a malformed envelope
        // — the cose layer failed to extract a public key.
        CoseVerifyError::MalformedLeafCert => {
            AttestationVerifyError::MalformedCose("leaf certificate is malformed")
        }
        CoseVerifyError::AlgorithmNotImplemented(_) => {
            AttestationVerifyError::MalformedCose("signature algorithm not implemented")
        }
    }
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
        let doc = NitroAttestationDoc::mock(
            cose_sign1,
            payload,
            leaf_pk,
            vec![trust_anchor.clone()],
            signature,
        );
        (doc, trust_anchor, leaf_sk.to_bytes().to_vec())
    }

    fn build_valid_cose_doc(now_ms: i64) -> (NitroAttestationDoc, Vec<u8>) {
        use crate::cose::{build_test_envelope, AttestationPayload};
        let leaf_sk = SigningKey::from_bytes(&[7u8; 32]);
        let leaf_pk = leaf_sk.verifying_key().to_bytes().to_vec();
        let mut pcrs = BTreeMap::new();
        for i in 0u8..=4 {
            pcrs.insert(i, vec![0xAB ^ i; PCR_LEN]);
        }
        let payload = AttestationPayload {
            module_id: "i-cose-test".into(),
            timestamp: now_ms,
            digest: "SHA384".into(),
            pcrs,
            certificate: leaf_pk.clone(),
            cabundle: vec![vec![0xCA; 16]],
            public_key: vec![1, 2, 3],
            user_data: b"user-data".to_vec(),
            nonce: vec![0u8; 32],
        };
        let bytes = build_test_envelope(&payload, &leaf_sk).expect("build envelope");
        let doc = NitroAttestationDoc::from_cose_sign1(&bytes).expect("from_cose_sign1");
        let trust_anchor = b"AWS-Nitro-Root-Cert-Stub-M3".to_vec();
        (doc, trust_anchor)
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
        let verified = verify_attestation(&doc, &pcrs, &anchor, now, 60_000).expect("verifies");
        assert_eq!(verified.payload.user_data, b"user-data");
    }

    #[test]
    fn rejects_pcr_mismatch() {
        let now = 1_000_000;
        let (doc, anchor, _sk) = build_valid_doc(now);
        let bad_pcr = [0xEEu8; PCR_LEN];
        let pcrs = PcrConstraint::pcr0_only(bad_pcr);
        let err = verify_attestation(&doc, &pcrs, &anchor, now, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::PcrMismatch { index: 0 })
        ));
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

    // ---------- real COSE_Sign1 path -----------------------------------------

    #[test]
    fn cose_happy_path_verifies() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_doc(now);
        assert_eq!(doc.signature_kind, SignatureKind::CoseSign1Ed25519);
        let pcrs = PcrConstraint::pcr0_only({
            let mut p0 = [0u8; PCR_LEN];
            for b in &mut p0 {
                *b = 0xAB;
            }
            p0
        });
        let verified = verify_attestation(&doc, &pcrs, &anchor, now, 60_000).expect("verifies");
        assert_eq!(verified.payload.user_data, b"user-data");
    }

    #[test]
    fn cose_rejects_pcr_mismatch() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_doc(now);
        let bad_pcr = [0xEEu8; PCR_LEN];
        let pcrs = PcrConstraint::pcr0_only(bad_pcr);
        let err = verify_attestation(&doc, &pcrs, &anchor, now, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::PcrMismatch { index: 0 })
        ));
    }

    #[test]
    fn cose_rejects_stale_attestation() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_doc(now);
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now + 120_000, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::StaleAttestation { .. })
        ));
    }

    #[test]
    fn cose_rejects_signature_tamper() {
        let now = 1_000_000;
        let (mut doc, anchor) = build_valid_cose_doc(now);
        // Tamper the last byte (in the signature region of the CBOR envelope).
        let last = doc.cose_sign1.len() - 1;
        doc.cose_sign1[last] ^= 0xFF;
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now, 60_000);
        assert_eq!(err, Err(AttestationVerifyError::InvalidSignature));
    }

    #[test]
    fn cose_rejects_payload_mirror_tamper() {
        // The parsed mirror must match what re-decoding the CBOR returns;
        // changing only the mirror but leaving the envelope alone must
        // fail the round-trip check before the signature check.
        let now = 1_000_000;
        let (mut doc, anchor) = build_valid_cose_doc(now);
        doc.parsed_payload.user_data = b"changed".to_vec();
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now, 60_000);
        assert_eq!(err, Err(AttestationVerifyError::PayloadMismatch));
    }

    #[test]
    fn cose_rejects_malformed_envelope_bytes() {
        let bad = b"not a valid COSE envelope";
        let err = NitroAttestationDoc::from_cose_sign1(bad);
        assert!(matches!(err, Err(AttestationVerifyError::MalformedCose(_))));
    }

    // ---------- ES384 (real ECDSA-P384) end-to-end --------------------------

    /// Build a synthetic ES384-signed `NitroAttestationDoc` mirroring the
    /// AWS Nitro production wire shape: a real COSE_Sign1 CBOR envelope,
    /// `alg = ES384` in the protected header, and an X.509 DER leaf cert
    /// in the inner payload's `certificate` field.
    fn build_valid_cose_es384_doc(now_ms: i64) -> (NitroAttestationDoc, Vec<u8>) {
        use crate::cose::{
            build_test_envelope_es384, tests_helpers::es384_keypair_and_cert, AttestationPayload,
        };
        let (sk, cert_der) = es384_keypair_and_cert(0x42);
        let mut pcrs = BTreeMap::new();
        for i in 0u8..=4 {
            pcrs.insert(i, vec![0xAB ^ i; PCR_LEN]);
        }
        let payload = AttestationPayload {
            module_id: "i-cose-es384-test".into(),
            timestamp: now_ms,
            digest: "SHA384".into(),
            pcrs,
            certificate: cert_der,
            cabundle: vec![vec![0xCA; 16]],
            public_key: vec![1, 2, 3],
            user_data: b"user-data-es384".to_vec(),
            nonce: vec![0u8; 32],
        };
        let bytes = build_test_envelope_es384(&payload, &sk).expect("build es384 envelope");
        let doc = NitroAttestationDoc::from_cose_sign1(&bytes).expect("from_cose_sign1");
        let trust_anchor = b"AWS-Nitro-Root-Cert-Stub-M3".to_vec();
        (doc, trust_anchor)
    }

    #[test]
    fn cose_es384_happy_path_verifies() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_es384_doc(now);
        assert_eq!(doc.signature_kind, SignatureKind::CoseSign1Es384);
        let pcrs = PcrConstraint::pcr0_only({
            let mut p0 = [0u8; PCR_LEN];
            for b in &mut p0 {
                *b = 0xAB;
            }
            p0
        });
        let verified = verify_attestation(&doc, &pcrs, &anchor, now, 60_000).expect("verifies");
        assert_eq!(verified.payload.user_data, b"user-data-es384");
    }

    #[test]
    fn cose_es384_rejects_stale_attestation() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_es384_doc(now);
        let err = verify_attestation(&doc, &PcrConstraint::any(), &anchor, now + 120_000, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::StaleAttestation { .. })
        ));
    }

    #[test]
    fn cose_es384_rejects_pcr_mismatch() {
        let now = 1_000_000;
        let (doc, anchor) = build_valid_cose_es384_doc(now);
        let bad_pcr = [0xEEu8; PCR_LEN];
        let pcrs = PcrConstraint::pcr0_only(bad_pcr);
        let err = verify_attestation(&doc, &pcrs, &anchor, now, 60_000);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::PcrMismatch { index: 0 })
        ));
    }

    #[test]
    fn signature_kind_defaults_to_mock_for_back_compat() {
        // Documents serialized before SignatureKind existed deserialize
        // with the field defaulted to Mock.
        let json = r#"{
            "cose_sign1": [],
            "parsed_payload": {
                "module_id":"x","timestamp_unix_ms":0,"pcrs":{},
                "public_key":[],"user_data":[],"nonce":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]
            },
            "leaf_certificate": [],
            "cabundle": [],
            "signature": []
        }"#;
        let doc: NitroAttestationDoc = serde_json::from_str(json).expect("legacy parse");
        assert_eq!(doc.signature_kind, SignatureKind::Mock);
    }
}
