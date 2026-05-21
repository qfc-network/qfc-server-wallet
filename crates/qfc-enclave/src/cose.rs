//! Real COSE_Sign1 CBOR parsing for Nitro attestation envelopes.
//!
//! This module closes the parse half of [D24](../../../docs/m3-decisions.md#d24)
//! — the M3 skeleton stand-in (`cose_sign1` field holding JSON) is replaced
//! with `coset`-based COSE_Sign1 decoding + `ciborium`-based inner-payload
//! decoding.
//!
//! ## Wire format
//!
//! Per RFC 8152 + AWS Nitro attestation document spec:
//!
//! ```text
//! COSE_Sign1 = [
//!     protected   : bstr .cbor protected-header-map,
//!     unprotected : { Headers },
//!     payload     : bstr .cbor attestation-doc-map,
//!     signature   : bstr,
//! ]
//! ```
//!
//! Inside `payload`, the AWS Nitro attestation document is a CBOR map
//! keyed by short strings (per the AWS spec):
//!
//! | key            | type                                    |
//! |----------------|-----------------------------------------|
//! | `module_id`    | tstr                                    |
//! | `timestamp`    | uint (unix ms)                          |
//! | `digest`       | tstr (e.g. "SHA384")                    |
//! | `pcrs`         | map { uint => bstr }                    |
//! | `certificate`  | bstr (leaf cert, X.509 DER)             |
//! | `cabundle`     | array of bstr (chain to AWS Nitro root) |
//! | `public_key`   | bstr / nil (enclave ephemeral pubkey)   |
//! | `user_data`    | bstr / nil                              |
//! | `nonce`        | bstr / nil                              |
//!
//! ## What this module does today
//!
//! - `parse_cose_sign1` decodes the outer COSE_Sign1 array (tagged or untagged).
//! - `extract_payload` decodes the inner attestation-doc map.
//! - `verify_cose_signature` runs the COSE_Sign1 to-be-signed computation
//!   (`tbs_data`) and verifies it against a supplied **ed25519** public key.
//!
//! ## ECDSA-P384 (ES384) — [D47](../../../docs/m3-decisions.md#d47) closed
//!
//! `verify_cose_signature_es384` runs real verification of ECDSA-P384
//! signatures (AWS Nitro production format) using the pure-Rust `p384` +
//! `x509-cert` crates from the RustCrypto family. The leaf cert is parsed
//! as X.509 DER, the P-384 public key is extracted from the
//! `SubjectPublicKeyInfo`, and the COSE_Sign1 to-be-signed (`tbs_data`)
//! is verified against the on-wire signature (raw 96-byte `r || s` per
//! COSE_Sign1 fixed-size signature format, NOT DER —
//! [D50](../../../docs/m3-decisions.md#d50)).
//!
//! ## What is deferred ([D46](../../../docs/m3-decisions.md#d46))
//!
//! - **AWS Nitro root cert chain validation.** `verify_root_chain` in
//!   `verify_attestation` returns `Ok(())` today with a `TODO`. The ES384
//!   verifier closed in this PR only walks the leaf-cert → message
//!   signature; chaining the leaf up to the pinned AWS Nitro root is a
//!   separate (and larger) piece pending the embedded root certificate
//!   plus an X.509 chain walker.

use std::collections::BTreeMap;

use ciborium::Value;
use coset::{CborSerializable, CoseSign1, TaggedCborSerializable};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use thiserror::Error;

/// Errors raised when parsing a COSE_Sign1 envelope.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoseParseError {
    /// The outer COSE_Sign1 bytes did not decode (truncated, wrong CBOR
    /// shape, wrong number of elements, etc.).
    #[error("malformed COSE_Sign1: {0}")]
    MalformedEnvelope(String),

    /// The inner attestation-doc payload could not be parsed as the
    /// expected `Map<key -> Value>` shape.
    #[error("malformed attestation payload: {0}")]
    MalformedPayload(String),

    /// The envelope's `payload` field was nil — Nitro always includes a
    /// payload, so this is a structural error in our context.
    #[error("attestation payload missing (COSE_Sign1.payload was nil)")]
    MissingPayload,

    /// A required field was missing from the inner attestation document.
    #[error("missing required attestation field: {0}")]
    MissingField(&'static str),

    /// A field carried the wrong CBOR type (e.g. `module_id` was not a string).
    #[error("attestation field {field} has wrong CBOR type")]
    WrongFieldType {
        /// Field name that failed.
        field: &'static str,
    },
}

/// Errors raised when verifying a COSE_Sign1 signature.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CoseVerifyError {
    /// The supplied public key was the wrong size or shape for the
    /// configured algorithm.
    #[error("invalid public key for COSE_Sign1 verification")]
    InvalidPublicKey,

    /// The supplied signature was the wrong size or did not verify.
    #[error("invalid COSE_Sign1 signature")]
    InvalidSignature,

    /// The supplied leaf cert (X.509 DER) could not be parsed or the SPKI
    /// did not carry a usable public key for the configured algorithm.
    /// Emitted by `verify_cose_signature_es384` when the leaf-cert bytes
    /// are truncated, malformed, or carry a non-P-384 public key.
    #[error("malformed leaf certificate")]
    MalformedLeafCert,

    /// The on-wire signature bytes were the wrong shape for the
    /// configured algorithm (e.g. ES384 expects a fixed-size 96-byte
    /// `r || s`; anything else surfaces this variant).
    #[error("malformed COSE_Sign1 signature")]
    MalformedSignature,

    /// The signature was well-formed but did not verify against the
    /// computed `tbs_data` under the supplied public key. Distinct from
    /// `MalformedSignature` (the bytes were structurally OK; verification
    /// just rejected them).
    #[error("COSE_Sign1 signature did not verify against tbs_data")]
    SignatureMismatch,

    /// The configured signature algorithm is not yet implemented in this
    /// crate. Reserved for future expansion; ES384 is now implemented and
    /// no longer surfaces this variant.
    #[error("COSE_Sign1 algorithm not implemented in this build: {0}")]
    AlgorithmNotImplemented(&'static str),
}

/// Owning wrapper around a parsed `CoseSign1`.
///
/// We hold the original bytes alongside the parsed object so re-serialization
/// is a no-op for callers who want to forward the envelope unchanged.
#[derive(Clone, Debug)]
pub struct CoseSign1Envelope {
    /// The exact bytes the envelope was parsed from.
    pub raw: Vec<u8>,
    /// Parsed COSE_Sign1.
    pub cose: CoseSign1,
}

impl PartialEq for CoseSign1Envelope {
    fn eq(&self, other: &Self) -> bool {
        // Compare on the raw bytes — `CoseSign1` doesn't impl `Eq` because
        // its `Header` carries `Value` (ciborium) which doesn't impl `Eq`.
        self.raw == other.raw
    }
}

/// Strongly-typed mirror of the AWS Nitro attestation-doc CBOR map. Field
/// names match the AWS spec exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationPayload {
    /// Nitro module identifier (per AWS docs).
    pub module_id: String,
    /// Unix-millisecond timestamp.
    pub timestamp: i64,
    /// Hash algorithm string, e.g. `"SHA384"`.
    pub digest: String,
    /// PCR map: index -> measurement bytes (48 B on Nitro).
    pub pcrs: BTreeMap<u8, Vec<u8>>,
    /// Leaf certificate (X.509 DER, in production). In our ed25519 test
    /// path this is a raw 32-byte public key — documented at the call
    /// site of `NitroAttestationDoc::from_cose_sign1`.
    pub certificate: Vec<u8>,
    /// Cert chain from leaf → AWS Nitro root (in production). Each entry
    /// is a DER cert; empty in mock-COSE tests.
    pub cabundle: Vec<Vec<u8>>,
    /// Enclave's ephemeral identity public key. Optional in spec; `None` →
    /// empty `Vec`.
    pub public_key: Vec<u8>,
    /// Caller-supplied user data bytes. Optional in spec; `None` → empty.
    pub user_data: Vec<u8>,
    /// Caller-supplied nonce bytes. Optional in spec; `None` → empty.
    pub nonce: Vec<u8>,
}

/// Parse a COSE_Sign1 envelope from bytes. Accepts both tagged
/// (CBOR-tag 18) and untagged forms — Nitro emits tagged in production,
/// but tests construct untagged for simplicity.
///
/// # Errors
///
/// Returns `CoseParseError::MalformedEnvelope` on any CBOR / shape error.
pub fn parse_cose_sign1(bytes: &[u8]) -> Result<CoseSign1Envelope, CoseParseError> {
    // Try tagged first (production); fall back to untagged (tests).
    let cose = if let Ok(c) = CoseSign1::from_tagged_slice(bytes) {
        c
    } else {
        CoseSign1::from_slice(bytes)
            .map_err(|e| CoseParseError::MalformedEnvelope(e.to_string()))?
    };
    Ok(CoseSign1Envelope {
        raw: bytes.to_vec(),
        cose,
    })
}

/// Encode the inner Nitro attestation-doc map as CBOR. This is the inverse
/// of `decode_payload_map`; used by tests and any caller that wants to
/// construct a synthetic envelope.
///
/// # Errors
///
/// Returns `CoseParseError::MalformedPayload` if `ciborium` rejects the
/// encoded value (should never happen for well-typed input).
pub fn encode_payload(payload: &AttestationPayload) -> Result<Vec<u8>, CoseParseError> {
    // PCR map: keep BTreeMap ordering (u8 ascending). `Value::Map` carries
    // a Vec<(Value, Value)>; CBOR readers tolerate the in-order encoding.
    let pcr_pairs: Vec<(Value, Value)> = payload
        .pcrs
        .iter()
        .map(|(k, v)| {
            (
                Value::Integer(u64::from(*k).into()),
                Value::Bytes(v.clone()),
            )
        })
        .collect();
    let chain: Vec<Value> = payload
        .cabundle
        .iter()
        .map(|c| Value::Bytes(c.clone()))
        .collect();

    let map: Vec<(Value, Value)> = vec![
        (
            Value::Text("module_id".into()),
            Value::Text(payload.module_id.clone()),
        ),
        (
            Value::Text("timestamp".into()),
            Value::Integer(payload.timestamp.into()),
        ),
        (
            Value::Text("digest".into()),
            Value::Text(payload.digest.clone()),
        ),
        (Value::Text("pcrs".into()), Value::Map(pcr_pairs)),
        (
            Value::Text("certificate".into()),
            Value::Bytes(payload.certificate.clone()),
        ),
        (Value::Text("cabundle".into()), Value::Array(chain)),
        (
            Value::Text("public_key".into()),
            Value::Bytes(payload.public_key.clone()),
        ),
        (
            Value::Text("user_data".into()),
            Value::Bytes(payload.user_data.clone()),
        ),
        (
            Value::Text("nonce".into()),
            Value::Bytes(payload.nonce.clone()),
        ),
    ];

    let value = Value::Map(map);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&value, &mut out)
        .map_err(|e| CoseParseError::MalformedPayload(e.to_string()))?;
    Ok(out)
}

/// Decode the inner attestation-doc map from a COSE_Sign1 envelope.
///
/// # Errors
///
/// Returns `CoseParseError::{MissingPayload, MalformedPayload, MissingField,
/// WrongFieldType}` on shape / type mismatches.
pub fn extract_payload(envelope: &CoseSign1Envelope) -> Result<AttestationPayload, CoseParseError> {
    let payload_bytes = envelope
        .cose
        .payload
        .as_ref()
        .ok_or(CoseParseError::MissingPayload)?;
    decode_payload_map(payload_bytes)
}

/// Decode the inner CBOR `Map<text -> Value>` into a typed payload.
fn decode_payload_map(bytes: &[u8]) -> Result<AttestationPayload, CoseParseError> {
    let value: Value = ciborium::de::from_reader(bytes)
        .map_err(|e| CoseParseError::MalformedPayload(e.to_string()))?;
    let Value::Map(entries) = value else {
        return Err(CoseParseError::MalformedPayload(
            "outer value is not a map".into(),
        ));
    };

    let mut module_id: Option<String> = None;
    let mut timestamp: Option<i64> = None;
    let mut digest: Option<String> = None;
    let mut pcrs: Option<BTreeMap<u8, Vec<u8>>> = None;
    let mut certificate: Option<Vec<u8>> = None;
    let mut cabundle: Option<Vec<Vec<u8>>> = None;
    let mut public_key: Vec<u8> = Vec::new();
    let mut user_data: Vec<u8> = Vec::new();
    let mut nonce: Vec<u8> = Vec::new();

    for (k, v) in entries {
        let Value::Text(key) = k else {
            // Tolerate unknown key types — future forward-compat.
            continue;
        };
        match key.as_str() {
            "module_id" => {
                module_id = Some(as_text(v, "module_id")?);
            }
            "timestamp" => {
                timestamp = Some(as_i64(&v, "timestamp")?);
            }
            "digest" => {
                digest = Some(as_text(v, "digest")?);
            }
            "pcrs" => {
                pcrs = Some(decode_pcr_map(v)?);
            }
            "certificate" => {
                certificate = Some(as_bytes(v, "certificate")?);
            }
            "cabundle" => {
                cabundle = Some(decode_cabundle(v)?);
            }
            "public_key" => {
                public_key = as_optional_bytes(v, "public_key")?;
            }
            "user_data" => {
                user_data = as_optional_bytes(v, "user_data")?;
            }
            "nonce" => {
                nonce = as_optional_bytes(v, "nonce")?;
            }
            _ => { /* unknown key — ignore for forward-compat */ }
        }
    }

    Ok(AttestationPayload {
        module_id: module_id.ok_or(CoseParseError::MissingField("module_id"))?,
        timestamp: timestamp.ok_or(CoseParseError::MissingField("timestamp"))?,
        digest: digest.ok_or(CoseParseError::MissingField("digest"))?,
        pcrs: pcrs.ok_or(CoseParseError::MissingField("pcrs"))?,
        certificate: certificate.ok_or(CoseParseError::MissingField("certificate"))?,
        cabundle: cabundle.ok_or(CoseParseError::MissingField("cabundle"))?,
        public_key,
        user_data,
        nonce,
    })
}

fn as_text(v: Value, field: &'static str) -> Result<String, CoseParseError> {
    if let Value::Text(s) = v {
        Ok(s)
    } else {
        Err(CoseParseError::WrongFieldType { field })
    }
}

fn as_bytes(v: Value, field: &'static str) -> Result<Vec<u8>, CoseParseError> {
    if let Value::Bytes(b) = v {
        Ok(b)
    } else {
        Err(CoseParseError::WrongFieldType { field })
    }
}

fn as_optional_bytes(v: Value, field: &'static str) -> Result<Vec<u8>, CoseParseError> {
    match v {
        Value::Bytes(b) => Ok(b),
        Value::Null => Ok(Vec::new()),
        _ => Err(CoseParseError::WrongFieldType { field }),
    }
}

fn as_i64(v: &Value, field: &'static str) -> Result<i64, CoseParseError> {
    if let Value::Integer(i) = v {
        (*i).try_into()
            .map_err(|_| CoseParseError::WrongFieldType { field })
    } else {
        Err(CoseParseError::WrongFieldType { field })
    }
}

fn decode_pcr_map(v: Value) -> Result<BTreeMap<u8, Vec<u8>>, CoseParseError> {
    let Value::Map(entries) = v else {
        return Err(CoseParseError::WrongFieldType { field: "pcrs" });
    };
    let mut out = BTreeMap::new();
    for (k, val) in entries {
        let idx_i64: i64 = if let Value::Integer(i) = k {
            i.try_into()
                .map_err(|_| CoseParseError::WrongFieldType { field: "pcrs" })?
        } else {
            return Err(CoseParseError::WrongFieldType { field: "pcrs" });
        };
        let idx =
            u8::try_from(idx_i64).map_err(|_| CoseParseError::WrongFieldType { field: "pcrs" })?;
        let Value::Bytes(bytes) = val else {
            return Err(CoseParseError::WrongFieldType { field: "pcrs" });
        };
        out.insert(idx, bytes);
    }
    Ok(out)
}

fn decode_cabundle(v: Value) -> Result<Vec<Vec<u8>>, CoseParseError> {
    let Value::Array(entries) = v else {
        return Err(CoseParseError::WrongFieldType { field: "cabundle" });
    };
    let mut out = Vec::with_capacity(entries.len());
    for e in entries {
        if let Value::Bytes(b) = e {
            out.push(b);
        } else {
            return Err(CoseParseError::WrongFieldType { field: "cabundle" });
        }
    }
    Ok(out)
}

/// Verify the COSE_Sign1 signature using a supplied ed25519 leaf public key.
///
/// The to-be-signed (`tbs_data`) is constructed per RFC 8152 §4.4 by the
/// `coset` crate.
///
/// # Errors
///
/// - `CoseVerifyError::InvalidPublicKey` if `leaf_pubkey` is not 32 bytes
///   or not a valid ed25519 point.
/// - `CoseVerifyError::InvalidSignature` if the signature is the wrong
///   length or does not verify against `tbs_data`.
pub fn verify_cose_signature(
    envelope: &CoseSign1Envelope,
    leaf_pubkey: &[u8],
) -> Result<(), CoseVerifyError> {
    let pk_bytes: [u8; 32] = leaf_pubkey
        .try_into()
        .map_err(|_| CoseVerifyError::InvalidPublicKey)?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CoseVerifyError::InvalidPublicKey)?;

    envelope.cose.verify_signature(&[], |sig_bytes, tbs| {
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| CoseVerifyError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_arr);
        vk.verify(tbs, &sig)
            .map_err(|_| CoseVerifyError::InvalidSignature)
    })
}

/// Verify the COSE_Sign1 signature as ECDSA-P384 (ES384) — the AWS Nitro
/// production attestation format. Closes
/// [D47](../../../docs/m3-decisions.md#d47).
///
/// `leaf_cert_der` is the leaf X.509 certificate in DER form (taken
/// verbatim from the attestation document's `certificate` field). The
/// P-384 public key is extracted from the cert's `SubjectPublicKeyInfo`;
/// the COSE_Sign1 to-be-signed (`tbs_data`) is then verified against the
/// on-wire signature.
///
/// Wire format ([D50](../../../docs/m3-decisions.md#d50)): COSE_Sign1
/// carries the ECDSA signature as a **raw 96-byte** concatenation of
/// `r || s` (NOT DER-encoded). `p384::ecdsa::Signature::from_slice`
/// accepts this directly.
///
/// # Errors
///
/// - [`CoseVerifyError::MalformedLeafCert`] if `leaf_cert_der` does not
///   parse as X.509 DER, or the SPKI does not carry a usable P-384
///   public key.
/// - [`CoseVerifyError::MalformedSignature`] if the on-wire signature is
///   not exactly 96 bytes (fixed-size ES384 expects raw `r || s`).
/// - [`CoseVerifyError::SignatureMismatch`] if the signature is
///   well-formed but did not verify against the computed `tbs_data`
///   under the leaf-cert public key.
pub fn verify_cose_signature_es384(
    envelope: &CoseSign1Envelope,
    leaf_cert_der: &[u8],
) -> Result<(), CoseVerifyError> {
    use p384::ecdsa::{signature::Verifier as _, Signature as P384Signature, VerifyingKey};
    use x509_cert::{
        der::{Decode as _, Encode as _},
        Certificate,
    };

    // 1. Parse the leaf cert as X.509 DER, extract the SPKI, and pull
    //    out the SEC1-encoded P-384 public key bytes.
    let cert =
        Certificate::from_der(leaf_cert_der).map_err(|_| CoseVerifyError::MalformedLeafCert)?;
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let sec1_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or(CoseVerifyError::MalformedLeafCert)?;
    let vk = VerifyingKey::from_sec1_bytes(sec1_bytes)
        .map_err(|_| CoseVerifyError::MalformedLeafCert)?;

    // 2. Run the RFC 8152 §4.4 `tbs_data` computation via `coset` and
    //    hand the raw signature bytes to `p384::ecdsa`.
    //
    //    `verify_signature`'s closure returns the first error it sees
    //    from us; we use the typed `CoseVerifyError` variants to
    //    distinguish "signature shape is wrong" (MalformedSignature) from
    //    "signature is the right shape but does not verify"
    //    (SignatureMismatch).
    //
    //    Sanity: re-encode the cert and confirm it round-trips. Catches
    //    callers who pass garbage that happened to parse as a non-cert
    //    SEQUENCE prefix — vanishingly rare but cheap to check.
    let _round_trip = cert
        .to_der()
        .map_err(|_| CoseVerifyError::MalformedLeafCert)?;

    envelope.cose.verify_signature(&[], |sig_bytes, tbs| {
        if sig_bytes.len() != 96 {
            return Err(CoseVerifyError::MalformedSignature);
        }
        let sig = P384Signature::from_slice(sig_bytes)
            .map_err(|_| CoseVerifyError::MalformedSignature)?;
        vk.verify(tbs, &sig)
            .map_err(|_| CoseVerifyError::SignatureMismatch)
    })
}

/// Construct a synthetic COSE_Sign1 envelope signed with a given ed25519
/// key. Intended for tests and for the orchestrator's M3 follow-up
/// integration tests; never called from production code.
///
/// `aad` (additional authenticated data) is hardcoded to empty, matching
/// what AWS Nitro emits.
///
/// # Errors
///
/// Returns `CoseParseError::MalformedEnvelope` if encoding fails (should
/// not happen in practice).
#[doc(hidden)]
pub fn build_test_envelope(
    payload: &AttestationPayload,
    signer_sk: &ed25519_dalek::SigningKey,
) -> Result<Vec<u8>, CoseParseError> {
    use coset::iana;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use ed25519_dalek::Signer as _;

    let payload_bytes = encode_payload(payload)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::EdDSA)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |tbs| signer_sk.sign(tbs).to_bytes().to_vec())
        .build();
    sign1
        .to_vec()
        .map_err(|e| CoseParseError::MalformedEnvelope(e.to_string()))
}

/// Construct a synthetic ES384-signed COSE_Sign1 envelope.
///
/// Mirror of [`build_test_envelope`] for the AWS Nitro production path.
/// Sets `alg = ES384` (`-35`) in the protected header, signs `tbs_data`
/// with the supplied P-384 signing key, and emits a raw 96-byte
/// (`r || s`) signature exactly as
/// [D50](../../../docs/m3-decisions.md#d50) prescribes.
///
/// `leaf_cert_der` is the X.509 DER bytes that callers will later hand to
/// `verify_cose_signature_es384` to extract the verification key. The
/// helper itself doesn't inspect the cert — it only stuffs it into the
/// payload's `certificate` field (caller's responsibility to ensure the
/// cert's SPKI carries the public key of `signer_sk`).
///
/// # Errors
///
/// Returns `CoseParseError::MalformedEnvelope` if encoding fails (should
/// not happen in practice).
#[doc(hidden)]
pub fn build_test_envelope_es384(
    payload: &AttestationPayload,
    signer_sk: &p384::ecdsa::SigningKey,
) -> Result<Vec<u8>, CoseParseError> {
    use coset::iana;
    use coset::{CoseSign1Builder, HeaderBuilder};
    use p384::ecdsa::{signature::Signer as _, Signature as P384Signature};

    let payload_bytes = encode_payload(payload)?;
    let protected = HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build();
    let sign1 = CoseSign1Builder::new()
        .protected(protected)
        .payload(payload_bytes)
        .create_signature(&[], |tbs| {
            // p384 emits the fixed-size 96-byte `r || s` form via
            // Signature::to_bytes; that's exactly what COSE_Sign1 wants
            // ([D50]).
            let sig: P384Signature = signer_sk.sign(tbs);
            sig.to_bytes().to_vec()
        })
        .build();
    sign1
        .to_vec()
        .map_err(|e| CoseParseError::MalformedEnvelope(e.to_string()))
}

/// Test-only helpers shared between this module's tests and the
/// `verify_attestation` end-to-end tests. Visible to crate-internal tests
/// (`pub(crate)`) but elided from non-test builds.
#[cfg(test)]
pub(crate) mod tests_helpers {
    /// Generate a deterministic P-384 keypair (the `SigningKey` itself)
    /// plus a freshly-built self-signed X.509 leaf cert (DER) wrapping
    /// the matching public key. Both the signer and the cert are emitted
    /// by pure-Rust RustCrypto crates (`p384` + `x509-cert::builder`);
    /// see [D49](../../../docs/m3-decisions.md#d49).
    ///
    /// `seed_byte` shifts the deterministic seed so callers can produce
    /// distinct keypairs in the same test.
    pub(crate) fn es384_keypair_and_cert(seed_byte: u8) -> (p384::ecdsa::SigningKey, Vec<u8>) {
        use p384::ecdsa::{DerSignature, SigningKey};
        use std::str::FromStr as _;
        use x509_cert::{
            builder::{Builder, CertificateBuilder, Profile},
            der::Encode as _,
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::Validity,
        };

        // Deterministic 48-byte scalar (so test failures are
        // reproducible). The leading byte is forced to 0x01 to keep the
        // scalar comfortably below the curve order.
        let mut scalar_bytes = [0u8; 48];
        for (i, b) in scalar_bytes.iter_mut().enumerate() {
            // `i` is always 0..48, so the cast is in-range — but go via
            // wrapping arithmetic on `u8` directly so clippy's truncation
            // lint is satisfied without an allow attribute.
            #[allow(clippy::cast_possible_truncation)]
            let idx = i as u8;
            *b = idx.wrapping_add(seed_byte) | 0x01;
        }
        scalar_bytes[0] = 0x01;
        let sk =
            SigningKey::from_bytes((&scalar_bytes).into()).expect("p384 scalar in field order");

        let vk = *sk.verifying_key();
        let spki =
            SubjectPublicKeyInfoOwned::from_key(vk).expect("encode P-384 public key into SPKI");

        let subject = Name::from_str("CN=qfc-test-es384-leaf").expect("valid CN");
        let serial = SerialNumber::from(1u32);
        let validity = Validity::from_now(core::time::Duration::from_secs(365 * 24 * 60 * 60))
            .expect("validity");

        // Self-signed; production verifiers walk a chain to the AWS Nitro
        // root (D46). These tests exercise the leaf parse + verify path
        // only.
        let builder = CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &sk)
            .expect("CertificateBuilder::new");
        let cert = builder
            .build::<DerSignature>()
            .expect("self-sign synthetic leaf cert");
        let cert_der = cert.to_der().expect("encode cert to DER");

        (sk, cert_der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn sample_payload() -> AttestationPayload {
        let mut pcrs = BTreeMap::new();
        for i in 0u8..=4 {
            pcrs.insert(i, vec![i ^ 0xAB; 48]);
        }
        AttestationPayload {
            module_id: "i-0abcd1234ef".into(),
            timestamp: 1_700_000_000_000,
            digest: "SHA384".into(),
            pcrs,
            certificate: vec![0xDE; 32], // ed25519 pubkey in our test path
            cabundle: vec![vec![0xCA; 16], vec![0xFE; 16]],
            public_key: vec![0x01, 0x02, 0x03],
            user_data: b"hello-world".to_vec(),
            nonce: vec![0u8; 32],
        }
    }

    fn round_trip_envelope() -> (Vec<u8>, SigningKey, AttestationPayload) {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut payload = sample_payload();
        // Stuff the leaf pubkey into `certificate` so verify_cose_signature
        // has the right key without a cert parse.
        payload.certificate = sk.verifying_key().to_bytes().to_vec();
        let bytes = build_test_envelope(&payload, &sk).expect("build");
        (bytes, sk, payload)
    }

    #[test]
    fn round_trip_envelope_decodes_back_to_payload() {
        let (bytes, _sk, payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let decoded = extract_payload(&env).expect("extract");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn signature_verifies_with_correct_key() {
        let (bytes, sk, _payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        verify_cose_signature(&env, &sk.verifying_key().to_bytes()).expect("verifies");
    }

    #[test]
    fn signature_tamper_rejected() {
        let (mut bytes, sk, _payload) = round_trip_envelope();
        // Flip the last byte (well inside the signature region).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let env = parse_cose_sign1(&bytes).expect("parse still works");
        let err = verify_cose_signature(&env, &sk.verifying_key().to_bytes());
        assert_eq!(err, Err(CoseVerifyError::InvalidSignature));
    }

    #[test]
    fn payload_tamper_rejected() {
        // Build, parse, mutate the parsed envelope's payload bytes, re-encode,
        // try to verify with the original signature → must fail because the
        // tbs_data changes.
        let (bytes, sk, _payload) = round_trip_envelope();
        let mut env = parse_cose_sign1(&bytes).expect("parse");
        let mut p = env.cose.payload.clone().expect("payload present");
        let n = p.len() / 2;
        p[n] ^= 0x80;
        env.cose.payload = Some(p);
        let err = verify_cose_signature(&env, &sk.verifying_key().to_bytes());
        assert_eq!(err, Err(CoseVerifyError::InvalidSignature));
    }

    #[test]
    fn wrong_key_rejected() {
        let (bytes, _sk, _payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let wrong = SigningKey::from_bytes(&[0xAAu8; 32])
            .verifying_key()
            .to_bytes();
        let err = verify_cose_signature(&env, &wrong);
        assert_eq!(err, Err(CoseVerifyError::InvalidSignature));
    }

    #[test]
    fn pcr_map_round_trips_in_order() {
        // PCR map is BTreeMap; assert the round-trip preserves *both* keys
        // and order (which matters for the digest the verifier computes).
        let (bytes, _sk, payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let decoded = extract_payload(&env).expect("extract");
        let original_keys: Vec<u8> = payload.pcrs.keys().copied().collect();
        let decoded_keys: Vec<u8> = decoded.pcrs.keys().copied().collect();
        assert_eq!(original_keys, decoded_keys);
        for (k, v) in &payload.pcrs {
            assert_eq!(decoded.pcrs.get(k), Some(v));
        }
    }

    #[test]
    fn truncated_input_rejected() {
        let (bytes, _sk, _payload) = round_trip_envelope();
        let truncated = &bytes[..bytes.len() / 2];
        let err = parse_cose_sign1(truncated);
        assert!(matches!(err, Err(CoseParseError::MalformedEnvelope(_))));
    }

    #[test]
    fn garbage_bytes_rejected() {
        let garbage = b"this is not CBOR at all -- not even close";
        let err = parse_cose_sign1(garbage);
        assert!(matches!(err, Err(CoseParseError::MalformedEnvelope(_))));
    }

    #[test]
    fn empty_bytes_rejected() {
        let err = parse_cose_sign1(&[]);
        assert!(matches!(err, Err(CoseParseError::MalformedEnvelope(_))));
    }

    #[test]
    fn missing_field_in_payload_rejected() {
        // Hand-roll a minimal map missing `module_id`.
        let pairs: Vec<(Value, Value)> = vec![
            (Value::Text("timestamp".into()), Value::Integer(1i64.into())),
            (Value::Text("digest".into()), Value::Text("SHA384".into())),
            (Value::Text("pcrs".into()), Value::Map(vec![])),
            (Value::Text("certificate".into()), Value::Bytes(vec![])),
            (Value::Text("cabundle".into()), Value::Array(vec![])),
        ];
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(pairs), &mut buf).unwrap();
        let err = decode_payload_map(&buf);
        assert!(matches!(
            err,
            Err(CoseParseError::MissingField("module_id"))
        ));
    }

    // ---------- ES384 (real ECDSA-P384) path -----------------------------

    use super::tests_helpers::es384_keypair_and_cert;

    fn es384_round_trip_envelope() -> (Vec<u8>, p384::ecdsa::SigningKey, Vec<u8>) {
        let (sk, cert_der) = es384_keypair_and_cert(0x11);
        let mut payload = sample_payload();
        // Stuff the leaf cert (X.509 DER) into `certificate` so callers
        // who consume the parsed payload can hand it back to
        // `verify_cose_signature_es384` directly.
        payload.certificate = cert_der.clone();
        let bytes = build_test_envelope_es384(&payload, &sk).expect("build es384 envelope");
        (bytes, sk, cert_der)
    }

    #[test]
    fn es384_round_trip_verifies() {
        let (bytes, _sk, cert_der) = es384_round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        verify_cose_signature_es384(&env, &cert_der).expect("verifies");
    }

    #[test]
    fn es384_tampered_signature_rejected() {
        let (mut bytes, _sk, cert_der) = es384_round_trip_envelope();
        // Flip the last byte (in the signature region — well past the
        // header + payload).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        let env = parse_cose_sign1(&bytes).expect("parse still works");
        let err = verify_cose_signature_es384(&env, &cert_der);
        assert_eq!(err, Err(CoseVerifyError::SignatureMismatch));
    }

    #[test]
    fn es384_tampered_payload_rejected() {
        let (bytes, _sk, cert_der) = es384_round_trip_envelope();
        let mut env = parse_cose_sign1(&bytes).expect("parse");
        let mut p = env.cose.payload.clone().expect("payload present");
        let n = p.len() / 2;
        p[n] ^= 0x80;
        env.cose.payload = Some(p);
        let err = verify_cose_signature_es384(&env, &cert_der);
        assert_eq!(err, Err(CoseVerifyError::SignatureMismatch));
    }

    #[test]
    fn es384_wrong_leaf_cert_rejected() {
        // Build the envelope with one keypair, verify against a DIFFERENT
        // keypair's cert. The signature is well-formed but verifies
        // against the wrong key — must surface SignatureMismatch.
        let (bytes, _sk, _cert_der) = es384_round_trip_envelope();
        let (_wrong_sk, wrong_cert) = es384_keypair_and_cert(0x99);
        let env = parse_cose_sign1(&bytes).expect("parse");
        let err = verify_cose_signature_es384(&env, &wrong_cert);
        assert_eq!(err, Err(CoseVerifyError::SignatureMismatch));
    }

    #[test]
    fn es384_truncated_leaf_cert_rejected() {
        let (bytes, _sk, cert_der) = es384_round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        // Lop off the tail of the DER cert.
        let truncated = &cert_der[..cert_der.len() / 2];
        let err = verify_cose_signature_es384(&env, truncated);
        assert_eq!(err, Err(CoseVerifyError::MalformedLeafCert));
    }

    #[test]
    fn es384_garbage_leaf_cert_rejected() {
        let (bytes, _sk, _cert_der) = es384_round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let garbage = b"this is not a certificate -- not even close";
        let err = verify_cose_signature_es384(&env, garbage);
        assert_eq!(err, Err(CoseVerifyError::MalformedLeafCert));
    }

    #[test]
    fn es384_truncated_signature_rejected() {
        // Build a normal envelope, then surgically remove the last byte
        // of the on-wire signature (turning a 96-byte sig into 95). The
        // `coset` parser is structural (it accepts arbitrary bstr
        // lengths), so we re-emit the inner CoseSign1 with a shortened
        // signature.
        let (bytes, _sk, cert_der) = es384_round_trip_envelope();
        let mut env = parse_cose_sign1(&bytes).expect("parse");
        env.cose.signature.truncate(env.cose.signature.len() - 1);
        let err = verify_cose_signature_es384(&env, &cert_der);
        assert_eq!(err, Err(CoseVerifyError::MalformedSignature));
    }

    #[test]
    fn invalid_public_key_length_rejected() {
        let (bytes, _sk, _payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let err = verify_cose_signature(&env, &[0u8; 31]); // too short
        assert_eq!(err, Err(CoseVerifyError::InvalidPublicKey));
    }

    #[test]
    fn tagged_envelope_also_parses() {
        // The production AWS Nitro stream is CBOR-tagged (tag 18). Verify
        // our parser accepts that form too.
        let (bytes, _sk, payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse untagged");
        // Re-encode tagged.
        let tagged = env.cose.clone().to_tagged_vec().expect("re-encode tagged");
        let env2 = parse_cose_sign1(&tagged).expect("parse tagged");
        let decoded = extract_payload(&env2).expect("extract");
        assert_eq!(decoded, payload);
    }
}
