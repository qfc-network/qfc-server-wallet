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
//! ## What is deferred ([D47](../../../docs/m3-decisions.md#d47))
//!
//! - **ECDSA-P384 (ES384) signature verification.** Real AWS Nitro
//!   attestations use ES384 over a P-384 leaf cert. The mock path used by
//!   our tests is ed25519-keyed, so the ed25519 verifier is what we ship
//!   today. `verify_cose_signature_es384` is a stub returning
//!   `CoseVerifyError::AlgorithmNotImplemented`. The wire format,
//!   `tbs_data` construction, and envelope round-trip are identical — only
//!   the curve plug changes.
//! - **AWS Nitro root cert chain validation.** See
//!   [D46](../../../docs/m3-decisions.md#d46); `verify_root_chain` in
//!   `verify_attestation` returns `Ok(())` today with a `TODO`.

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

    /// The configured signature algorithm is not yet implemented in this
    /// crate. Currently emitted by `verify_cose_signature_es384` — see
    /// [D47](../../../docs/m3-decisions.md#d47).
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

/// **Stub** — ECDSA-P384 (ES384) verification for real AWS Nitro
/// attestations. Always returns `AlgorithmNotImplemented`; tracked as
/// [D47](../../../docs/m3-decisions.md#d47). The wire format and
/// `tbs_data` flow are identical to the ed25519 path — only the curve
/// verifier swap is missing.
///
/// # Errors
///
/// Always `CoseVerifyError::AlgorithmNotImplemented`.
pub fn verify_cose_signature_es384(
    _envelope: &CoseSign1Envelope,
    _leaf_cert_der: &[u8],
) -> Result<(), CoseVerifyError> {
    Err(CoseVerifyError::AlgorithmNotImplemented(
        "ECDSA-P384 (ES384) signature verification — see docs/m3-decisions.md D47",
    ))
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

    #[test]
    fn es384_stub_returns_not_implemented() {
        let (bytes, _sk, _payload) = round_trip_envelope();
        let env = parse_cose_sign1(&bytes).expect("parse");
        let err = verify_cose_signature_es384(&env, &[]);
        assert!(matches!(
            err,
            Err(CoseVerifyError::AlgorithmNotImplemented(_))
        ));
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
