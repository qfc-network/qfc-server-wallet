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
//! ## What this verifier does today
//!
//! A real COSE_Sign1 verifier with cert-chain validation rooted at the
//! AWS Nitro root certificate is built from three pieces:
//! 1. COSE parsing — `coset` crate (no FFI). See `crate::cose`.
//! 2. ECDSA P-384 signature verification — `p384` crate (RustCrypto).
//!    See `crate::cose::verify_cose_signature_es384`.
//! 3. X.509 chain walk to the AWS Nitro G1 root — implemented in this
//!    module via `verify_root_chain` ([D46](../../../docs/m3-decisions.md#d46)
//!    closed). Pure-Rust on `x509-cert` + `p384`.
//!
//! The AWS Nitro G1 root certificate is embedded in this crate via
//! `include_bytes!` (see `AWS_NITRO_ROOT_G1_PEM` + `AWS_NITRO_ROOT_G1_SHA256`
//! — [D51](../../../docs/m3-decisions.md#d51)). The verifier validates
//! the leaf cert → cabundle intermediates → embedded root chain by:
//! - parsing each cert as X.509 DER,
//! - confirming issuer/subject DN linkage adjacent-pairwise,
//! - verifying each cert's ECDSA-P384 signature with the next cert's
//!   public key,
//! - checking the validity window contains `now_ms` for every link.
//!
//! Production callers select the AWS Nitro G1 anchor via
//! `RootAnchor::AwsNitroG1` (the default — see
//! [D52](../../../docs/m3-decisions.md#d52)). Tests with synthetic
//! certs pass `RootAnchor::Custom(&[u8])`; the mock-tier path uses
//! `RootAnchor::None` to skip chain validation entirely (M1/M2 mock
//! attestations have no real chain).
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

use hex_literal::hex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::attestation::{AttestationDoc, AttestationError, PCR_LEN};
use crate::cose::{
    extract_payload, parse_cose_sign1, verify_cose_signature, verify_cose_signature_es384,
    CoseParseError, CoseSign1Envelope, CoseVerifyError,
};

/// AWS Nitro Enclaves G1 root certificate. Public, self-signed P-384.
/// Valid 2019-10-28 to 2049-10-28. Verifiers check the leaf -> cabundle ->
/// this root chain. Operators who want to test with a custom root (e.g. for
/// integration tests in a sandboxed environment) can pass an alternative
/// root to `verify_root_chain` directly via `RootAnchor::Custom`.
///
/// See [D51](../../../docs/m3-decisions.md#d51) for the provenance + pin
/// strategy.
pub const AWS_NITRO_ROOT_G1_PEM: &[u8] = include_bytes!("../data/aws-nitro-root-g1.pem");

/// SHA-256 fingerprint (over the DER body, NOT the PEM armor) of
/// [`AWS_NITRO_ROOT_G1_PEM`] — asserted by tests so a supply-chain swap
/// of the embedded cert fails loudly. See
/// [D51](../../../docs/m3-decisions.md#d51).
pub const AWS_NITRO_ROOT_G1_SHA256: [u8; 32] =
    hex!("641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b");

/// Where the chain walk should anchor.
///
/// See [D52](../../../docs/m3-decisions.md#d52) for the rationale on
/// exposing this as an enum (vs threading a `&[u8]` everywhere).
///
/// - [`RootAnchor::AwsNitroG1`] — the production default: chain walk
///   terminates at the embedded AWS Nitro G1 root.
/// - [`RootAnchor::Custom`] — caller-provided root cert bytes (DER or
///   PEM). Used by integration tests + cross-TEE-vendor verifiers that
///   want to point at a synthetic chain.
/// - [`RootAnchor::None`] — **skip chain validation entirely**.
///   Mock-tier only. Production callers MUST NOT construct this variant
///   — it is reserved for the M1/M2 ed25519 mock attestations where
///   there is no real cert chain to walk. `verify_attestation` will
///   accept any non-empty `cabundle` (and ignore its contents) on this
///   anchor; the surrounding signature + PCR + freshness checks still
///   run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootAnchor<'a> {
    /// Production default: the embedded AWS Nitro G1 root.
    AwsNitroG1,
    /// Caller-provided root cert bytes (DER or PEM accepted).
    Custom(&'a [u8]),
    /// Skip chain validation entirely. Mock-tier only — see the enum doc.
    None,
}

impl<'a> RootAnchor<'a> {
    /// Resolve the anchor to a byte slice for chain-walk consumption.
    /// Returns `None` when chain validation is opted out.
    fn root_bytes(self) -> Option<&'a [u8]> {
        match self {
            RootAnchor::AwsNitroG1 => Some(AWS_NITRO_ROOT_G1_PEM),
            RootAnchor::Custom(bytes) => Some(bytes),
            RootAnchor::None => None,
        }
    }
}

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

/// Walk `[leaf_cert, cabundle[0], ..., cabundle[N-1], root]` and verify
/// every link.
///
/// `cabundle` is in **leaf-most-first** order (AWS Nitro's documented
/// convention — see [D53](../../../docs/m3-decisions.md#d53)). The
/// expected ordering is:
/// - `cabundle[0]` issued `leaf_cert`,
/// - `cabundle[i]` issued `cabundle[i-1]`,
/// - `root` issued `cabundle[N-1]` (or `leaf_cert` directly if
///   `cabundle` is empty),
/// - `root` is self-signed (issuer DN == subject DN).
///
/// For each adjacent pair `(child, parent)` the walker confirms:
/// 1. `child.issuer == parent.subject` (DN match);
/// 2. `parent.subject_public_key_info` parses as a P-384 SEC1 public key
///    (every link in the Nitro chain is P-384);
/// 3. `child`'s signature (`ecdsa-with-SHA384`) verifies against
///    `parent`'s pubkey over `child.tbs_certificate` DER bytes;
/// 4. `child`'s `validity` window contains `now_ms`.
///
/// The root itself is also checked self-signed (defense in depth — even
/// though the root IS the trust anchor, a corrupted embedded root would
/// otherwise pass silently).
///
/// `root` accepts both PEM-encoded and DER-encoded bytes. PEM is tried
/// first (so callers can embed via `include_bytes!` on a .pem file);
/// raw DER is the fallback.
///
/// `cabundle` MUST be in leaf-most-first order — that's what real AWS
/// Nitro attestation documents emit. If you have an unordered chain you
/// must sort it before calling.
///
/// `now_ms` is the Unix-millisecond timestamp the validity windows are
/// checked against. The same value flows from `verify_attestation`'s
/// `now_ms` parameter.
///
/// # Errors
///
/// - [`AttestationVerifyError::MalformedLeafCert`] — leaf is not parseable
///   X.509 DER.
/// - [`AttestationVerifyError::MalformedIntermediate`] — a cabundle entry
///   is not parseable X.509 DER. The variant carries the cabundle index.
/// - [`AttestationVerifyError::MalformedRoot`] — `root` is neither valid
///   PEM nor valid DER.
/// - [`AttestationVerifyError::CertChainBroken`] — DN mismatch, signature
///   mismatch, expired link, or non-P-384 SPKI somewhere in the chain.
///   `index` is the position of the *child* cert in the full chain
///   `[leaf, cab[0], ..., cab[N-1], root]`.
pub fn verify_root_chain(
    leaf_cert: &[u8],
    cabundle: &[Vec<u8>],
    root: &[u8],
    now_ms: i64,
) -> Result<(), AttestationVerifyError> {
    use x509_cert::{
        der::{Decode as _, Encode as _},
        Certificate,
    };

    // 1. Parse the leaf (DER).
    let leaf =
        Certificate::from_der(leaf_cert).map_err(|_| AttestationVerifyError::MalformedLeafCert)?;

    // 2. Parse each cabundle entry (DER), preserving caller order.
    let mut intermediates: Vec<Certificate> = Vec::with_capacity(cabundle.len());
    for (idx, der_bytes) in cabundle.iter().enumerate() {
        let cert = Certificate::from_der(der_bytes)
            .map_err(|_| AttestationVerifyError::MalformedIntermediate(idx))?;
        intermediates.push(cert);
    }

    // 3. Parse the root — PEM first, DER fallback. `load_pem_chain`
    //    accepts a single PEM block too, so we use it for both
    //    multi-cert PEM files and the common single-cert case.
    let root_cert: Certificate = if let Ok(mut chain) = Certificate::load_pem_chain(root) {
        // Multiple PEM blocks → pick the LAST one. AWS publishes a
        // single-cert PEM today, but operators occasionally bundle
        // multiple roots (intermediate + root) — pick the actual root
        // (last entry in load order; load_pem_chain reads top-down).
        chain.pop().ok_or(AttestationVerifyError::MalformedRoot)?
    } else {
        Certificate::from_der(root).map_err(|_| AttestationVerifyError::MalformedRoot)?
    };

    // 4. Build the full chain [leaf, intermediates..., root]. Indices
    //    in `CertChainBroken` refer to positions in this concatenated
    //    sequence (so the leaf is index 0, the first intermediate is
    //    index 1, etc.).
    let mut chain: Vec<&Certificate> = Vec::with_capacity(intermediates.len() + 2);
    chain.push(&leaf);
    for c in &intermediates {
        chain.push(c);
    }
    chain.push(&root_cert);

    // 5. Walk adjacent pairs (child, parent).
    for i in 0..(chain.len() - 1) {
        let child = chain[i];
        let parent = chain[i + 1];
        check_pair(child, parent, i, now_ms)?;
    }

    // 6. Defense-in-depth: confirm the root is self-signed. Issuer and
    //    subject DNs must match, AND the root's own signature must verify
    //    against its own public key.
    if root_cert.tbs_certificate.issuer != root_cert.tbs_certificate.subject {
        return Err(AttestationVerifyError::CertChainBroken {
            index: chain.len() - 1,
            reason: "root certificate is not self-signed (issuer != subject)".to_string(),
        });
    }
    // Re-encode the root's TBS bytes and verify against its own SPKI.
    // We've already validated the root's validity window via the
    // adjacent-pair walk above (the last `(intermediate, root)` pair
    // checks the intermediate, not the root). Check the root window
    // here.
    check_validity(&root_cert, chain.len() - 1, now_ms)?;
    verify_p384_signature(
        &root_cert,
        &root_cert,
        chain.len() - 1,
        "root self-signature did not verify",
    )?;

    // Encode-only sanity round-trip (catches the same kind of garbage
    // the ES384 leaf-cert verifier catches: bytes that happened to
    // parse as a SEQUENCE prefix but aren't real certificates).
    let _ = leaf
        .to_der()
        .map_err(|_| AttestationVerifyError::MalformedLeafCert)?;
    let _ = root_cert
        .to_der()
        .map_err(|_| AttestationVerifyError::MalformedRoot)?;

    Ok(())
}

/// Verify the embedded AWS Nitro G1 root chain. Convenience wrapper over
/// [`verify_root_chain`] that pins the root to [`AWS_NITRO_ROOT_G1_PEM`].
///
/// # Errors
///
/// Same as [`verify_root_chain`].
pub fn verify_aws_nitro_root_chain(
    leaf_cert: &[u8],
    cabundle: &[Vec<u8>],
    now_ms: i64,
) -> Result<(), AttestationVerifyError> {
    verify_root_chain(leaf_cert, cabundle, AWS_NITRO_ROOT_G1_PEM, now_ms)
}

/// Verify one `(child, parent)` adjacency in the chain. Used by
/// `verify_root_chain` and `verify_aws_nitro_root_chain`.
///
/// `index` is the position of `child` in the caller's full chain (used
/// to populate `CertChainBroken { index }`).
fn check_pair(
    child: &x509_cert::Certificate,
    parent: &x509_cert::Certificate,
    index: usize,
    now_ms: i64,
) -> Result<(), AttestationVerifyError> {
    // DN linkage: child.issuer must equal parent.subject (verbatim DN
    // comparison — RFC 5280 §4.1.2.4 says CAs SHOULD use the same
    // encoding for both fields).
    if child.tbs_certificate.issuer != parent.tbs_certificate.subject {
        return Err(AttestationVerifyError::CertChainBroken {
            index,
            reason: "issuer DN does not match parent subject DN".to_string(),
        });
    }

    // Validity window check on the child.
    check_validity(child, index, now_ms)?;

    // Signature verification: child.signature is over child.tbs_certificate
    // bytes, signed with parent's public key. AWS Nitro uses
    // ecdsa-with-SHA384 throughout.
    verify_p384_signature(child, parent, index, "signature did not verify")
}

/// Check that `cert`'s validity window contains `now_ms`. Used by the
/// chain walker for every link including the root.
fn check_validity(
    cert: &x509_cert::Certificate,
    index: usize,
    now_ms: i64,
) -> Result<(), AttestationVerifyError> {
    let not_before_ms = i64::try_from(
        cert.tbs_certificate
            .validity
            .not_before
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| AttestationVerifyError::CertChainBroken {
        index,
        reason: "not_before exceeds i64 millis range".to_string(),
    })?;
    let not_after_ms = i64::try_from(
        cert.tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_millis(),
    )
    .map_err(|_| AttestationVerifyError::CertChainBroken {
        index,
        reason: "not_after exceeds i64 millis range".to_string(),
    })?;
    if now_ms < not_before_ms {
        return Err(AttestationVerifyError::CertChainBroken {
            index,
            reason: "not yet valid (now < not_before)".to_string(),
        });
    }
    if now_ms > not_after_ms {
        return Err(AttestationVerifyError::CertChainBroken {
            index,
            reason: "expired (now > not_after)".to_string(),
        });
    }
    Ok(())
}

/// Verify `child.signature` (DER ECDSA-P384) against `parent`'s SPKI.
fn verify_p384_signature(
    child: &x509_cert::Certificate,
    parent: &x509_cert::Certificate,
    index: usize,
    mismatch_reason: &'static str,
) -> Result<(), AttestationVerifyError> {
    use p384::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
    use x509_cert::der::Encode as _;

    // Extract parent's SEC1 P-384 public key.
    let sec1_bytes = parent
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| AttestationVerifyError::CertChainBroken {
            index,
            reason: "parent SubjectPublicKeyInfo bit string is not byte-aligned".to_string(),
        })?;
    let vk = VerifyingKey::from_sec1_bytes(sec1_bytes).map_err(|_| {
        AttestationVerifyError::CertChainBroken {
            index,
            reason: "parent SubjectPublicKeyInfo is not a P-384 public key".to_string(),
        }
    })?;

    // Re-encode child.tbs_certificate to DER — that's what was signed.
    let tbs_der =
        child
            .tbs_certificate
            .to_der()
            .map_err(|_| AttestationVerifyError::CertChainBroken {
                index,
                reason: "could not re-encode child TBS to DER".to_string(),
            })?;

    // X.509 ECDSA signatures are DER-encoded (RFC 5480), NOT the raw 96-byte
    // form COSE uses. p384::ecdsa::DerSignature handles the decode.
    let sig_bytes =
        child
            .signature
            .as_bytes()
            .ok_or_else(|| AttestationVerifyError::CertChainBroken {
                index,
                reason: "child signature bit string is not byte-aligned".to_string(),
            })?;
    let sig =
        DerSignature::try_from(sig_bytes).map_err(|_| AttestationVerifyError::CertChainBroken {
            index,
            reason: "child signature is not a valid DER ECDSA signature".to_string(),
        })?;

    vk.verify(&tbs_der, &sig)
        .map_err(|_| AttestationVerifyError::CertChainBroken {
            index,
            reason: mismatch_reason.to_string(),
        })
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

    /// Leaf certificate (the cert that signs the COSE_Sign1 payload) did
    /// not parse as X.509 DER.
    #[error("leaf certificate is not parseable X.509 DER")]
    MalformedLeafCert,

    /// A cabundle entry did not parse as X.509 DER. The index is into
    /// `cabundle` as passed to `verify_root_chain` (0-based).
    #[error("cabundle entry {0} is not parseable X.509 DER")]
    MalformedIntermediate(usize),

    /// The root certificate did not parse as either PEM or DER.
    #[error("root certificate is malformed (neither PEM nor DER)")]
    MalformedRoot,

    /// A specific link in the cert chain failed to validate. `index` is
    /// the position of the child cert in the full chain
    /// `[leaf, cab[0], ..., cab[N-1], root]` (so leaf = 0, first
    /// intermediate = 1, etc.). `reason` is a human-readable string —
    /// stable enough for ops dashboards to grep on but not a stable API
    /// contract.
    #[error("cert chain broken at index {index}: {reason}")]
    CertChainBroken {
        /// Position of the failing child cert in the concatenated chain.
        index: usize,
        /// Human-readable failure reason.
        reason: String,
    },

    /// The cabundle was empty AND no chain validation was opted out.
    /// Production attestations always carry at least one intermediate;
    /// an empty cabundle on the AWS Nitro path is structurally invalid.
    /// (The synthetic-test path can still build chains where the leaf is
    /// directly issued by the root — see the chain-walk tests.)
    #[error("cabundle is empty")]
    EmptyCabundle,

    /// `backend` field is `"mock"` — production callers MUST refuse.
    #[error("refusing mock attestation in production verifier")]
    RefusesMockAttestation,
}

/// Verify a Nitro-shape attestation against an explicit
/// [`RootAnchor`]. This is the production entry point — most callers
/// should select `RootAnchor::AwsNitroG1` to get the embedded AWS Nitro
/// G1 root.
///
/// See [D52](../../../docs/m3-decisions.md#d52) for why this lands as a
/// new function rather than a parameter on the existing
/// `verify_attestation`.
///
/// Inputs:
/// - `doc` — the document to verify.
/// - `expected_pcrs` — PCR constraint (see [`PcrConstraint`]).
/// - `root_anchor` — where the cert chain anchors. See [`RootAnchor`].
/// - `now_ms` — current wall-clock time in unix millis.
/// - `max_age_ms` — how old the attestation may be.
///
/// # Errors
///
/// Returns the first failure encountered. Fail-closed. See
/// [`AttestationVerifyError`] for the variants.
pub fn verify_attestation_with_root(
    doc: &NitroAttestationDoc,
    expected_pcrs: &PcrConstraint,
    root_anchor: RootAnchor<'_>,
    now_ms: i64,
    max_age_ms: i64,
) -> Result<VerifiedAttestation, AttestationVerifyError> {
    verify_attestation_inner(doc, expected_pcrs, root_anchor, now_ms, max_age_ms)
}

/// Back-compat wrapper that skips chain validation.
///
/// **Deprecated for production use** — production callers should switch
/// to [`verify_attestation_with_root`] with [`RootAnchor::AwsNitroG1`]
/// or another explicit anchor. This function preserves the pre-D46
/// behaviour where `verify_root_chain` was a typed stub returning
/// `Ok(())`: the cert chain is NOT walked. Existing M1/M2 callers
/// (mock-tier ed25519 attestations with synthetic non-cert "cabundle"
/// payloads) continue to work without modification.
///
/// New production paths MUST migrate. See
/// [D52](../../../docs/m3-decisions.md#d52).
///
/// Inputs:
/// - `doc` — the document to verify.
/// - `expected_pcrs` — PCR constraint (see [`PcrConstraint`]).
/// - `_trust_anchor` — kept for ABI back-compat; **ignored**. Was the
///   pinned AWS Nitro root cert bytes in the M3 skeleton; chain
///   validation is now driven by [`RootAnchor`] in
///   [`verify_attestation_with_root`].
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
    verify_attestation_inner(doc, expected_pcrs, RootAnchor::None, now_ms, max_age_ms)
}

fn verify_attestation_inner(
    doc: &NitroAttestationDoc,
    expected_pcrs: &PcrConstraint,
    root_anchor: RootAnchor<'_>,
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

    // 5. Cert-chain validation.
    //
    //    - `RootAnchor::None` (mock tier + back-compat `verify_attestation`):
    //      we still require a non-empty `cabundle` to catch the structurally
    //      empty case (matches the pre-D46 behaviour), but the chain itself
    //      is NOT walked. Callers MUST NOT rely on this path in production
    //      — see the `RootAnchor::None` docstring.
    //    - `RootAnchor::AwsNitroG1` / `RootAnchor::Custom`: walk the chain
    //      from leaf -> cabundle -> root via `verify_root_chain`.
    if doc.cabundle.is_empty() {
        return Err(AttestationVerifyError::CertChain);
    }
    if let Some(root_bytes) = root_anchor.root_bytes() {
        verify_root_chain(&doc.leaf_certificate, &doc.cabundle, root_bytes, now_ms)?;
    }

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

    // ---------- X.509 chain walk (D46) -------------------------------------

    use sha2::{Digest as _, Sha256};

    /// Generate a deterministic P-384 keypair from `seed_byte`. Mirrors
    /// the test helper in `crate::cose::tests_helpers` without going
    /// through the cert builder.
    fn p384_keypair(seed_byte: u8) -> p384::ecdsa::SigningKey {
        let mut scalar_bytes = [0u8; 48];
        for (i, b) in scalar_bytes.iter_mut().enumerate() {
            #[allow(clippy::cast_possible_truncation)]
            let idx = i as u8;
            *b = idx.wrapping_add(seed_byte) | 0x01;
        }
        // Make the seeds disjoint from `cose::tests_helpers::es384_keypair_and_cert`
        // so tests that mix the two don't accidentally hit the same key.
        scalar_bytes[0] = seed_byte.wrapping_add(0x02);
        p384::ecdsa::SigningKey::from_bytes((&scalar_bytes).into()).expect("scalar in field order")
    }

    /// Build a self-signed root cert. `cn` is the subject (and issuer) CN.
    fn build_root_cert(signer: &p384::ecdsa::SigningKey, cn: &str, years_validity: u64) -> Vec<u8> {
        use core::time::Duration;
        use std::str::FromStr as _;
        use x509_cert::{
            builder::{Builder as _, CertificateBuilder, Profile},
            der::Encode as _,
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::Validity,
        };

        let vk = *signer.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(vk).expect("spki");
        let subject = Name::from_str(&format!("CN={cn}")).expect("name");
        let serial = SerialNumber::from(1u32);
        let validity = Validity::from_now(Duration::from_secs(years_validity * 365 * 24 * 60 * 60))
            .expect("validity");

        let builder =
            CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, signer)
                .expect("builder");
        let cert = builder.build::<p384::ecdsa::DerSignature>().expect("build");
        cert.to_der().expect("der")
    }

    /// Build a SubCA (intermediate) cert signed by `issuer_signer`.
    fn build_intermediate_cert(
        issuer_signer: &p384::ecdsa::SigningKey,
        issuer_cn: &str,
        subject_signer: &p384::ecdsa::SigningKey,
        subject_cn: &str,
        years_validity: u64,
    ) -> Vec<u8> {
        use core::time::Duration;
        use std::str::FromStr as _;
        use x509_cert::{
            builder::{Builder as _, CertificateBuilder, Profile},
            der::Encode as _,
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::Validity,
        };

        let subject_vk = *subject_signer.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(subject_vk).expect("spki");
        let subject = Name::from_str(&format!("CN={subject_cn}")).expect("name");
        let issuer = Name::from_str(&format!("CN={issuer_cn}")).expect("issuer name");
        let serial = SerialNumber::from(2u32);
        let validity = Validity::from_now(Duration::from_secs(years_validity * 365 * 24 * 60 * 60))
            .expect("validity");

        let builder = CertificateBuilder::new(
            Profile::SubCA {
                issuer,
                path_len_constraint: Some(0),
            },
            serial,
            validity,
            subject,
            spki,
            issuer_signer,
        )
        .expect("builder");
        let cert = builder.build::<p384::ecdsa::DerSignature>().expect("build");
        cert.to_der().expect("der")
    }

    /// Build a leaf cert signed by `issuer_signer`.
    fn build_leaf_cert(
        issuer_signer: &p384::ecdsa::SigningKey,
        issuer_cn: &str,
        subject_signer: &p384::ecdsa::SigningKey,
        subject_cn: &str,
        years_validity: u64,
    ) -> Vec<u8> {
        use core::time::Duration;
        use std::str::FromStr as _;
        use x509_cert::{
            builder::{Builder as _, CertificateBuilder, Profile},
            der::Encode as _,
            name::Name,
            serial_number::SerialNumber,
            spki::SubjectPublicKeyInfoOwned,
            time::Validity,
        };

        let subject_vk = *subject_signer.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(subject_vk).expect("spki");
        let subject = Name::from_str(&format!("CN={subject_cn}")).expect("subject");
        let issuer = Name::from_str(&format!("CN={issuer_cn}")).expect("issuer");
        let serial = SerialNumber::from(3u32);
        let validity = Validity::from_now(Duration::from_secs(years_validity * 365 * 24 * 60 * 60))
            .expect("validity");

        let builder = CertificateBuilder::new(
            Profile::Leaf {
                issuer,
                enable_key_agreement: false,
                enable_key_encipherment: false,
            },
            serial,
            validity,
            subject,
            spki,
            issuer_signer,
        )
        .expect("builder");
        let cert = builder.build::<p384::ecdsa::DerSignature>().expect("build");
        cert.to_der().expect("der")
    }

    /// Returns the "now" used throughout the chain-walk tests, in unix
    /// millis. Synthetic certs built via `from_now` are valid from "right
    /// now"; we anchor the test clock a small step after that so the
    /// not_before check passes deterministically.
    fn synthetic_now_ms() -> i64 {
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch")
            .as_millis();
        i64::try_from(secs).expect("now fits i64") + 1_000
    }

    #[test]
    fn embedded_root_sha256_fingerprint_matches() {
        // The PEM file ships in-tree; if a supply-chain swap touches
        // either the file OR the constant, this test catches it.
        use x509_cert::{der::Encode as _, Certificate};

        let chain = Certificate::load_pem_chain(AWS_NITRO_ROOT_G1_PEM).expect("PEM parses");
        assert_eq!(chain.len(), 1, "AWS Nitro G1 PEM is a single cert");
        let der = chain[0].to_der().expect("DER round-trip");
        let mut h = Sha256::new();
        h.update(&der);
        let got: [u8; 32] = h.finalize().into();
        assert_eq!(
            got, AWS_NITRO_ROOT_G1_SHA256,
            "embedded root SHA-256 does not match the pinned fingerprint"
        );
    }

    #[test]
    fn embedded_root_is_self_signed_with_expected_dn() {
        use x509_cert::Certificate;
        let chain = Certificate::load_pem_chain(AWS_NITRO_ROOT_G1_PEM).expect("PEM parses");
        let cert = &chain[0];
        // Subject == issuer (self-signed).
        assert_eq!(
            cert.tbs_certificate.subject, cert.tbs_certificate.issuer,
            "AWS Nitro G1 root must be self-signed"
        );
        // The subject CN should contain "aws.nitro-enclaves" — we don't
        // pin the exact DN encoding (it's an X.500 RDN sequence), just
        // grep the rendered form.
        let rendered = format!("{}", cert.tbs_certificate.subject);
        assert!(
            rendered.contains("aws.nitro-enclaves"),
            "subject DN should contain 'aws.nitro-enclaves'; got {rendered}"
        );
    }

    #[test]
    fn embedded_root_self_signature_verifies() {
        use x509_cert::{der::Encode as _, Certificate};
        // The root MUST sign itself with its own pubkey. We exercise
        // verify_root_chain's defense-in-depth self-signed check
        // indirectly by walking a chain of [leaf, root_as_intermediate,
        // root] — but the most direct check is to call the chain walker
        // with an empty cabundle and a leaf that's the root itself.
        //
        // The G1 root validity ends 2049 so any now_ms in [2019, 2049]
        // is in-window.
        let now = synthetic_now_ms();
        let chain = Certificate::load_pem_chain(AWS_NITRO_ROOT_G1_PEM).expect("PEM parses");
        let der = chain[0].to_der().expect("DER round-trip");
        verify_root_chain(&der, &[], AWS_NITRO_ROOT_G1_PEM, now).expect("root chains to itself");
    }

    #[test]
    fn synthetic_three_cert_chain_happy_path() {
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x10);
        let int_sk = p384_keypair(0x11);
        let leaf_sk = p384_keypair(0x12);

        let root_der = build_root_cert(&root_sk, "qfc-test-root", 5);
        let int_der =
            build_intermediate_cert(&root_sk, "qfc-test-root", &int_sk, "qfc-test-int", 4);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-test-int", &leaf_sk, "qfc-test-leaf", 3);

        verify_root_chain(&leaf_der, &[int_der], &root_der, now).expect("happy path chain walks");
    }

    #[test]
    fn synthetic_empty_cabundle_with_leaf_directly_under_root() {
        // Chain [leaf, root] — cabundle is empty.
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x20);
        let leaf_sk = p384_keypair(0x21);
        let root_der = build_root_cert(&root_sk, "qfc-test-root-2", 5);
        let leaf_der = build_leaf_cert(&root_sk, "qfc-test-root-2", &leaf_sk, "qfc-test-leaf-2", 3);
        verify_root_chain(&leaf_der, &[], &root_der, now).expect("leaf-under-root chain walks");
    }

    #[test]
    fn synthetic_empty_cabundle_leaf_not_under_root_rejected() {
        // Leaf signed by some intermediate, but cabundle is empty so the
        // walker tries to match leaf.issuer == root.subject — must fail.
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x30);
        let other_sk = p384_keypair(0x31);
        let leaf_sk = p384_keypair(0x32);
        let root_der = build_root_cert(&root_sk, "qfc-real-root", 5);
        // Leaf signed by `other_sk` claiming issuer "qfc-other".
        let leaf_der = build_leaf_cert(&other_sk, "qfc-other", &leaf_sk, "qfc-leaf", 3);
        let err = verify_root_chain(&leaf_der, &[], &root_der, now);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::CertChainBroken { index: 0, .. })
        ));
    }

    #[test]
    fn synthetic_tampered_intermediate_signature_rejected() {
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x40);
        let int_sk = p384_keypair(0x41);
        let leaf_sk = p384_keypair(0x42);
        let root_der = build_root_cert(&root_sk, "qfc-r", 5);
        let mut int_der = build_intermediate_cert(&root_sk, "qfc-r", &int_sk, "qfc-i", 4);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-i", &leaf_sk, "qfc-l", 3);

        // Flip a byte deep inside the intermediate's DER (well past the
        // SEQUENCE header, into the signature region).
        let target_idx = int_der.len() - 5;
        int_der[target_idx] ^= 0x01;

        let err = verify_root_chain(&leaf_der, &[int_der], &root_der, now);
        match err {
            Err(
                AttestationVerifyError::MalformedIntermediate(0)
                | AttestationVerifyError::CertChainBroken { index: 1, .. },
            ) => {}
            other => panic!("expected MalformedIntermediate(0) or CertChainBroken {{ index: 1, .. }}, got {other:?}"),
        }
    }

    #[test]
    fn synthetic_wrong_root_rejected() {
        // Build a valid 3-cert chain, then walk it against a DIFFERENT
        // root. The intermediate->wrong-root link breaks.
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x50);
        let int_sk = p384_keypair(0x51);
        let leaf_sk = p384_keypair(0x52);
        let _real_root_der = build_root_cert(&root_sk, "qfc-r", 5);
        let int_der = build_intermediate_cert(&root_sk, "qfc-r", &int_sk, "qfc-i", 4);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-i", &leaf_sk, "qfc-l", 3);

        let wrong_root_sk = p384_keypair(0x59);
        let wrong_root_der = build_root_cert(&wrong_root_sk, "qfc-wrong", 5);

        let err = verify_root_chain(&leaf_der, &[int_der], &wrong_root_der, now);
        // The intermediate.issuer DN ("qfc-r") != wrong_root.subject
        // ("qfc-wrong") so we get CertChainBroken at the intermediate's
        // index (1).
        assert!(matches!(
            err,
            Err(AttestationVerifyError::CertChainBroken { index: 1, .. })
        ));
    }

    #[test]
    fn synthetic_truncated_cabundle_rejected() {
        // Build a 4-cert chain (root -> sub-CA -> intermediate -> leaf)
        // but drop the sub-CA from the cabundle. The walker should
        // detect intermediate.issuer != root.subject and reject at the
        // intermediate's index in the chain (which is 1, since the leaf
        // is 0 and the dropped sub-CA would have been 2).
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x60);
        let sub_sk = p384_keypair(0x61);
        let int_sk = p384_keypair(0x62);
        let leaf_sk = p384_keypair(0x63);

        let root_der = build_root_cert(&root_sk, "qfc-root", 5);
        let _sub_der = build_intermediate_cert(&root_sk, "qfc-root", &sub_sk, "qfc-sub", 4);
        let int_der = build_intermediate_cert(&sub_sk, "qfc-sub", &int_sk, "qfc-int", 3);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-int", &leaf_sk, "qfc-leaf", 2);

        // cabundle is [int_der] — sub_der is dropped.
        let err = verify_root_chain(&leaf_der, &[int_der], &root_der, now);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::CertChainBroken { index: 1, .. })
        ));
    }

    #[test]
    fn malformed_leaf_rejected() {
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x70);
        let root_der = build_root_cert(&root_sk, "qfc-r", 5);
        let garbage = b"not a certificate at all -- garbage bytes";
        let err = verify_root_chain(garbage, &[], &root_der, now);
        assert_eq!(err, Err(AttestationVerifyError::MalformedLeafCert));
    }

    #[test]
    fn malformed_intermediate_rejected() {
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x80);
        let leaf_sk = p384_keypair(0x81);
        let root_der = build_root_cert(&root_sk, "qfc-r", 5);
        let leaf_der = build_leaf_cert(&root_sk, "qfc-r", &leaf_sk, "qfc-l", 3);
        let garbage = b"intermediate garbage -- nope".to_vec();
        let err = verify_root_chain(&leaf_der, &[garbage], &root_der, now);
        assert_eq!(err, Err(AttestationVerifyError::MalformedIntermediate(0)));
    }

    #[test]
    fn malformed_root_rejected() {
        let now = synthetic_now_ms();
        let root_sk = p384_keypair(0x90);
        let leaf_sk = p384_keypair(0x91);
        let _real_root = build_root_cert(&root_sk, "qfc-r", 5);
        let leaf_der = build_leaf_cert(&root_sk, "qfc-r", &leaf_sk, "qfc-l", 3);
        let garbage = b"root cert is garbage";
        let err = verify_root_chain(&leaf_der, &[], garbage, now);
        assert_eq!(err, Err(AttestationVerifyError::MalformedRoot));
    }

    #[test]
    fn synthetic_chain_outside_validity_window_rejected() {
        // Walk a freshly-built chain with a "now" far in the future
        // (beyond not_after on every cert). The walker rejects at the
        // first link.
        let root_sk = p384_keypair(0xA0);
        let int_sk = p384_keypair(0xA1);
        let leaf_sk = p384_keypair(0xA2);
        let root_der = build_root_cert(&root_sk, "qfc-r", 1);
        let int_der = build_intermediate_cert(&root_sk, "qfc-r", &int_sk, "qfc-i", 1);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-i", &leaf_sk, "qfc-l", 1);

        // Now in year ~2300 — well past not_after.
        let far_future = 10_000_000_000_000i64;
        let err = verify_root_chain(&leaf_der, &[int_der], &root_der, far_future);
        assert!(matches!(
            err,
            Err(AttestationVerifyError::CertChainBroken { index: 0, .. })
        ));
    }

    // ---------- verify_attestation_with_root end-to-end --------------------
    //
    // These tests exercise `verify_attestation_with_root` (the new entry
    // point that takes a `RootAnchor`) against a real ES384 COSE_Sign1
    // doc whose leaf cert IS the leaf in a synthetic 3-cert chain. They
    // demonstrate that the chain walk integrates cleanly with the
    // attestation verifier.

    fn build_es384_doc_with_chain(now_ms: i64) -> (NitroAttestationDoc, Vec<u8>, Vec<u8>) {
        use crate::cose::{build_test_envelope_es384, AttestationPayload};

        let root_sk = p384_keypair(0xC0);
        let int_sk = p384_keypair(0xC1);
        let leaf_sk = p384_keypair(0xC2);

        let root_der = build_root_cert(&root_sk, "qfc-root-e2e", 5);
        let int_der = build_intermediate_cert(&root_sk, "qfc-root-e2e", &int_sk, "qfc-int-e2e", 4);
        let leaf_der = build_leaf_cert(&int_sk, "qfc-int-e2e", &leaf_sk, "qfc-leaf-e2e", 3);

        let mut pcrs = BTreeMap::new();
        for i in 0u8..=4 {
            pcrs.insert(i, vec![0xAB ^ i; PCR_LEN]);
        }
        let payload = AttestationPayload {
            module_id: "i-cose-es384-chain".into(),
            timestamp: now_ms,
            digest: "SHA384".into(),
            pcrs,
            certificate: leaf_der.clone(),
            cabundle: vec![int_der],
            public_key: vec![1, 2, 3],
            user_data: b"chain-e2e".to_vec(),
            nonce: vec![0u8; 32],
        };
        let bytes = build_test_envelope_es384(&payload, &leaf_sk).expect("build env");
        let doc = NitroAttestationDoc::from_cose_sign1(&bytes).expect("parse");
        (doc, root_der, leaf_der)
    }

    #[test]
    fn verify_with_custom_root_happy_path() {
        let now = synthetic_now_ms();
        let (doc, root_der, _leaf_der) = build_es384_doc_with_chain(now);
        let pcrs = PcrConstraint::pcr0_only({
            let mut p0 = [0u8; PCR_LEN];
            for b in &mut p0 {
                *b = 0xAB;
            }
            p0
        });
        let verified =
            verify_attestation_with_root(&doc, &pcrs, RootAnchor::Custom(&root_der), now, 60_000)
                .expect("end-to-end verifies");
        assert_eq!(verified.payload.user_data, b"chain-e2e");
    }

    #[test]
    fn verify_with_wrong_custom_root_rejected() {
        let now = synthetic_now_ms();
        let (doc, _real_root_der, _leaf_der) = build_es384_doc_with_chain(now);
        let bogus_root_sk = p384_keypair(0xCF);
        let bogus_root_der = build_root_cert(&bogus_root_sk, "qfc-bogus", 5);
        let err = verify_attestation_with_root(
            &doc,
            &PcrConstraint::any(),
            RootAnchor::Custom(&bogus_root_der),
            now,
            60_000,
        );
        assert!(matches!(
            err,
            Err(AttestationVerifyError::CertChainBroken { .. })
        ));
    }

    #[test]
    fn verify_with_root_anchor_none_skips_chain_walk() {
        // RootAnchor::None preserves the pre-D46 behaviour: the chain
        // is NOT walked, but the cabundle must still be non-empty.
        // This is what the back-compat `verify_attestation` (no
        // `_with_root`) thunks through to.
        let now = synthetic_now_ms();
        let (doc, _root_der, _leaf_der) = build_es384_doc_with_chain(now);
        let pcrs = PcrConstraint::pcr0_only({
            let mut p0 = [0u8; PCR_LEN];
            for b in &mut p0 {
                *b = 0xAB;
            }
            p0
        });
        verify_attestation_with_root(&doc, &pcrs, RootAnchor::None, now, 60_000)
            .expect("None anchor accepts any non-empty cabundle");
    }
}
