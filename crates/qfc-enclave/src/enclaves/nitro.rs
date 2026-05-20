//! `NitroEnclave` — host-side client to a Nitro Enclave's vsock server.
//!
//! See `docs/server-wallet-rfc.md` §1.5 and §7 (M3 scope).
//!
//! ## What this is
//!
//! The host-side facade. The actual signing / SSS-combine / NSM-attestation
//! work happens inside the EIF (in-enclave binary at `enclave/src/main.rs`)
//! over a vsock connection. This struct is the client wrapper the
//! orchestrator talks to.
//!
//! ## Feature gating
//!
//! Real vsock I/O requires Linux + `tokio-vsock`. Pulling that crate
//! unconditionally would break macOS / Windows dev. We feature-gate it
//! behind `nitro` (off by default). Without the feature, every trait method
//! returns `EnclaveError::NotImplemented("nitro feature not enabled")`
//! so the project still builds + the trait shape stays uniform.
//!
//! Tests for the **wire format** (the bincode-over-length-prefix protocol)
//! are feature-independent — they exercise the serialization round trip
//! using an in-memory vector instead of vsock.
//!
//! ## Wire format
//!
//! - Outer framing: `LengthDelimitedCodec` (u32-BE length prefix).
//! - Body: `serde_json` of `NitroWireRequest` / `NitroWireResponse`.
//!
//! JSON is chosen over bincode for the M3 skeleton so the wire is
//! human-readable in test logs and the in-enclave binary doesn't need to
//! pull a serializer that may not be reproducible. Bincode is a future
//! optimization if the wire becomes a hot path.
//!
//! ## `unsafe` allowlist
//!
//! The crate-wide `#![forbid(unsafe_code)]` is **not** relaxed in this
//! file at present — all vsock access goes through safe Rust (`tokio-vsock`
//! exposes a safe API). If we ever switch to a hand-rolled `libc::socket`
//! path, that branch lives behind `#[cfg(feature = "nitro")]` and uses
//! `#[allow(unsafe_code)]` with `SAFETY:` comments per RFC §12.3.

use std::sync::Arc;

use async_trait::async_trait;
use qfc_sss::ShamirShare;
use qfc_wallet_types::{HashAlg, HdPath, RequestId, SigningScheme, WalletId};
use serde::{Deserialize, Serialize};

use crate::attestation::AttestationDoc;
use crate::enclave::{
    Enclave, EnclaveApproval, EnclaveError, EnclaveSignRequest, EnclaveSignResponse,
    GenerateWalletRequest, GenerateWalletResponse, SigningContext,
};
use crate::verify_attestation::PcrConstraint;
use qfc_policy::SignedPolicyDecision;

/// AWS vsock CID for the parent (host) — this is the well-known value
/// hosts use to address themselves over vsock.
pub const VMADDR_CID_PARENT: u32 = 3;

/// Default port the in-enclave server listens on.
pub const NITRO_DEFAULT_PORT: u32 = 5005;

/// Vsock address (cid, port). Pure data type that's feature-independent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VsockAddr {
    /// Vsock CID (AWS_NITRO_ENCLAVES_CID is in `nitro-cli describe-enclaves`).
    pub cid: u32,
    /// Vsock port.
    pub port: u32,
}

impl VsockAddr {
    /// Construct a vsock address.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }
}

/// Request envelope sent host → enclave over vsock.
///
/// Serialized with `serde_json` then framed with a `u32`-big-endian length
/// prefix.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum NitroWireRequest {
    /// `attest(nonce)` — produce a fresh NSM attestation document.
    Attest {
        /// Caller-supplied 32-byte nonce embedded in the attestation.
        nonce: [u8; 32],
    },
    /// `sign_in_enclave(req)`.
    Sign(NitroSignRequest),
    /// `generate_wallet(req)`.
    GenerateWallet(NitroGenerateRequest),
}

/// Sign request body. Subset of `EnclaveSignRequest` that's serialization-safe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroSignRequest {
    /// Per `EnclaveSignRequest`.
    pub request_id: RequestId,
    /// Per `EnclaveSignRequest`.
    pub wallet_id: WalletId,
    /// Per `EnclaveSignRequest`.
    pub shares: Vec<ShamirShare>,
    /// Per `EnclaveSignRequest`.
    pub scheme: SigningScheme,
    /// Per `EnclaveSignRequest`.
    pub hd_path: Option<HdPath>,
    /// Per `EnclaveSignRequest`.
    #[serde(with = "serde_bytes")]
    pub message: Vec<u8>,
    /// Per `EnclaveSignRequest`.
    pub hash_alg: HashAlg,
    /// Per `EnclaveSignRequest`.
    pub context: SigningContext,
    /// Per `EnclaveSignRequest`. Optional in M3.
    pub policy_decision: Option<SignedPolicyDecision>,
    /// Per `EnclaveSignRequest`.
    pub approvals: Vec<EnclaveApproval>,
}

/// Generate request body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NitroGenerateRequest {
    /// Per `GenerateWalletRequest`.
    pub wallet_id: WalletId,
    /// Per `GenerateWalletRequest`.
    pub scheme: SigningScheme,
    /// Per `GenerateWalletRequest`.
    pub threshold: u8,
    /// Per `GenerateWalletRequest`.
    pub total: u8,
    /// Per `GenerateWalletRequest`.
    pub master_hd_path: Option<HdPath>,
}

/// Response envelope sent enclave → host over vsock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NitroWireResponse {
    /// Result of `Attest`.
    Attest {
        /// COSE_Sign1 NSM attestation document or M3-skeleton mock attestation.
        attestation: AttestationDoc,
    },
    /// Result of `Sign`.
    Sign {
        /// Signature bytes.
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
        /// Derived public key bytes.
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
        /// Attestation binding the operation.
        attestation: AttestationDoc,
    },
    /// Result of `GenerateWallet`.
    GenerateWallet {
        /// Newly minted shares.
        shares: Vec<ShamirShare>,
        /// Public key derived at `master_hd_path`.
        #[serde(with = "serde_bytes")]
        master_public_key: Vec<u8>,
        /// Attestation binding the wallet creation.
        attestation: AttestationDoc,
    },
    /// In-enclave error.
    Error {
        /// Human-readable error.
        message: String,
    },
}

/// Host-side facade. Construct via `NitroEnclaveBuilder`.
pub struct NitroEnclave {
    vsock_addr: VsockAddr,
    expected_pcrs: Arc<PcrConstraint>,
}

impl std::fmt::Debug for NitroEnclave {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NitroEnclave")
            .field("vsock_addr", &self.vsock_addr)
            .field("expected_pcrs", &self.expected_pcrs)
            .finish()
    }
}

impl NitroEnclave {
    /// Borrow the vsock address.
    #[must_use]
    pub fn vsock_addr(&self) -> VsockAddr {
        self.vsock_addr
    }

    /// Borrow the expected PCR constraint.
    #[must_use]
    pub fn expected_pcrs(&self) -> &PcrConstraint {
        &self.expected_pcrs
    }

    /// Send a request, wait for a response. Real implementation requires
    /// the `nitro` feature. The stub branch returns `NotImplemented` so the
    /// trait surface is uniform on dev hosts.
    async fn round_trip(
        &self,
        _req: NitroWireRequest,
    ) -> Result<NitroWireResponse, EnclaveError> {
        #[cfg(feature = "nitro")]
        {
            // SAFETY: tokio-vsock's API is safe Rust; no unsafe block needed.
            //
            // The wire format is `LengthDelimitedCodec` framing of
            // `serde_json::to_vec(&NitroWireRequest)`. The enclave-side
            // counterpart (`enclave/src/main.rs`) mirrors this.
            use futures::SinkExt;
            use tokio_util::codec::{Framed, LengthDelimitedCodec};
            use tokio_stream::StreamExt;

            let stream = tokio_vsock::VsockStream::connect(
                tokio_vsock::VsockAddr::new(self.vsock_addr.cid, self.vsock_addr.port),
            )
            .await
            .map_err(|e| {
                EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                    format!("vsock connect: {e}"),
                ))
            })?;
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            let body = serde_json::to_vec(&_req).map_err(|e| {
                EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                    e.to_string(),
                ))
            })?;
            framed.send(body.into()).await.map_err(|e| {
                EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                    format!("vsock send: {e}"),
                ))
            })?;
            let resp_bytes = framed
                .next()
                .await
                .ok_or_else(|| {
                    EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                        "vsock closed".into(),
                    ))
                })?
                .map_err(|e| {
                    EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                        format!("vsock recv: {e}"),
                    ))
                })?;
            let resp: NitroWireResponse = serde_json::from_slice(&resp_bytes).map_err(|e| {
                EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                    e.to_string(),
                ))
            })?;
            Ok(resp)
        }
        #[cfg(not(feature = "nitro"))]
        {
            Err(EnclaveError::NotImplemented(
                "nitro feature not enabled — build with --features nitro on a Nitro host",
            ))
        }
    }
}

/// Builder for `NitroEnclave`. Required fields are checked at `build()` time.
pub struct NitroEnclaveBuilder {
    vsock_addr: Option<VsockAddr>,
    expected_pcrs: Option<PcrConstraint>,
}

impl NitroEnclaveBuilder {
    /// Start a fresh builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            vsock_addr: None,
            expected_pcrs: None,
        }
    }

    /// Set the vsock address of the in-enclave server.
    #[must_use]
    pub fn vsock(mut self, addr: VsockAddr) -> Self {
        self.vsock_addr = Some(addr);
        self
    }

    /// Set the PCR constraint the host expects to see in every NSM
    /// attestation. Production deployments pin every wallet to a specific
    /// PCR set; the host fails closed on mismatch.
    #[must_use]
    pub fn expected_pcrs(mut self, pcrs: PcrConstraint) -> Self {
        self.expected_pcrs = Some(pcrs);
        self
    }

    /// Build a `NitroEnclave`. Returns `EnclaveError::InvalidRequest` if a
    /// required field is missing.
    ///
    /// # Errors
    ///
    /// `EnclaveError::InvalidRequest` if `vsock_addr` or `expected_pcrs`
    /// have not been set.
    pub fn build(self) -> Result<NitroEnclave, EnclaveError> {
        let vsock_addr = self
            .vsock_addr
            .ok_or(EnclaveError::InvalidRequest("vsock_addr not set"))?;
        let expected_pcrs = self
            .expected_pcrs
            .ok_or(EnclaveError::InvalidRequest("expected_pcrs not set"))?;
        Ok(NitroEnclave {
            vsock_addr,
            expected_pcrs: Arc::new(expected_pcrs),
        })
    }
}

impl Default for NitroEnclaveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Enclave for NitroEnclave {
    async fn attest(&self, nonce: [u8; 32]) -> Result<AttestationDoc, EnclaveError> {
        match self.round_trip(NitroWireRequest::Attest { nonce }).await? {
            NitroWireResponse::Attest { attestation } => Ok(attestation),
            NitroWireResponse::Error { message } => {
                Err(EnclaveError::InvalidRequest(Box::leak(message.into_boxed_str())))
            }
            _ => Err(EnclaveError::InvalidRequest("unexpected nitro response")),
        }
    }

    async fn sign_in_enclave(
        &self,
        req: EnclaveSignRequest,
    ) -> Result<EnclaveSignResponse, EnclaveError> {
        let wire = NitroWireRequest::Sign(NitroSignRequest {
            request_id: req.request_id,
            wallet_id: req.wallet_id,
            shares: req.shares,
            scheme: req.scheme,
            hd_path: req.hd_path,
            message: req.message,
            hash_alg: req.hash_alg,
            context: req.context,
            policy_decision: req.policy_decision,
            approvals: req.approvals,
        });
        match self.round_trip(wire).await? {
            NitroWireResponse::Sign {
                signature,
                public_key,
                attestation,
            } => Ok(EnclaveSignResponse {
                signature,
                public_key,
                attestation,
            }),
            NitroWireResponse::Error { message } => Err(EnclaveError::InvalidRequest(
                Box::leak(message.into_boxed_str()),
            )),
            _ => Err(EnclaveError::InvalidRequest("unexpected nitro response")),
        }
    }

    async fn generate_wallet(
        &self,
        req: GenerateWalletRequest,
    ) -> Result<GenerateWalletResponse, EnclaveError> {
        let wire = NitroWireRequest::GenerateWallet(NitroGenerateRequest {
            wallet_id: req.wallet_id,
            scheme: req.scheme,
            threshold: req.threshold,
            total: req.total,
            master_hd_path: req.master_hd_path,
        });
        match self.round_trip(wire).await? {
            NitroWireResponse::GenerateWallet {
                shares,
                master_public_key,
                attestation,
            } => Ok(GenerateWalletResponse {
                shares,
                master_public_key,
                attestation,
            }),
            NitroWireResponse::Error { message } => Err(EnclaveError::InvalidRequest(
                Box::leak(message.into_boxed_str()),
            )),
            _ => Err(EnclaveError::InvalidRequest("unexpected nitro response")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify_attestation::PcrConstraint;

    #[test]
    fn builder_requires_vsock_addr() {
        let err = NitroEnclaveBuilder::new()
            .expected_pcrs(PcrConstraint::any())
            .build();
        assert!(matches!(err, Err(EnclaveError::InvalidRequest(_))));
    }

    #[test]
    fn builder_requires_pcr_constraint() {
        let err = NitroEnclaveBuilder::new()
            .vsock(VsockAddr::new(16, NITRO_DEFAULT_PORT))
            .build();
        assert!(matches!(err, Err(EnclaveError::InvalidRequest(_))));
    }

    #[test]
    fn builder_constructs_with_required_fields() {
        let enc = NitroEnclaveBuilder::new()
            .vsock(VsockAddr::new(16, NITRO_DEFAULT_PORT))
            .expected_pcrs(PcrConstraint::any())
            .build()
            .expect("build");
        assert_eq!(enc.vsock_addr().cid, 16);
        assert_eq!(enc.vsock_addr().port, NITRO_DEFAULT_PORT);
    }

    #[tokio::test]
    async fn attest_without_nitro_feature_returns_not_implemented() {
        let enc = NitroEnclaveBuilder::new()
            .vsock(VsockAddr::new(16, NITRO_DEFAULT_PORT))
            .expected_pcrs(PcrConstraint::any())
            .build()
            .unwrap();
        let err = enc.attest([0u8; 32]).await;
        #[cfg(not(feature = "nitro"))]
        assert!(matches!(err, Err(EnclaveError::NotImplemented(_))));
        #[cfg(feature = "nitro")]
        {
            // With the feature the connect itself will fail (no enclave to
            // talk to in CI). The shape of the error differs but it
            // should be some Err.
            assert!(err.is_err());
        }
    }

    #[test]
    fn wire_request_attest_round_trips() {
        let r = NitroWireRequest::Attest { nonce: [42u8; 32] };
        let s = serde_json::to_vec(&r).unwrap();
        let back: NitroWireRequest = serde_json::from_slice(&s).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn wire_request_generate_round_trips() {
        let r = NitroWireRequest::GenerateWallet(NitroGenerateRequest {
            wallet_id: WalletId::new(),
            scheme: SigningScheme::Ed25519,
            threshold: 2,
            total: 3,
            master_hd_path: None,
        });
        let s = serde_json::to_vec(&r).unwrap();
        let back: NitroWireRequest = serde_json::from_slice(&s).unwrap();
        assert_eq!(r, back);
    }
}
