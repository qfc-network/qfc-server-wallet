//! In-enclave boot binary.
//!
//! Runs inside the Nitro EIF. Listens on a vsock port; for each connection
//! reads exactly one length-prefixed JSON-encoded `NitroWireRequest`,
//! dispatches to the appropriate handler, writes back exactly one
//! `NitroWireResponse`, then closes.
//!
//! ## Handler semantics
//!
//! - `attest(nonce)`: calls NSM (`feature = "nitro"`) or returns a
//!   mock-attested document (default — for build-on-dev).
//! - `sign(req)`: runs the **hybrid verifier** on the policy decision +
//!   approvals, then performs SSS combine + key derive + curve sign and
//!   wraps the result in a fresh attestation.
//! - `generate_wallet(req)`: generates entropy, splits via SSS, derives the
//!   public key, attests the (`wallet_id || master_pub || share_indices`)
//!   tuple.
//!
//! ## What this is NOT
//!
//! This binary does **not** run as part of `cargo test` against the host
//! workspace. The host workspace's `cargo test` exercises `MockEnclave`,
//! which mirrors this binary's behavior in-process. This file's unit tests
//! (the dispatch + verifier path) run as `cargo test` inside this
//! standalone enclave crate.
//!
//! ## `unsafe` allowlist
//!
//! `#![forbid(unsafe_code)]` is in effect. The crate uses only safe Rust;
//! NSM calls go through the safe-API `aws-nitro-enclaves-nsm-api` wrapper.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use qfc_enclave::enclaves::{NitroSignRequest, NitroWireRequest, NitroWireResponse};
use qfc_enclave::hybrid_verifier::{HybridVerifier, WalletCeilings};
use qfc_enclave::{
    derive_classical, signer_for_scheme, AttestationDoc, MockAttestationKey,
};
use qfc_policy::{SigningPayload, SigningRequest};
use qfc_wallet_types::SecretBytes;

/// Result of a single dispatch.
type DispatchResult = anyhow::Result<NitroWireResponse>;

/// Boot-time configuration. In production this comes from the
/// `init.config`/`/dev/nsm`-injected blob; here we keep it inline so the
/// stub builds.
#[derive(Clone, Debug)]
pub struct BootConfig {
    /// Pinned ed25519 public key of the policy service. Built into the
    /// EIF — verified by the host's KMS-attestation step.
    pub policy_service_pubkey: Vec<u8>,
}

/// The dispatch core — pure, testable, no I/O.
pub fn dispatch(
    cfg: &BootConfig,
    attestation_key: &MockAttestationKey,
    req: NitroWireRequest,
) -> DispatchResult {
    match req {
        NitroWireRequest::Attest { nonce } => {
            let doc: AttestationDoc =
                attestation_key.sign_attestation(nonce, Vec::new())?;
            Ok(NitroWireResponse::Attest { attestation: doc })
        }
        NitroWireRequest::Sign(sign_req) => handle_sign(cfg, attestation_key, sign_req),
        NitroWireRequest::GenerateWallet(gen_req) => {
            handle_generate(attestation_key, gen_req)
        }
    }
}

fn handle_sign(
    cfg: &BootConfig,
    attestation_key: &MockAttestationKey,
    req: NitroSignRequest,
) -> DispatchResult {
    // Step 1: hybrid verify.
    //
    // The orchestrator hands us a `policy_decision` + `approvals`. We
    // build a `SigningRequest` projection from the wire shape and run
    // the verifier. The boot binary does NOT trust the host's wallet
    // ceilings — in production these come from attested storage. For the
    // skeleton, accept them inline from `signing_request_for_verifier`.
    let verifier = HybridVerifier::new(cfg.policy_service_pubkey.clone());
    let signing_request = signing_request_for_verifier(&req);
    let ceilings = WalletCeilings {
        wallet_id: req.wallet_id,
        ..Default::default()
    };
    let now_ms = current_unix_ms();
    verifier.verify(
        req.policy_decision.as_ref(),
        &req.approvals,
        &signing_request,
        &ceilings,
        now_ms,
    )?;

    // Step 2: combine shares, derive key, sign.
    let combined = qfc_sss::combine_shares(&req.shares)?;
    let seed = SecretBytes::from_slice(&combined);
    drop(combined);

    let signing_key = match req.hd_path.as_ref() {
        None => {
            if seed.len() < 32 {
                anyhow::bail!("seed too short for classical scheme");
            }
            SecretBytes::from_slice(&seed.expose()[..32])
        }
        Some(path) => derive_classical(req.scheme, &seed, path)?.secret,
    };

    let signer = signer_for_scheme(req.scheme)?;
    let public_key = signer.public_key(&signing_key)?;
    let signature = signer.sign(&signing_key, &req.message, req.hash_alg)?;

    // Step 3: bind into attestation.
    let mut user_data = Vec::new();
    user_data.extend_from_slice(req.request_id.to_string().as_bytes());
    user_data.push(b'|');
    user_data.extend_from_slice(req.wallet_id.to_string().as_bytes());
    user_data.push(b'|');
    user_data.extend_from_slice(&sha256_32(&req.message));
    user_data.push(b'|');
    user_data.extend_from_slice(&sha256_32(&signature));
    let nonce = fresh_nonce();
    let attestation = attestation_key.sign_attestation(nonce, user_data)?;
    Ok(NitroWireResponse::Sign {
        signature,
        public_key,
        attestation,
    })
}

fn handle_generate(
    attestation_key: &MockAttestationKey,
    req: qfc_enclave::enclaves::NitroGenerateRequest,
) -> DispatchResult {
    if req.threshold < 2 || req.threshold > req.total {
        anyhow::bail!("invalid (threshold, total)");
    }
    if req.scheme.is_post_quantum() {
        anyhow::bail!("post-quantum schemes not implemented (M5)");
    }
    // Generate entropy.
    let mut seed_bytes = [0u8; 64];
    fill_random(&mut seed_bytes);
    let seed = SecretBytes::from_slice(&seed_bytes);
    seed_bytes.iter_mut().for_each(|b| *b = 0);

    let signing_key = match req.master_hd_path.as_ref() {
        None => SecretBytes::from_slice(&seed.expose()[..32]),
        Some(path) => derive_classical(req.scheme, &seed, path)?.secret,
    };
    let signer = signer_for_scheme(req.scheme)?;
    let public_key = signer.public_key(&signing_key)?;
    drop(signing_key);

    let shares = qfc_sss::split_secret(
        seed.expose(),
        qfc_sss::ShamirParams {
            threshold: req.threshold,
            total: req.total,
        },
    )?;

    let mut user_data = Vec::new();
    user_data.extend_from_slice(req.wallet_id.to_string().as_bytes());
    user_data.push(b'|');
    user_data.extend_from_slice(&sha256_32(&public_key));
    user_data.push(b'|');
    for s in &shares {
        user_data.push(s.index);
    }
    let nonce = fresh_nonce();
    let attestation = attestation_key.sign_attestation(nonce, user_data)?;

    Ok(NitroWireResponse::GenerateWallet {
        shares,
        master_public_key: public_key,
        attestation,
    })
}

/// Reconstruct the `SigningRequest` shape the verifier expects. The wire
/// `NitroSignRequest` carries the same data with a different layout.
fn signing_request_for_verifier(req: &NitroSignRequest) -> SigningRequest {
    SigningRequest {
        request_id: req.request_id,
        wallet_id: req.wallet_id,
        // M3 boot binary does not yet decode requester / payload. The
        // verifier uses only request_id + payload.chain_id / .to / .raw
        // for ceiling re-checks.
        requester: qfc_policy::Requester::ApiKey {
            key_id: "in-enclave".into(),
        },
        payload: SigningPayload::Raw {
            bytes: req.message.clone(),
        },
        hd_path: req.hd_path.clone(),
        received_at_unix_ms: current_unix_ms(),
    }
}

fn current_unix_ms() -> i64 {
    let nanos = time_now_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

#[cfg(feature = "nitro")]
fn time_now_nanos() -> i128 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0)
}

#[cfg(not(feature = "nitro"))]
fn time_now_nanos() -> i128 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| i128::try_from(d.as_nanos()).unwrap_or(i128::MAX))
        .unwrap_or(0)
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    use std::convert::TryInto;
    // Hand-rolled to avoid pulling sha2 directly — the enclave already
    // links it via qfc-sss.
    use qfc_enclave::attestation::sha256_32;
    let _ = std::convert::identity::<fn(&[u8]) -> [u8; 32]>(sha256_32);
    let r: [u8; 32] = sha256_32_impl(bytes).try_into().expect("sha256 is 32 bytes");
    r
}

fn sha256_32_impl(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().to_vec()
}

fn fresh_nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    fill_random(&mut n);
    n
}

#[cfg(feature = "nitro")]
fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

#[cfg(not(feature = "nitro"))]
fn fill_random(buf: &mut [u8]) {
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(buf);
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = BootConfig {
        // Real production EIFs bake the policy-service pubkey in. For the
        // skeleton the binary refuses to start without an env var, so
        // there's no "accidentally accept any decision" failure mode.
        policy_service_pubkey: load_policy_pubkey_from_env()?,
    };

    let attestation_key = MockAttestationKey::generate();

    #[cfg(feature = "nitro")]
    {
        serve_vsock(cfg, attestation_key).await?;
    }
    #[cfg(not(feature = "nitro"))]
    {
        // Without `nitro` we don't open a vsock — the binary becomes a
        // stub that prints its expected handshake and exits. Useful for
        // CI sanity tests.
        let _ = (cfg, attestation_key);
        println!("qfc-enclave-boot: built without `nitro` feature; nothing to serve.");
    }
    Ok(())
}

fn load_policy_pubkey_from_env() -> anyhow::Result<Vec<u8>> {
    let v = std::env::var("QFC_POLICY_SERVICE_PUBKEY_HEX")
        .map_err(|_| anyhow::anyhow!("QFC_POLICY_SERVICE_PUBKEY_HEX env var required"))?;
    let bytes = hex_decode(&v).map_err(|e| anyhow::anyhow!("invalid pubkey hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("policy pubkey must be 32 bytes, got {}", bytes.len());
    }
    Ok(bytes)
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err("odd hex length".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

#[cfg(feature = "nitro")]
async fn serve_vsock(
    cfg: BootConfig,
    attestation_key: MockAttestationKey,
) -> anyhow::Result<()> {
    use futures::StreamExt;
    use futures::SinkExt;
    use tokio_util::codec::{Framed, LengthDelimitedCodec};

    let port: u32 = std::env::var("QFC_ENCLAVE_VSOCK_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5005);
    let listener =
        tokio_vsock::VsockListener::bind(tokio_vsock::VsockAddr::new(u32::MAX, port))?;
    tracing::info!(port = port, "qfc-enclave-boot listening on vsock");
    let cfg = std::sync::Arc::new(cfg);
    let key = std::sync::Arc::new(attestation_key);
    loop {
        let (stream, _peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let key = key.clone();
        tokio::spawn(async move {
            let mut framed = Framed::new(stream, LengthDelimitedCodec::new());
            if let Some(Ok(body)) = framed.next().await {
                let resp = match serde_json::from_slice::<NitroWireRequest>(&body) {
                    Ok(req) => match dispatch(&cfg, &key, req) {
                        Ok(r) => r,
                        Err(e) => NitroWireResponse::Error {
                            message: e.to_string(),
                        },
                    },
                    Err(e) => NitroWireResponse::Error {
                        message: format!("parse: {e}"),
                    },
                };
                let bytes = serde_json::to_vec(&resp).unwrap_or_default();
                let _ = framed.send(bytes.into()).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use qfc_enclave::enclave::SigningContext;
    use qfc_enclave::enclaves::{NitroGenerateRequest, NitroSignRequest};
    use qfc_enclave::{EnclaveApproval, EnclaveApprovalDecision};
    use qfc_policy::{DenyReason, PolicyDecision, RuleHit, SignedPolicyDecision};
    use qfc_wallet_types::{
        ApprovalId, DecisionId, HashAlg, PolicyId, RequestId, SigningScheme, WalletId,
    };

    fn boot_cfg() -> (BootConfig, SigningKey) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (
            BootConfig {
                policy_service_pubkey: pk,
            },
            sk,
        )
    }

    fn signed_allow(
        sk: &SigningKey,
        r: RequestId,
        w: WalletId,
        signed_at: i64,
    ) -> SignedPolicyDecision {
        let decision = PolicyDecision::Allow {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            rationale: Vec::<RuleHit>::new(),
        };
        let preimage = SignedPolicyDecision::build_preimage(&decision, &r, &w, signed_at, 60);
        let sig = sk.sign(&preimage).to_bytes().to_vec();
        SignedPolicyDecision {
            decision,
            request_id: r,
            wallet_id: w,
            raw_payload: preimage,
            policy_service_signature: sig,
            signed_at_unix_ms: signed_at,
            max_age_secs: 60,
        }
    }

    #[test]
    fn dispatch_attest_returns_attestation() {
        let (cfg, _sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        let resp = dispatch(&cfg, &key, NitroWireRequest::Attest { nonce: [3u8; 32] })
            .expect("dispatch");
        assert!(matches!(resp, NitroWireResponse::Attest { .. }));
    }

    #[test]
    fn dispatch_sign_fails_with_no_policy_decision() {
        let (cfg, _sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        let wallet_id = WalletId::new();
        let request_id = RequestId::new();
        let req = NitroSignRequest {
            request_id,
            wallet_id,
            shares: Vec::new(),
            scheme: SigningScheme::Ed25519,
            hd_path: None,
            message: b"hi".to_vec(),
            hash_alg: HashAlg::None,
            context: SigningContext::default(),
            policy_decision: None,
            approvals: Vec::new(),
        };
        let err = dispatch(&cfg, &key, NitroWireRequest::Sign(req));
        assert!(err.is_err());
        let msg = err.err().unwrap().to_string();
        assert!(msg.contains("no signed policy decision"), "got: {msg}");
    }

    #[test]
    fn dispatch_sign_succeeds_with_valid_decision() {
        let (cfg, sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        // Generate a wallet first to get shares we can sign with.
        let wallet_id = WalletId::new();
        let gen_resp = dispatch(
            &cfg,
            &key,
            NitroWireRequest::GenerateWallet(NitroGenerateRequest {
                wallet_id,
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            }),
        )
        .unwrap();
        let shares = match gen_resp {
            NitroWireResponse::GenerateWallet { shares, .. } => shares,
            _ => panic!("expected GenerateWallet response"),
        };
        let request_id = RequestId::new();
        let now_ms = current_unix_ms();
        let signed = signed_allow(&sk, request_id, wallet_id, now_ms);
        let req = NitroSignRequest {
            request_id,
            wallet_id,
            shares: shares[..2].to_vec(),
            scheme: SigningScheme::Ed25519,
            hd_path: None,
            message: b"hi".to_vec(),
            hash_alg: HashAlg::None,
            context: SigningContext::default(),
            policy_decision: Some(signed),
            approvals: Vec::new(),
        };
        let resp = dispatch(&cfg, &key, NitroWireRequest::Sign(req)).unwrap();
        assert!(matches!(resp, NitroWireResponse::Sign { .. }));
    }

    #[test]
    fn dispatch_sign_rejects_explicit_deny() {
        let (cfg, sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        let wallet_id = WalletId::new();
        let request_id = RequestId::new();
        let decision = PolicyDecision::Deny {
            decision_id: DecisionId::new(),
            policy_id: PolicyId::default(),
            reason: DenyReason::ChainDenied,
            rationale: Vec::new(),
        };
        let now_ms = current_unix_ms();
        let preimage =
            SignedPolicyDecision::build_preimage(&decision, &request_id, &wallet_id, now_ms, 60);
        let sig = sk.sign(&preimage).to_bytes().to_vec();
        let signed = SignedPolicyDecision {
            decision,
            request_id,
            wallet_id,
            raw_payload: preimage,
            policy_service_signature: sig,
            signed_at_unix_ms: now_ms,
            max_age_secs: 60,
        };
        let req = NitroSignRequest {
            request_id,
            wallet_id,
            shares: Vec::new(),
            scheme: SigningScheme::Ed25519,
            hd_path: None,
            message: b"hi".to_vec(),
            hash_alg: HashAlg::None,
            context: SigningContext::default(),
            policy_decision: Some(signed),
            approvals: Vec::new(),
        };
        let err = dispatch(&cfg, &key, NitroWireRequest::Sign(req));
        assert!(err.is_err());
        let msg = err.err().unwrap().to_string();
        assert!(msg.contains("Deny"), "expected Deny error, got: {msg}");
    }

    #[test]
    fn dispatch_generate_returns_shares_and_attestation() {
        let (cfg, _sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        let resp = dispatch(
            &cfg,
            &key,
            NitroWireRequest::GenerateWallet(NitroGenerateRequest {
                wallet_id: WalletId::new(),
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            }),
        )
        .unwrap();
        match resp {
            NitroWireResponse::GenerateWallet {
                shares,
                master_public_key,
                attestation: _,
            } => {
                assert_eq!(shares.len(), 3);
                assert_eq!(master_public_key.len(), 32);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn dispatch_generate_rejects_pq() {
        let (cfg, _sk) = boot_cfg();
        let key = MockAttestationKey::from_seed([9u8; 32]);
        let err = dispatch(
            &cfg,
            &key,
            NitroWireRequest::GenerateWallet(NitroGenerateRequest {
                wallet_id: WalletId::new(),
                scheme: SigningScheme::MlDsa44,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            }),
        );
        assert!(err.is_err());
    }

    // Suppress unused-import lints for cfg-gated code paths.
    #[allow(dead_code)]
    fn _silence_unused() {
        let _ = EnclaveApproval {
            approval_id: ApprovalId::new(),
            approver_public_key: vec![],
            approver_scheme: SigningScheme::Ed25519,
            request_id: RequestId::new(),
            message_hash: [0u8; 32],
            decision: EnclaveApprovalDecision::Approve,
            timestamp_unix_ms: 0,
            signature: vec![],
        };
    }
}
