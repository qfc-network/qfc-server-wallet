//! `MockEnclave` — in-process implementation of the `Enclave` trait.
//!
//! Same production crypto (k256 / ed25519-dalek / vsss-rs), just no memory
//! isolation, no real attestation, no PCR binding. Fail-closed by default:
//! `MockEnclave::new()` returns `EnclaveError::MockNotAllowed` unless the
//! `QFC_ALLOW_MOCK_ENCLAVE` env var is set to `yes-i-know`. Tests that
//! actually want a `MockEnclave` use `MockEnclave::new_for_testing()`,
//! which bypasses the env var and is gated behind a clearly-named API.

use async_trait::async_trait;
use qfc_policy::{SigningPayload as PolicySigningPayload, SigningRequest as PolicySigningRequest};
use qfc_sss::{combine_shares, split_secret, ShamirParams, ShamirShare};
use qfc_wallet_types::{HdPath, SecretBytes, SigningScheme};
use rand::rngs::OsRng;
use rand::RngCore;

use crate::attestation::{sha256_32, AttestationDoc, MockAttestationKey};
use crate::derivation::derive_classical;
use crate::enclave::{
    Enclave, EnclaveError, EnclaveSignRequest, EnclaveSignResponse, GenerateWalletRequest,
    GenerateWalletResponse,
};
use crate::hybrid_verifier::{HybridVerifier, WalletCeilings};
use crate::signer::signer_for_scheme;

/// Sentinel value the operator must set to opt into mock enclave usage.
pub const MOCK_ENABLE_ENV: &str = "QFC_ALLOW_MOCK_ENCLAVE";
const MOCK_ENABLE_VALUE: &str = "yes-i-know";

/// In-process enclave. Holds its own attestation key.
///
/// M3 §3.4 follow-up: when configured with a pinned policy-service public
/// key via [`MockEnclave::with_policy_service_pubkey`], `sign_in_enclave`
/// invokes the [`HybridVerifier`] before any SSS combine / curve sign.
/// This brings the mock backend into parity with what the Nitro EIF boot
/// binary does in production.
pub struct MockEnclave {
    attestation_key: MockAttestationKey,
    /// Pinned policy-service public key. When `Some`, the hybrid verifier
    /// is invoked on every `sign_in_enclave`. When `None`, the mock skips
    /// hybrid verification entirely — preserves M1/M2 back-compat.
    policy_service_pubkey: Option<Vec<u8>>,
    /// When `true` (and `policy_service_pubkey` is `Some`), the mock
    /// rejects sign requests that carry `policy_decision: None`. Defaults
    /// to `false` so callers that opt into hybrid verification can still
    /// accept legacy in-flight requests during a migration window. Per
    /// `docs/m3-decisions.md` D21, the in-enclave verifier itself defaults
    /// fail-closed; this mock-level flag is the looser default to keep the
    /// migration window open.
    require_signed_decision: bool,
}

impl MockEnclave {
    /// Construct a `MockEnclave`. Returns `EnclaveError::MockNotAllowed`
    /// unless the operator has set `QFC_ALLOW_MOCK_ENCLAVE=yes-i-know`.
    ///
    /// # Errors
    ///
    /// `EnclaveError::MockNotAllowed` when the env var is missing / wrong.
    pub fn new() -> Result<Self, EnclaveError> {
        let env = std::env::var(MOCK_ENABLE_ENV).ok();
        if Self::env_gate_open(env.as_deref()) {
            Ok(Self {
                attestation_key: MockAttestationKey::generate(),
                policy_service_pubkey: None,
                require_signed_decision: false,
            })
        } else {
            Err(EnclaveError::MockNotAllowed)
        }
    }

    /// Test-only constructor that bypasses the env-var safety check.
    ///
    /// Compiled in regardless of `cfg(test)` because integration tests in
    /// other crates need it; the explicit name `_for_testing` documents
    /// the intent and any audit grep will flag accidental production
    /// usage.
    #[must_use]
    pub fn new_for_testing() -> Self {
        Self {
            attestation_key: MockAttestationKey::generate(),
            policy_service_pubkey: None,
            require_signed_decision: false,
        }
    }

    /// Deterministic test constructor — seeds the attestation key from
    /// `seed` so tests can pin attestation public keys.
    #[must_use]
    pub fn new_for_testing_with_seed(seed: [u8; 32]) -> Self {
        Self {
            attestation_key: MockAttestationKey::from_seed(seed),
            policy_service_pubkey: None,
            require_signed_decision: false,
        }
    }

    /// Pin the policy-service public key the in-enclave hybrid verifier
    /// trusts. When set, every `sign_in_enclave` that carries a
    /// `policy_decision` is re-verified by [`HybridVerifier`] before
    /// share-combine + curve-sign.
    ///
    /// Production deployments MUST set this to the policy-service's
    /// identity key. Without it, the hybrid scheme degrades to "host
    /// trusts the policy decision blindly" — which defeats the whole
    /// point.
    #[must_use]
    pub fn with_policy_service_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.policy_service_pubkey = Some(pubkey);
        self
    }

    /// When set (in combination with [`Self::with_policy_service_pubkey`]),
    /// the mock rejects sign requests that don't carry a
    /// `SignedPolicyDecision`. Defaults to `false`.
    ///
    /// Use `true` for production-style integration tests where every sign
    /// MUST be policy-signed. Use `false` (the default) for migration /
    /// back-compat tests where some flows pre-date the signer wiring.
    #[must_use]
    pub fn with_require_signed_decision(mut self, require: bool) -> Self {
        self.require_signed_decision = require;
        self
    }

    /// Borrow the mock's attestation public key (32-byte ed25519). Useful
    /// for tests that want to bind an expected public key.
    #[must_use]
    pub fn attestation_public_key(&self) -> Vec<u8> {
        self.attestation_key.public_key_bytes()
    }

    fn check_share_params(shares: &[ShamirShare]) -> Result<ShamirParams, EnclaveError> {
        let Some(first) = shares.first() else {
            return Err(EnclaveError::NotEnoughShares {
                threshold: 1,
                provided: 0,
            });
        };
        let params = first.params;
        if shares.len() < params.threshold as usize {
            return Err(EnclaveError::NotEnoughShares {
                threshold: params.threshold,
                provided: shares.len(),
            });
        }
        if shares.iter().any(|s| s.params != params) {
            return Err(EnclaveError::InconsistentShares("parameters mismatch"));
        }
        let mut indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
        indices.sort_unstable();
        indices.dedup();
        if indices.len() != shares.len() {
            return Err(EnclaveError::InconsistentShares("duplicate share indices"));
        }
        Ok(params)
    }

    fn derive_signing_key(
        scheme: SigningScheme,
        seed: &SecretBytes,
        hd_path: Option<&HdPath>,
    ) -> Result<SecretBytes, EnclaveError> {
        match scheme {
            SigningScheme::Ed25519
            | SigningScheme::Secp256k1
            | SigningScheme::Secp256k1Recoverable => match hd_path {
                None => {
                    // No derivation: the seed itself is the signing key. For
                    // ed25519 / secp256k1 we expect a 32-byte seed.
                    if seed.len() < 32 {
                        return Err(EnclaveError::InvalidRequest(
                            "seed too short for classical scheme",
                        ));
                    }
                    Ok(SecretBytes::from_slice(&seed.expose()[..32]))
                }
                Some(path) => {
                    let d = derive_classical(scheme, seed, path)?;
                    Ok(d.secret)
                }
            },
            // PQ schemes (M5): non-HD per RFC §9.1 / D40. The 32-byte FIPS
            // 204 seed (`xi`) IS the signing key. Reject any HD path here —
            // the orchestrator should never thread one through for a PQ
            // wallet; this is defence-in-depth.
            SigningScheme::MlDsa44 | SigningScheme::MlDsa65 | SigningScheme::MlDsa87 => {
                if hd_path.is_some() {
                    return Err(EnclaveError::Derivation(
                        crate::error::DerivationError::SchemeNotHd("ml_dsa"),
                    ));
                }
                if seed.len() < crate::signers::ML_DSA_SEED_BYTES {
                    return Err(EnclaveError::InvalidRequest(
                        "seed too short for ML-DSA (need 32 bytes)",
                    ));
                }
                Ok(SecretBytes::from_slice(
                    &seed.expose()[..crate::signers::ML_DSA_SEED_BYTES],
                ))
            }
        }
    }

    /// Pure helper that decides whether the env-var gate has been opened.
    /// Exposed so tests can verify the gate without process-global env
    /// mutation (which is `unsafe` post-edition-2024 and conflicts with
    /// `#![forbid(unsafe_code)]`).
    fn env_gate_open(env_value: Option<&str>) -> bool {
        env_value == Some(MOCK_ENABLE_VALUE)
    }
}

fn current_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

#[async_trait]
impl Enclave for MockEnclave {
    async fn attest(&self, nonce: [u8; 32]) -> Result<AttestationDoc, EnclaveError> {
        Ok(self.attestation_key.sign_attestation(nonce, Vec::new())?)
    }

    async fn sign_in_enclave(
        &self,
        req: EnclaveSignRequest,
    ) -> Result<EnclaveSignResponse, EnclaveError> {
        // 0. Hybrid policy verification (M3 §3.4). When the mock is
        //    configured with a pinned policy-service public key, run the
        //    verifier *before* any SSS combine or curve sign so a bad
        //    decision can't leak key material into the signature path.
        if let Some(pubkey) = &self.policy_service_pubkey {
            let verifier = HybridVerifier::new(pubkey.clone())
                .with_require_signed_decision(self.require_signed_decision);
            // Build the SigningRequest projection the verifier expects.
            // The verifier inspects `payload.chain_id()` + decoded EVM
            // value, so we need the structured payload. The orchestrator
            // passes it in `policy_signing_payload`; fall back to
            // `SigningPayload::Raw { bytes: req.message.clone() }` when
            // it's not present so the verifier can at least apply the
            // signed-decision binding + freshness checks.
            let payload =
                req.policy_signing_payload
                    .clone()
                    .unwrap_or_else(|| PolicySigningPayload::Raw {
                        bytes: req.message.clone(),
                    });
            let verifier_request = PolicySigningRequest {
                request_id: req.request_id,
                wallet_id: req.wallet_id,
                requester: qfc_policy::Requester::ApiKey {
                    key_id: "mock-enclave".into(),
                },
                payload,
                hd_path: req.hd_path.clone(),
                received_at_unix_ms: current_unix_ms(),
            };
            let ceilings = req
                .wallet_ceilings
                .clone()
                .unwrap_or_else(|| WalletCeilings {
                    wallet_id: req.wallet_id,
                    ..Default::default()
                });
            verifier.verify(
                req.policy_decision.as_ref(),
                &req.approvals,
                &verifier_request,
                &ceilings,
                current_unix_ms(),
            )?;
        }

        // 1. Validate share set.
        let _params = Self::check_share_params(&req.shares)?;
        // Cross-check that every share belongs to req.wallet_id is not
        // possible here because ShamirShare itself doesn't carry the
        // wallet_id (that's on the StoredShare envelope in the store
        // layer). The orchestrator is responsible for that cross-check.

        // 2. Combine shares into the master seed. Zeroize seed material
        //    via SecretBytes / Zeroizing on drop.
        let combined = combine_shares(&req.shares)?;
        let seed = SecretBytes::from_slice(&combined);
        drop(combined); // explicit; the Vec<u8> itself was a momentary copy

        // 3. Derive the signing key per scheme.
        let signing_key = Self::derive_signing_key(req.scheme, &seed, req.hd_path.as_ref())?;

        // 4. Sign + derive pubkey.
        let signer = signer_for_scheme(req.scheme)?;
        let pubkey = signer.public_key(&signing_key)?;
        let signature = signer.sign(&signing_key, &req.message, req.hash_alg)?;

        // 5. Build attestation user_data: (request_id || message_hash ||
        //    signature_hash || hd_path_str || context_json) — see RFC §4.2 step 16.
        let mut user_data = Vec::new();
        user_data.extend_from_slice(req.request_id.to_string().as_bytes());
        user_data.push(b'|');
        user_data.extend_from_slice(req.wallet_id.to_string().as_bytes());
        user_data.push(b'|');
        user_data.extend_from_slice(&sha256_32(&req.message));
        user_data.push(b'|');
        user_data.extend_from_slice(&sha256_32(&signature));
        user_data.push(b'|');
        if let Some(p) = &req.hd_path {
            user_data.extend_from_slice(p.to_string().as_bytes());
        }
        user_data.push(b'|');
        let ctx_bytes = serde_json::to_vec(&req.context).map_err(|e| {
            EnclaveError::Attestation(crate::attestation::AttestationError::PayloadParse(
                e.to_string(),
            ))
        })?;
        user_data.extend_from_slice(&ctx_bytes);

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let attestation = self.attestation_key.sign_attestation(nonce, user_data)?;

        Ok(EnclaveSignResponse {
            signature,
            public_key: pubkey,
            attestation,
        })
    }

    async fn generate_wallet(
        &self,
        req: GenerateWalletRequest,
    ) -> Result<GenerateWalletResponse, EnclaveError> {
        if req.threshold < 2 || req.threshold > req.total {
            return Err(EnclaveError::InvalidRequest(
                "invalid (threshold, total) — need 2 <= threshold <= total",
            ));
        }
        // PQ schemes are non-HD per RFC §9.1 / D40. Reject any
        // `master_hd_path` for PQ wallets up front so the orchestrator
        // can't accidentally request a derived public key.
        if req.scheme.is_post_quantum() && req.master_hd_path.is_some() {
            return Err(EnclaveError::Derivation(
                crate::error::DerivationError::SchemeNotHd("ml_dsa"),
            ));
        }

        // 1. Generate seed material. Classical schemes get the 64-byte
        //    BIP39-style seed so HD derivation works downstream; PQ schemes
        //    get exactly 32 bytes (the FIPS 204 `xi`). Splitting the seed
        //    sizes here keeps the SSS chunking honest — a PQ wallet's seed
        //    is the same shape as an ed25519 wallet's seed at the wire
        //    layer, but the BIP39-style 64-byte buffer would be twice as
        //    large for no benefit.
        let seed_len = if req.scheme.is_post_quantum() {
            crate::signers::ML_DSA_SEED_BYTES
        } else {
            64
        };
        let mut seed_bytes = vec![0u8; seed_len];
        OsRng.fill_bytes(&mut seed_bytes);
        let seed = SecretBytes::from_slice(&seed_bytes);
        // Wipe stack/heap copy.
        seed_bytes.iter_mut().for_each(|b| *b = 0);

        // 2. Derive the *reported* public key at master_hd_path.
        let signing_key = Self::derive_signing_key(req.scheme, &seed, req.master_hd_path.as_ref())?;
        let signer = signer_for_scheme(req.scheme)?;
        let pubkey = signer.public_key(&signing_key)?;
        drop(signing_key); // zeroize via Drop

        // 3. Split the seed via SSS.
        let shares = split_secret(
            seed.expose(),
            ShamirParams {
                threshold: req.threshold,
                total: req.total,
            },
        )?;
        // `seed` zeroizes on drop here.

        // 4. Build the attestation binding (wallet_id || master_pubkey || share_indices).
        let mut user_data = Vec::new();
        user_data.extend_from_slice(req.wallet_id.to_string().as_bytes());
        user_data.push(b'|');
        user_data.extend_from_slice(&sha256_32(&pubkey));
        user_data.push(b'|');
        for s in &shares {
            user_data.push(s.index);
        }
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let attestation = self.attestation_key.sign_attestation(nonce, user_data)?;

        Ok(GenerateWalletResponse {
            shares,
            master_public_key: pubkey,
            attestation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enclave::SigningContext;
    use crate::signer::Signer;
    use crate::Ed25519Signer;
    use qfc_wallet_types::{HashAlg, RequestId, SigningScheme, WalletId};

    fn enc() -> MockEnclave {
        MockEnclave::new_for_testing_with_seed([1u8; 32])
    }

    #[test]
    fn env_gate_closed_for_default_env() {
        assert!(!MockEnclave::env_gate_open(None));
        assert!(!MockEnclave::env_gate_open(Some("")));
        assert!(!MockEnclave::env_gate_open(Some("1")));
        assert!(!MockEnclave::env_gate_open(Some("yes")));
        assert!(!MockEnclave::env_gate_open(Some("YES-I-KNOW")));
    }

    #[test]
    fn env_gate_open_only_for_exact_sentinel() {
        assert!(MockEnclave::env_gate_open(Some("yes-i-know")));
    }

    #[tokio::test]
    async fn attest_returns_verifiable_doc() {
        let e = enc();
        let nonce = [0xABu8; 32];
        let doc = e.attest(nonce).await.unwrap();
        assert_eq!(doc.payload.nonce, nonce);
        doc.verify().expect("mock attestation verifies");
    }

    #[tokio::test]
    async fn generate_then_sign_then_verify_ed25519() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        gen.attestation.verify().unwrap();
        assert_eq!(gen.shares.len(), 3);
        assert_eq!(gen.master_public_key.len(), 32);

        // Sign with 2-of-3 shares.
        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::Ed25519,
                hd_path: None,
                message: b"hello qfc".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        resp.attestation.verify().unwrap();
        // Returned public_key must match the wallet's master public key for
        // a non-HD signature path.
        assert_eq!(resp.public_key, gen.master_public_key);
        // External verification of the signature itself.
        Ed25519Signer
            .verify(
                &resp.public_key,
                b"hello qfc",
                &resp.signature,
                HashAlg::None,
            )
            .expect("ed25519 sig valid");
    }

    #[tokio::test]
    async fn generate_then_sign_secp256k1_with_hd_path() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::Secp256k1,
                threshold: 3,
                total: 5,
                master_hd_path: Some("m/44'/60'/0'/0/0".parse().unwrap()),
            })
            .await
            .unwrap();
        gen.attestation.verify().unwrap();
        assert_eq!(gen.shares.len(), 5);
        assert_eq!(gen.master_public_key.len(), 33); // SEC1 compressed
        assert!(matches!(gen.master_public_key[0], 0x02 | 0x03));

        // Sign with the same HD path — pubkey must match the master_public_key.
        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..3].to_vec(),
                scheme: SigningScheme::Secp256k1,
                hd_path: Some("m/44'/60'/0'/0/0".parse().unwrap()),
                message: b"sign me".to_vec(),
                hash_alg: HashAlg::Keccak256,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        resp.attestation.verify().unwrap();
        assert_eq!(resp.public_key, gen.master_public_key);
        crate::Secp256k1Signer
            .verify(
                &resp.public_key,
                b"sign me",
                &resp.signature,
                HashAlg::Keccak256,
            )
            .expect("secp256k1 sig valid");
    }

    #[tokio::test]
    async fn sign_rejects_too_few_shares() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::Ed25519,
                threshold: 3,
                total: 5,
                master_hd_path: None,
            })
            .await
            .unwrap();
        // Send only 2 shares to a 3-of-5 wallet.
        let err = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::Ed25519,
                hd_path: None,
                message: b"x".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await;
        assert!(matches!(
            err,
            Err(EnclaveError::NotEnoughShares {
                threshold: 3,
                provided: 2,
            })
        ));
    }

    #[tokio::test]
    async fn sign_rejects_duplicate_shares() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        let dup = vec![gen.shares[0].clone(), gen.shares[0].clone()];
        let err = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: dup,
                scheme: SigningScheme::Ed25519,
                hd_path: None,
                message: b"x".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::InconsistentShares(_))));
    }

    #[tokio::test]
    async fn generate_pq_with_hd_path_rejected() {
        // M5: PQ wallets are non-HD (§9.1). A request with master_hd_path
        // set on a PQ scheme is rejected up-front.
        let e = enc();
        let err = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id: WalletId::new(),
                scheme: SigningScheme::MlDsa44,
                threshold: 2,
                total: 3,
                master_hd_path: Some("m/0'".parse().unwrap()),
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::Derivation(_))));
    }

    #[tokio::test]
    async fn sign_pq_with_hd_path_rejected() {
        // Same invariant on the sign path — `hd_path: Some(...)` for a PQ
        // wallet must surface SchemeNotHd.
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::MlDsa65,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        let err = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::MlDsa65,
                hd_path: Some("m/0'".parse().unwrap()),
                message: b"x".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::Derivation(_))));
    }

    #[tokio::test]
    async fn generate_then_sign_ml_dsa_44() {
        // M5 end-to-end: ML-DSA-44 wallet, generate → sign → verify.
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::MlDsa44,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        gen.attestation.verify().unwrap();
        assert_eq!(gen.shares.len(), 3);
        // ML-DSA-44 public key is 1312 bytes.
        assert_eq!(gen.master_public_key.len(), 1312);

        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::MlDsa44,
                hd_path: None,
                message: b"pq message".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        resp.attestation.verify().unwrap();
        assert_eq!(resp.public_key, gen.master_public_key);
        // ML-DSA-44 signature is 2420 bytes.
        assert_eq!(resp.signature.len(), 2420);
        // External verification.
        crate::MlDsa44Signer
            .verify(
                &resp.public_key,
                b"pq message",
                &resp.signature,
                HashAlg::None,
            )
            .expect("ML-DSA-44 sig valid");
    }

    #[tokio::test]
    async fn generate_then_sign_ml_dsa_65() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::MlDsa65,
                threshold: 3,
                total: 5,
                master_hd_path: None,
            })
            .await
            .unwrap();
        assert_eq!(gen.master_public_key.len(), 1952);
        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..3].to_vec(),
                scheme: SigningScheme::MlDsa65,
                hd_path: None,
                message: b"sign me ml-dsa-65".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.signature.len(), 3309);
        crate::MlDsa65Signer
            .verify(
                &resp.public_key,
                b"sign me ml-dsa-65",
                &resp.signature,
                HashAlg::None,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn generate_then_sign_ml_dsa_87() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::MlDsa87,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        assert_eq!(gen.master_public_key.len(), 2592);
        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id: RequestId::new(),
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::MlDsa87,
                hd_path: None,
                message: b"ml-dsa-87 payload".to_vec(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        assert_eq!(resp.signature.len(), 4627);
        crate::MlDsa87Signer
            .verify(
                &resp.public_key,
                b"ml-dsa-87 payload",
                &resp.signature,
                HashAlg::None,
            )
            .unwrap();
    }

    #[tokio::test]
    async fn generate_rejects_invalid_params() {
        let e = enc();
        let err = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id: WalletId::new(),
                scheme: SigningScheme::Ed25519,
                threshold: 5,
                total: 3,
                master_hd_path: None,
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn attestation_user_data_binds_request_id_and_message_hash() {
        let e = enc();
        let wallet_id = WalletId::new();
        let gen = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: SigningScheme::Ed25519,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await
            .unwrap();
        let request_id = RequestId::new();
        let msg = b"binding-check".to_vec();
        let resp = e
            .sign_in_enclave(EnclaveSignRequest {
                request_id,
                wallet_id,
                shares: gen.shares[..2].to_vec(),
                scheme: SigningScheme::Ed25519,
                hd_path: None,
                message: msg.clone(),
                hash_alg: HashAlg::None,
                context: SigningContext::default(),
                policy_decision: None,
                approvals: Vec::new(),
                wallet_ceilings: None,
                policy_signing_payload: None,
            })
            .await
            .unwrap();
        let ud = &resp.attestation.payload.user_data;
        // request_id appears in user_data.
        let rid_str = request_id.to_string();
        assert!(
            ud.windows(rid_str.len()).any(|w| w == rid_str.as_bytes()),
            "request_id should be embedded in attestation user_data"
        );
        // message hash appears.
        let msg_hash = sha256_32(&msg);
        assert!(
            ud.windows(32).any(|w| w == msg_hash),
            "message hash should be embedded in attestation user_data"
        );
        // signature hash appears.
        let sig_hash = sha256_32(&resp.signature);
        assert!(
            ud.windows(32).any(|w| w == sig_hash),
            "signature hash should be embedded in attestation user_data"
        );
    }

    #[tokio::test]
    async fn deterministic_seed_yields_stable_attestation_pubkey() {
        let e1 = MockEnclave::new_for_testing_with_seed([9u8; 32]);
        let e2 = MockEnclave::new_for_testing_with_seed([9u8; 32]);
        assert_eq!(e1.attestation_public_key(), e2.attestation_public_key());
    }
}
