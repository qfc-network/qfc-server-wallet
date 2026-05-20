//! `MockEnclave` — in-process implementation of the `Enclave` trait.
//!
//! Same production crypto (k256 / ed25519-dalek / vsss-rs), just no memory
//! isolation, no real attestation, no PCR binding. Fail-closed by default:
//! `MockEnclave::new()` returns `EnclaveError::MockNotAllowed` unless the
//! `QFC_ALLOW_MOCK_ENCLAVE` env var is set to `yes-i-know`. Tests that
//! actually want a `MockEnclave` use `MockEnclave::new_for_testing()`,
//! which bypasses the env var and is gated behind a clearly-named API.

use async_trait::async_trait;
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
use crate::signer::signer_for_scheme;

/// Sentinel value the operator must set to opt into mock enclave usage.
pub const MOCK_ENABLE_ENV: &str = "QFC_ALLOW_MOCK_ENCLAVE";
const MOCK_ENABLE_VALUE: &str = "yes-i-know";

/// In-process enclave. Holds its own attestation key.
pub struct MockEnclave {
    attestation_key: MockAttestationKey,
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
        }
    }

    /// Deterministic test constructor — seeds the attestation key from
    /// `seed` so tests can pin attestation public keys.
    #[must_use]
    pub fn new_for_testing_with_seed(seed: [u8; 32]) -> Self {
        Self {
            attestation_key: MockAttestationKey::from_seed(seed),
        }
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
            SigningScheme::MlDsa44 => Err(EnclaveError::SchemeNotImplemented("ml_dsa_44")),
            SigningScheme::MlDsa65 => Err(EnclaveError::SchemeNotImplemented("ml_dsa_65")),
            SigningScheme::MlDsa87 => Err(EnclaveError::SchemeNotImplemented("ml_dsa_87")),
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

#[async_trait]
impl Enclave for MockEnclave {
    async fn attest(&self, nonce: [u8; 32]) -> Result<AttestationDoc, EnclaveError> {
        Ok(self.attestation_key.sign_attestation(nonce, Vec::new())?)
    }

    async fn sign_in_enclave(
        &self,
        req: EnclaveSignRequest,
    ) -> Result<EnclaveSignResponse, EnclaveError> {
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
        if req.scheme.is_post_quantum() {
            return Err(EnclaveError::SchemeNotImplemented(match req.scheme {
                SigningScheme::MlDsa44 => "ml_dsa_44",
                SigningScheme::MlDsa65 => "ml_dsa_65",
                SigningScheme::MlDsa87 => "ml_dsa_87",
                _ => "post_quantum",
            }));
        }

        // 1. Generate a 64-byte BIP39-style seed (so it's compatible with HD
        //    derivation downstream). We don't materialize a mnemonic here —
        //    operators that want one go through `mnemonic_to_seed` instead.
        let mut seed_bytes = [0u8; 64];
        OsRng.fill_bytes(&mut seed_bytes);
        let seed = SecretBytes::from_slice(&seed_bytes);
        // Wipe stack copy.
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
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::InconsistentShares(_))));
    }

    #[tokio::test]
    async fn generate_rejects_pq_schemes() {
        let e = enc();
        let err = e
            .generate_wallet(GenerateWalletRequest {
                wallet_id: WalletId::new(),
                scheme: SigningScheme::MlDsa44,
                threshold: 2,
                total: 3,
                master_hd_path: None,
            })
            .await;
        assert!(matches!(err, Err(EnclaveError::SchemeNotImplemented(_))));
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
