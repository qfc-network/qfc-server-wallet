//! secp256k1 signers — both fixed-width (64-byte) and recoverable
//! (65-byte with `v`).
//!
//! Pure-Rust impl via `k256` (`RustCrypto`). No FFI surface (RFC §1.5).

use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{
    signature::hazmat::PrehashSigner, RecoveryId, Signature as EcdsaSignature, SigningKey,
    VerifyingKey,
};
use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::SignerError;
use crate::signer::Signer;

/// Fixed-width (64-byte) secp256k1 ECDSA signer. Signature layout: `r || s`,
/// both big-endian 32-byte scalars, normalized to low-S form.
pub struct Secp256k1Signer;

/// secp256k1 ECDSA signer with EIP-155 / Ethereum-style recovery byte.
/// Signature layout: `r || s || v` (65 bytes). `v` is normalized to {0, 1};
/// callers that need {27, 28} or chain-id-folded values handle that
/// transformation at the encoding boundary (e.g. when assembling an Ethereum tx).
pub struct Secp256k1RecoverableSigner;

fn signing_key_from(secret: &SecretBytes) -> Result<SigningKey, SignerError> {
    let bytes: &[u8] = secret.expose();
    if bytes.len() != 32 {
        return Err(SignerError::InvalidSecret {
            scheme: "secp256k1",
            reason: "secret must be exactly 32 bytes",
        });
    }
    SigningKey::from_slice(bytes).map_err(|e| SignerError::Crypto(e.to_string()))
}

fn prehash(message: &[u8], hash: HashAlg) -> Result<[u8; 32], SignerError> {
    match hash {
        HashAlg::Sha256 => {
            let mut h = Sha256::new();
            h.update(message);
            let out = h.finalize();
            Ok(out.into())
        }
        HashAlg::Keccak256 => {
            let mut h = Keccak256::new();
            h.update(message);
            let out = h.finalize();
            Ok(out.into())
        }
        HashAlg::Blake3 => {
            let h = blake3::hash(message);
            Ok(*h.as_bytes())
        }
        HashAlg::None => Err(SignerError::UnsupportedHash {
            scheme: "secp256k1",
            hash: "none",
        }),
    }
}

fn compressed_public_key(sk: &SigningKey) -> Vec<u8> {
    let vk: VerifyingKey = *sk.verifying_key();
    vk.to_encoded_point(true).as_bytes().to_vec()
}

fn verifying_key_from(public_key: &[u8]) -> Result<VerifyingKey, SignerError> {
    VerifyingKey::from_sec1_bytes(public_key).map_err(|_| SignerError::InvalidPublicKey {
        scheme: "secp256k1",
        reason: "expected 33-byte SEC1 compressed public key",
    })
}

impl Signer for Secp256k1Signer {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::Secp256k1
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        let sk = signing_key_from(secret)?;
        Ok(compressed_public_key(&sk))
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        let sk = signing_key_from(secret)?;
        let digest = prehash(message, hash_alg)?;
        let sig: EcdsaSignature = sk
            .sign_prehash(&digest)
            .map_err(|e| SignerError::Crypto(e.to_string()))?;
        let sig = sig.normalize_s().unwrap_or(sig);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        let vk = verifying_key_from(public_key)?;
        let digest = prehash(message, hash_alg)?;
        if signature.len() != 64 {
            return Err(SignerError::InvalidPublicKey {
                scheme: "secp256k1",
                reason: "signature must be 64 bytes",
            });
        }
        let sig = EcdsaSignature::from_slice(signature)
            .map_err(|e| SignerError::Crypto(e.to_string()))?;
        vk.verify_prehash(&digest, &sig)
            .map_err(|_| SignerError::VerificationFailed)
    }
}

impl Signer for Secp256k1RecoverableSigner {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::Secp256k1Recoverable
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        let sk = signing_key_from(secret)?;
        Ok(compressed_public_key(&sk))
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        let sk = signing_key_from(secret)?;
        let digest = prehash(message, hash_alg)?;
        let (sig, rec_id): (EcdsaSignature, RecoveryId) = sk
            .sign_prehash_recoverable(&digest)
            .map_err(|e| SignerError::Crypto(e.to_string()))?;
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.to_bytes());
        out.push(rec_id.to_byte());
        Ok(out)
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        if signature.len() != 65 {
            return Err(SignerError::InvalidPublicKey {
                scheme: "secp256k1_recoverable",
                reason: "signature must be 65 bytes (r || s || v)",
            });
        }
        let digest = prehash(message, hash_alg)?;

        // Try direct verification against the provided public key first.
        let vk = verifying_key_from(public_key)?;
        let sig = EcdsaSignature::from_slice(&signature[..64])
            .map_err(|e| SignerError::Crypto(e.to_string()))?;
        if vk.verify_prehash(&digest, &sig).is_ok() {
            // Additionally verify that the recovery byte recovers to the same
            // public key — protects against well-formed `(r, s)` paired with a
            // bogus `v`.
            let rec_id =
                RecoveryId::from_byte(signature[64]).ok_or(SignerError::InvalidPublicKey {
                    scheme: "secp256k1_recoverable",
                    reason: "invalid recovery byte",
                })?;
            let recovered = VerifyingKey::recover_from_prehash(&digest, &sig, rec_id)
                .map_err(|_| SignerError::VerificationFailed)?;
            if recovered.to_encoded_point(true).as_bytes() == public_key {
                return Ok(());
            }
            return Err(SignerError::VerificationFailed);
        }
        Err(SignerError::VerificationFailed)
    }
}
