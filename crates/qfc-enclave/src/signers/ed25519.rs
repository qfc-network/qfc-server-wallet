//! Ed25519 (RFC 8032) signer.
//!
//! Pure-Rust impl via `ed25519-dalek`. No FFI. Signing is deterministic by
//! construction (Ed25519 derives the nonce from the secret + message).

use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier, VerifyingKey};
use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};

use crate::error::SignerError;
use crate::signer::Signer;

/// Signer for the `Ed25519` scheme.
///
/// Ed25519 has no notion of "pre-hashing" in the RFC 8032 sense (or rather,
/// its internal pre-hashing is part of the construction). Callers must pass
/// `HashAlg::None`; any other value is rejected. Use Ed25519ph if you need a
/// distinct pre-hashing mode — that is a separate scheme we don't yet support.
pub struct Ed25519Signer;

impl Ed25519Signer {
    fn signing_key(secret: &SecretBytes) -> Result<SigningKey, SignerError> {
        let bytes: [u8; 32] =
            secret
                .expose()
                .try_into()
                .map_err(|_| SignerError::InvalidSecret {
                    scheme: "ed25519",
                    reason: "secret must be exactly 32 bytes",
                })?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    fn require_no_hash(hash: HashAlg) -> Result<(), SignerError> {
        match hash {
            HashAlg::None => Ok(()),
            _ => Err(SignerError::UnsupportedHash {
                scheme: "ed25519",
                hash: match hash {
                    HashAlg::Sha256 => "sha256",
                    HashAlg::Keccak256 => "keccak256",
                    HashAlg::Blake3 => "blake3",
                    HashAlg::None => unreachable!(),
                },
            }),
        }
    }
}

impl Signer for Ed25519Signer {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::Ed25519
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        let sk = Self::signing_key(secret)?;
        Ok(sk.verifying_key().to_bytes().to_vec())
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        Self::require_no_hash(hash_alg)?;
        let sk = Self::signing_key(secret)?;
        let sig = sk.sign(message);
        Ok(sig.to_bytes().to_vec())
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        Self::require_no_hash(hash_alg)?;
        let pk_bytes: [u8; 32] =
            public_key
                .try_into()
                .map_err(|_| SignerError::InvalidPublicKey {
                    scheme: "ed25519",
                    reason: "expected 32-byte compressed public key",
                })?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
            SignerError::InvalidPublicKey {
                scheme: "ed25519",
                // ed25519-dalek returns SignatureError; preserve via Crypto for tests
                // that only need an unambiguous "not a valid key" outcome would expect
                // VerificationFailed, but we surface InvalidPublicKey because the bytes
                // are structurally bad, not a verification-time miss.
                reason: Box::leak(e.to_string().into_boxed_str()),
            }
        })?;
        let sig_bytes: [u8; 64] =
            signature
                .try_into()
                .map_err(|_| SignerError::InvalidPublicKey {
                    scheme: "ed25519",
                    reason: "signature must be 64 bytes",
                })?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(message, &sig)
            .map_err(|_| SignerError::VerificationFailed)
    }
}
