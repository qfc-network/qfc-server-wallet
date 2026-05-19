//! The `Signer` trait — curve-agnostic signing interface.
//!
//! See `docs/server-wallet-rfc.md` §2.3. Every concrete signer implementation
//! is curve-agnostic from the caller's perspective: callers pass raw secret
//! bytes plus an explicit `HashAlg`, and the impl decides whether and how to
//! pre-hash the message.
//!
//! Secret format per scheme:
//! - `Ed25519` — 32 bytes of seed material.
//! - `Secp256k1` / `Secp256k1Recoverable` — 32 bytes of scalar (1..=N-1).
//!
//! Public-key encoding returned by `public_key()`:
//! - `Ed25519` — 32 bytes (compressed Edwards Y + sign bit).
//! - `Secp256k1` / `Secp256k1Recoverable` — 33 bytes (SEC1 compressed).
//!
//! Signature encoding returned by `sign()`:
//! - `Ed25519` — 64 bytes (R || S).
//! - `Secp256k1` — 64 bytes (r || s) — fixed-width, no DER.
//! - `Secp256k1Recoverable` — 65 bytes (r || s || v), where `v` is the
//!   recovery byte normalized to {0, 1}.

use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};

use crate::error::SignerError;
use crate::signers::{Ed25519Signer, Secp256k1RecoverableSigner, Secp256k1Signer};

/// Curve-agnostic signing interface. Inside the enclave this trait is the
/// only surface exposed to higher layers — callers do not need to know the
/// concrete curve.
pub trait Signer: Send + Sync {
    /// The scheme this signer implements.
    fn scheme(&self) -> SigningScheme;

    /// Derive the public key from raw secret bytes.
    ///
    /// # Errors
    ///
    /// Returns `SignerError::InvalidSecret` if `secret` is not the expected
    /// length / shape for this scheme, or `SignerError::Crypto` if the
    /// underlying library reports failure.
    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError>;

    /// Produce a signature over `message`. The implementation applies
    /// `hash_alg` to the message if the scheme requires (or supports) it.
    ///
    /// # Errors
    ///
    /// - `SignerError::InvalidSecret` if `secret` is malformed.
    /// - `SignerError::UnsupportedHash` if the scheme rejects `hash_alg`.
    /// - `SignerError::Crypto` for underlying-library failures.
    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError>;

    /// Verify a signature. Returns `Ok(())` if valid.
    ///
    /// # Errors
    ///
    /// - `SignerError::VerificationFailed` for an unambiguous "bad signature".
    /// - `SignerError::InvalidPublicKey` if the public key or signature is
    ///   structurally invalid (wrong length, malformed encoding).
    /// - `SignerError::UnsupportedHash` if the scheme rejects `hash_alg`.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError>;
}

/// Return a heap-allocated signer implementing `scheme`. Returns
/// `SignerError::NotImplemented` for PQ schemes (M5).
///
/// # Errors
///
/// Returns `SignerError::NotImplemented` when called for a PQ scheme that
/// has not yet been implemented (RFC §7 M5).
pub fn signer_for_scheme(scheme: SigningScheme) -> Result<Box<dyn Signer>, SignerError> {
    match scheme {
        SigningScheme::Ed25519 => Ok(Box::new(Ed25519Signer)),
        SigningScheme::Secp256k1 => Ok(Box::new(Secp256k1Signer)),
        SigningScheme::Secp256k1Recoverable => Ok(Box::new(Secp256k1RecoverableSigner)),
        SigningScheme::MlDsa44 => Err(SignerError::NotImplemented("ml_dsa_44")),
        SigningScheme::MlDsa65 => Err(SignerError::NotImplemented("ml_dsa_65")),
        SigningScheme::MlDsa87 => Err(SignerError::NotImplemented("ml_dsa_87")),
    }
}

/// Convenience helper: dispatch a sign call by scheme without allocating a
/// trait object. Equivalent to `signer_for_scheme(scheme)?.sign(...)` but
/// avoids the boxing overhead in tight loops.
///
/// # Errors
///
/// Propagates any error from the underlying signer impl.
pub fn dispatch_signer<F, T>(scheme: SigningScheme, f: F) -> Result<T, SignerError>
where
    F: FnOnce(&dyn Signer) -> Result<T, SignerError>,
{
    match scheme {
        SigningScheme::Ed25519 => f(&Ed25519Signer),
        SigningScheme::Secp256k1 => f(&Secp256k1Signer),
        SigningScheme::Secp256k1Recoverable => f(&Secp256k1RecoverableSigner),
        SigningScheme::MlDsa44 => Err(SignerError::NotImplemented("ml_dsa_44")),
        SigningScheme::MlDsa65 => Err(SignerError::NotImplemented("ml_dsa_65")),
        SigningScheme::MlDsa87 => Err(SignerError::NotImplemented("ml_dsa_87")),
    }
}
