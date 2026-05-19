//! Error types for the enclave / signer layer.

use thiserror::Error;

/// Errors raised by `Signer` implementations.
#[derive(Debug, Error)]
pub enum SignerError {
    /// The secret bytes were not the right length / shape for this scheme.
    #[error("invalid secret material for {scheme}: {reason}")]
    InvalidSecret {
        /// Symbolic name of the scheme (e.g. `"ed25519"`).
        scheme: &'static str,
        /// Human-readable reason.
        reason: &'static str,
    },

    /// Requested an unsupported hash pre-image (e.g. ed25519 + Sha256 mixing).
    #[error("scheme {scheme} does not support hash algorithm {hash}")]
    UnsupportedHash {
        /// Scheme name.
        scheme: &'static str,
        /// Hash name.
        hash: &'static str,
    },

    /// The scheme is declared but not yet implemented (e.g. PQ schemes in M1).
    #[error("scheme {0} is not implemented in this milestone")]
    NotImplemented(&'static str),

    /// Underlying cryptographic library reported a failure.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// The signature did not verify against the public key.
    #[error("signature verification failed")]
    VerificationFailed,

    /// The public key bytes were not the right length / shape.
    #[error("invalid public key for {scheme}: {reason}")]
    InvalidPublicKey {
        /// Scheme name.
        scheme: &'static str,
        /// Reason.
        reason: &'static str,
    },
}

/// Errors raised by HD derivation paths.
#[derive(Debug, Error)]
pub enum DerivationError {
    /// The HD path contains a non-hardened segment but the scheme requires all
    /// hardened segments (e.g. ed25519 / SLIP-0010).
    #[error("scheme {0} requires all path segments to be hardened")]
    NonHardenedRequired(&'static str),

    /// The scheme is not HD-capable (e.g. ML-DSA / PQ).
    #[error("scheme {0} does not support HD derivation")]
    SchemeNotHd(&'static str),

    /// Underlying derivation library reported a failure.
    #[error("derivation error: {0}")]
    Underlying(String),

    /// Mnemonic generation or parsing failed.
    #[error("mnemonic error: {0}")]
    Mnemonic(String),
}
