//! Load an approver-side signing key from disk.
//!
//! This is the reference impl — it loads raw 32-byte secret material
//! from a file. Production deployments will swap this for a hardware
//! integration (`YubiKey`, Ledger, KMS), but the rest of the client
//! contract is just `ApproverSigner::sign(&self, preimage) -> Vec<u8>`
//! so a hardware-backed signer can be dropped in without touching the
//! webhook handler.
//!
//! File format: exactly 32 bytes (no header, no PEM, no hex). For
//! ed25519 those 32 bytes are the seed; for secp256k1 they are the
//! 32-byte scalar. Both forms match what `qfc_enclave::Signer` already
//! accepts via `SecretBytes`.

use std::path::Path;

use qfc_enclave::dispatch_signer;
use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};

/// Errors loading or using the approver's signing key.
#[derive(Debug, thiserror::Error)]
pub enum SignerLoadError {
    /// Filesystem error reading the secret file.
    #[error("read secret file {path}: {source}")]
    Io {
        /// Path that failed to read.
        path: String,
        /// Underlying IO error.
        #[source]
        source: std::io::Error,
    },
    /// Wrong file length. The reference impl only accepts 32-byte raw
    /// secrets, which covers ed25519 and secp256k1. PQ schemes also use
    /// a 32-byte seed but the reference impl exposes only the two
    /// classical curves on the CLI.
    #[error("secret file {path} is {got} bytes, expected exactly 32")]
    Length {
        /// Path that was loaded.
        path: String,
        /// Actual length observed.
        got: usize,
    },
    /// The signer rejected the secret at signing time.
    #[error("signer failed: {0}")]
    Signer(#[from] qfc_enclave::SignerError),
}

/// Load 32 bytes of raw secret material from `path`.
///
/// # Errors
///
/// `SignerLoadError::Io` on filesystem failure, `SignerLoadError::Length`
/// if the file is not exactly 32 bytes.
pub fn load_secret(path: &Path) -> Result<SecretBytes, SignerLoadError> {
    let bytes = std::fs::read(path).map_err(|source| SignerLoadError::Io {
        path: path.display().to_string(),
        source,
    })?;
    if bytes.len() != 32 {
        return Err(SignerLoadError::Length {
            path: path.display().to_string(),
            got: bytes.len(),
        });
    }
    Ok(SecretBytes::new(bytes))
}

/// A loaded approver signing key + the scheme it signs with.
///
/// Cloning is intentional: `SecretBytes` zeroizes on drop and the
/// underlying buffer is reference-counted via `Zeroizing<Vec<u8>>`. We
/// keep the secret behind an `Arc` so the same loaded key can be shared
/// across the axum router and the prompt thread without per-handler
/// copies.
#[derive(Clone)]
pub struct ApproverSigner {
    secret: std::sync::Arc<SecretBytes>,
    scheme: SigningScheme,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for ApproverSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApproverSigner")
            .field("scheme", &self.scheme)
            .field("public_key_len", &self.public_key.len())
            .finish_non_exhaustive()
    }
}

impl ApproverSigner {
    /// Build from already-loaded secret + scheme. Derives + caches the
    /// public key.
    ///
    /// # Errors
    ///
    /// `SignerLoadError::Signer` if `secret` is malformed for `scheme`.
    pub fn new(secret: SecretBytes, scheme: SigningScheme) -> Result<Self, SignerLoadError> {
        let public_key = dispatch_signer(scheme, |s| s.public_key(&secret))?;
        Ok(Self {
            secret: std::sync::Arc::new(secret),
            scheme,
            public_key,
        })
    }

    /// Borrow the cached compressed public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// The scheme this signer signs with.
    #[must_use]
    pub fn scheme(&self) -> SigningScheme {
        self.scheme
    }

    /// Sign `preimage` and return the raw signature bytes (hex-encoded
    /// at the wire layer).
    ///
    /// The hash alg follows the same rule the enclave applies: `None`
    /// for ed25519 / ML-DSA, `Sha256` for secp256k1. This matches
    /// `qfc_quorum::approval::hash_alg_for(scheme)`.
    ///
    /// # Errors
    ///
    /// `SignerLoadError::Signer` for any underlying signer failure.
    pub fn sign(&self, preimage: &[u8]) -> Result<Vec<u8>, SignerLoadError> {
        let hash_alg = match self.scheme {
            SigningScheme::Ed25519
            | SigningScheme::MlDsa44
            | SigningScheme::MlDsa65
            | SigningScheme::MlDsa87 => HashAlg::None,
            SigningScheme::Secp256k1 | SigningScheme::Secp256k1Recoverable => HashAlg::Sha256,
        };
        let sig = dispatch_signer(self.scheme, |s| s.sign(&self.secret, preimage, hash_alg))?;
        Ok(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn rejects_wrong_length() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0u8; 16]).unwrap();
        let err = load_secret(f.path()).unwrap_err();
        assert!(matches!(err, SignerLoadError::Length { got: 16, .. }));
    }

    #[test]
    fn loads_32_bytes() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[7u8; 32]).unwrap();
        let s = load_secret(f.path()).unwrap();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn round_trips_ed25519_signature() {
        let secret = SecretBytes::from_slice(&[42u8; 32]);
        let signer = ApproverSigner::new(secret, SigningScheme::Ed25519).unwrap();
        let preimage = b"some-preimage";
        let sig = signer.sign(preimage).unwrap();
        // ed25519 produces 64-byte sigs.
        assert_eq!(sig.len(), 64);
        // Verifies under the dispatched signer.
        qfc_enclave::dispatch_signer(SigningScheme::Ed25519, |s| {
            s.verify(signer.public_key(), preimage, &sig, HashAlg::None)
        })
        .unwrap();
    }
}
