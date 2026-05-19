//! Signing schemes and hash algorithms.
//!
//! See `docs/server-wallet-rfc.md` §2.3.

use serde::{Deserialize, Serialize};

/// Supported signing schemes.
///
/// The PQ variants (`MlDsa*`) are *declared* in M1 but only *implemented*
/// in M5 (RFC §7). Treating them as a known enum from M1 keeps wire-level
/// serialization stable.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningScheme {
    /// Ed25519 (RFC 8032). Supports HD via SLIP-0010.
    Ed25519,
    /// secp256k1 ECDSA (Bitcoin / generic).
    Secp256k1,
    /// secp256k1 ECDSA with a recovery byte (EIP-155 / Ethereum-style `v`).
    Secp256k1Recoverable,
    /// ML-DSA-44 (FIPS 204, formerly Dilithium2). Non-HD. M5.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204, formerly Dilithium3). Non-HD. M5.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204, formerly Dilithium5). Non-HD. M5.
    MlDsa87,
}

impl SigningScheme {
    /// Whether this scheme supports BIP32-style HD derivation.
    ///
    /// PQ schemes do not have an interoperable HD construction (RFC §9.1).
    #[must_use]
    pub const fn is_hd_capable(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::Secp256k1 | Self::Secp256k1Recoverable
        )
    }

    /// Whether this scheme is a classical (pre-PQ) signature scheme.
    #[must_use]
    pub const fn is_classical(self) -> bool {
        matches!(
            self,
            Self::Ed25519 | Self::Secp256k1 | Self::Secp256k1Recoverable
        )
    }

    /// Whether this scheme is a post-quantum signature scheme.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        !self.is_classical()
    }
}

/// Hash pre-image transformation applied before signing.
///
/// `None` means the scheme signs the raw message (e.g. ed25519). Concrete
/// schemes like secp256k1 commonly hash with keccak256 (Ethereum) or sha256
/// (Bitcoin); the choice is made per call so a single `Signer` can serve
/// multiple downstream conventions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HashAlg {
    /// No pre-hashing (scheme signs the message directly).
    None,
    /// SHA-256.
    Sha256,
    /// Keccak-256 (Ethereum).
    Keccak256,
    /// BLAKE3.
    Blake3,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hd_capable_matches_classical() {
        for s in [
            SigningScheme::Ed25519,
            SigningScheme::Secp256k1,
            SigningScheme::Secp256k1Recoverable,
        ] {
            assert!(s.is_hd_capable());
            assert!(s.is_classical());
            assert!(!s.is_post_quantum());
        }
        for s in [
            SigningScheme::MlDsa44,
            SigningScheme::MlDsa65,
            SigningScheme::MlDsa87,
        ] {
            assert!(!s.is_hd_capable());
            assert!(s.is_post_quantum());
            assert!(!s.is_classical());
        }
    }

    #[test]
    fn scheme_serde_uses_snake_case() {
        let j = serde_json::to_string(&SigningScheme::Secp256k1Recoverable).unwrap();
        assert_eq!(j, "\"secp256k1_recoverable\"");
        let parsed: SigningScheme = serde_json::from_str("\"ed25519\"").unwrap();
        assert_eq!(parsed, SigningScheme::Ed25519);
    }

    #[test]
    fn hash_alg_serde_uses_snake_case() {
        let j = serde_json::to_string(&HashAlg::Keccak256).unwrap();
        assert_eq!(j, "\"keccak256\"");
    }
}
