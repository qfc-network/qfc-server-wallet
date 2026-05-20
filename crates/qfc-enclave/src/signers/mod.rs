//! Concrete `Signer` impls grouped by curve.

mod ed25519;
mod ml_dsa;
mod secp256k1;

pub use ed25519::Ed25519Signer;
pub use ml_dsa::{MlDsa44Signer, MlDsa65Signer, MlDsa87Signer, SEED_BYTES as ML_DSA_SEED_BYTES};
pub use secp256k1::{Secp256k1RecoverableSigner, Secp256k1Signer};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::Signer;
    use proptest::prelude::*;
    use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};

    /// Helper: produce a 32-byte secret with a given seed byte.
    fn secret_with(seed: u8) -> SecretBytes {
        SecretBytes::from_slice(&[seed; 32])
    }

    fn schemes_and_hashes() -> Vec<(Box<dyn Signer>, HashAlg)> {
        vec![
            (Box::new(Ed25519Signer), HashAlg::None),
            (Box::new(Secp256k1Signer), HashAlg::Sha256),
            (Box::new(Secp256k1Signer), HashAlg::Keccak256),
            (Box::new(Secp256k1RecoverableSigner), HashAlg::Keccak256),
        ]
    }

    #[test]
    fn sign_then_verify_round_trip() {
        for (signer, hash) in schemes_and_hashes() {
            let secret = secret_with(7);
            let pk = signer.public_key(&secret).unwrap();
            let msg = b"hello qfc";
            let sig = signer.sign(&secret, msg, hash).unwrap();
            signer
                .verify(&pk, msg, &sig, hash)
                .expect("signature valid");
        }
    }

    #[test]
    fn verify_rejects_modified_message() {
        for (signer, hash) in schemes_and_hashes() {
            let secret = secret_with(3);
            let pk = signer.public_key(&secret).unwrap();
            let sig = signer.sign(&secret, b"original", hash).unwrap();
            let err = signer.verify(&pk, b"modified", &sig, hash);
            assert!(matches!(
                err,
                Err(crate::error::SignerError::VerificationFailed)
            ));
        }
    }

    #[test]
    fn verify_rejects_modified_signature() {
        for (signer, hash) in schemes_and_hashes() {
            let secret = secret_with(11);
            let pk = signer.public_key(&secret).unwrap();
            let mut sig = signer.sign(&secret, b"msg", hash).unwrap();
            sig[0] ^= 0xFF;
            let err = signer.verify(&pk, b"msg", &sig, hash);
            assert!(matches!(
                err,
                Err(crate::error::SignerError::VerificationFailed)
            ));
        }
    }

    #[test]
    fn ed25519_public_key_is_32_bytes() {
        let pk = Ed25519Signer.public_key(&secret_with(1)).unwrap();
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn secp256k1_public_key_is_33_bytes() {
        let pk = Secp256k1Signer.public_key(&secret_with(1)).unwrap();
        assert_eq!(pk.len(), 33);
        assert!(matches!(pk[0], 0x02 | 0x03));
    }

    #[test]
    fn secp256k1_signature_is_64_bytes() {
        let s = Secp256k1Signer
            .sign(&secret_with(1), b"abc", HashAlg::Sha256)
            .unwrap();
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn secp256k1_recoverable_signature_is_65_bytes() {
        let s = Secp256k1RecoverableSigner
            .sign(&secret_with(1), b"abc", HashAlg::Keccak256)
            .unwrap();
        assert_eq!(s.len(), 65);
        assert!(s[64] < 4);
    }

    #[test]
    fn ed25519_is_deterministic() {
        let secret = secret_with(9);
        let s1 = Ed25519Signer.sign(&secret, b"x", HashAlg::None).unwrap();
        let s2 = Ed25519Signer.sign(&secret, b"x", HashAlg::None).unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn secp256k1_is_deterministic_under_rfc6979() {
        // k256's ECDSA signing uses RFC6979 deterministic nonces by default.
        let secret = secret_with(13);
        let s1 = Secp256k1Signer
            .sign(&secret, b"x", HashAlg::Sha256)
            .unwrap();
        let s2 = Secp256k1Signer
            .sign(&secret, b"x", HashAlg::Sha256)
            .unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn signer_factory_dispatches_correctly() {
        for scheme in [
            SigningScheme::Ed25519,
            SigningScheme::Secp256k1,
            SigningScheme::Secp256k1Recoverable,
            SigningScheme::MlDsa44,
            SigningScheme::MlDsa65,
            SigningScheme::MlDsa87,
        ] {
            let s = crate::signer::signer_for_scheme(scheme).unwrap();
            assert_eq!(s.scheme(), scheme);
        }
    }

    /// PQ schemes were `NotImplemented` in M1; M5 wires them through. Test
    /// pinned here so we don't regress the dispatch tables silently.
    #[test]
    fn pq_schemes_now_dispatch_to_real_signers() {
        for scheme in [
            SigningScheme::MlDsa44,
            SigningScheme::MlDsa65,
            SigningScheme::MlDsa87,
        ] {
            let s = crate::signer::signer_for_scheme(scheme).expect("M5 dispatch");
            assert_eq!(s.scheme(), scheme);
            // public_key derivation must succeed on a fresh 32-byte seed.
            let secret = SecretBytes::from_slice(&[0xCDu8; 32]);
            let pk = s.public_key(&secret).unwrap();
            assert!(!pk.is_empty());
        }
    }

    proptest! {
        #[test]
        fn proptest_sign_verify_round_trip_ed25519(
            secret_bytes in proptest::array::uniform32(any::<u8>()),
            message in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let secret = SecretBytes::from_slice(&secret_bytes);
            let pk = Ed25519Signer.public_key(&secret).unwrap();
            let sig = Ed25519Signer.sign(&secret, &message, HashAlg::None).unwrap();
            Ed25519Signer.verify(&pk, &message, &sig, HashAlg::None).unwrap();
        }

        #[test]
        fn proptest_sign_verify_round_trip_secp256k1(
            secret_bytes in proptest::array::uniform32(1u8..=200u8), // avoid 0 / N-edge
            message in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            let secret = SecretBytes::from_slice(&secret_bytes);
            let pk = Secp256k1Signer.public_key(&secret).unwrap();
            let sig = Secp256k1Signer.sign(&secret, &message, HashAlg::Sha256).unwrap();
            Secp256k1Signer.verify(&pk, &message, &sig, HashAlg::Sha256).unwrap();
        }
    }
}
