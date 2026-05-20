//! ML-DSA (FIPS 204, formerly CRYSTALS-Dilithium) signers — M5.
//!
//! All three NIST security levels:
//! - `MlDsa44Signer` — ML-DSA-44, category 2 (~128-bit symmetric strength).
//! - `MlDsa65Signer` — ML-DSA-65, category 3 (~192-bit). Recommended.
//! - `MlDsa87Signer` — ML-DSA-87, category 5 (~256-bit).
//!
//! ## Secret material
//!
//! Per FIPS 204 Algorithm 6 (`ML-DSA.KeyGen_internal`), the secret material is
//! a 32-byte seed `xi` from which all expanded key data is deterministically
//! derived. We use the seed as the canonical secret across crate boundaries
//! (see [`SEED_BYTES`]). This means:
//! - `SecretBytes` for ML-DSA is exactly 32 bytes — the same width as
//!   ed25519/secp256k1 — so the SSS chunking layer (31-byte payload per
//!   scalar chunk) handles it in two chunks identically to classical keys
//!   (see [`docs/m5-decisions.md`] D39).
//! - The expanded signing key (~2.4 kB for ML-DSA-44, ~4.9 kB for ML-DSA-87)
//!   never crosses the enclave boundary; it is recomputed inside the
//!   enclave from the seed each time `sign()` is called. This trades a few
//!   ms of CPU per sign for a much smaller secret-management surface.
//!
//! ## Public key encoding
//!
//! - ML-DSA-44 — 1312 bytes (fixed).
//! - ML-DSA-65 — 1952 bytes (fixed).
//! - ML-DSA-87 — 2592 bytes (fixed).
//!
//! The bytes are the FIPS 204 `pkEncode` output (Algorithm 22). The crate
//! exposes it as a `hybrid_array::Array<u8, _>`; we materialise to `Vec<u8>`
//! at the trait boundary.
//!
//! ## Signature encoding
//!
//! - ML-DSA-44 — 2420 bytes.
//! - ML-DSA-65 — 3309 bytes.
//! - ML-DSA-87 — 4627 bytes.
//!
//! The bytes are the FIPS 204 `sigEncode` output (Algorithm 26).
//!
//! ## Pre-hashing
//!
//! ML-DSA hashes the message internally as part of the signing construction
//! (see FIPS 204 §6.2: `μ = H(BytesToBits(tr) || M', 64)`). Callers MUST pass
//! [`HashAlg::None`] — any other value is rejected with
//! [`SignerError::UnsupportedHash`]. There is a separate pre-hashed mode
//! (HashML-DSA / FIPS 204 §6.3) we do not yet expose; if a caller needs it,
//! add a distinct variant rather than overloading these signers.
//!
//! ## Determinism
//!
//! The `Signer` trait impl uses the deterministic ML-DSA variant
//! (`raw_sign_deterministic` in `ml-dsa::signing`). The randomized variant
//! is not exposed; deterministic signing makes the M5 test suite reproducible
//! and matches the behaviour we already rely on for ed25519 / secp256k1
//! (RFC 6979). Per FIPS 204 §3.6.1, the deterministic variant is acceptable
//! when paired with a strong KDF on the seed material — which we have via
//! SSS reconstruction inside the enclave.

use ml_dsa::signature::{Keypair, Signer as MlDsaSignerTrait, Verifier};
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, MlDsa44, MlDsa65, MlDsa87, MlDsaParams, Signature,
    SigningKey, VerifyingKey, B32,
};
use qfc_wallet_types::{HashAlg, SecretBytes, SigningScheme};

use crate::error::SignerError;
use crate::signer::Signer;

/// ML-DSA secret material is a 32-byte seed across all NIST levels.
pub const SEED_BYTES: usize = 32;

/// Signer for [`SigningScheme::MlDsa44`] (NIST level 2 — Dilithium2).
pub struct MlDsa44Signer;

/// Signer for [`SigningScheme::MlDsa65`] (NIST level 3 — Dilithium3).
pub struct MlDsa65Signer;

/// Signer for [`SigningScheme::MlDsa87`] (NIST level 5 — Dilithium5).
pub struct MlDsa87Signer;

fn seed_from(secret: &SecretBytes, scheme: &'static str) -> Result<B32, SignerError> {
    let bytes = secret.expose();
    if bytes.len() != SEED_BYTES {
        return Err(SignerError::InvalidSecret {
            scheme,
            reason: "ML-DSA seed must be exactly 32 bytes",
        });
    }
    let mut arr = B32::default();
    arr.as_mut_slice().copy_from_slice(bytes);
    Ok(arr)
}

fn require_no_hash(hash: HashAlg, scheme: &'static str) -> Result<(), SignerError> {
    match hash {
        HashAlg::None => Ok(()),
        _ => Err(SignerError::UnsupportedHash {
            scheme,
            hash: match hash {
                HashAlg::Sha256 => "sha256",
                HashAlg::Keccak256 => "keccak256",
                HashAlg::Blake3 => "blake3",
                HashAlg::None => unreachable!(),
            },
        }),
    }
}

/// Inner generic helper: `public_key` over any ML-DSA parameter set.
fn public_key_inner<P>(secret: &SecretBytes, scheme: &'static str) -> Result<Vec<u8>, SignerError>
where
    P: MlDsaParams,
{
    let seed = seed_from(secret, scheme)?;
    let sk: SigningKey<P> = SigningKey::from_seed(&seed);
    let vk: VerifyingKey<P> = sk.verifying_key();
    Ok(vk.encode().as_slice().to_vec())
}

/// Inner generic helper: `sign` over any ML-DSA parameter set.
fn sign_inner<P>(
    secret: &SecretBytes,
    message: &[u8],
    hash_alg: HashAlg,
    scheme: &'static str,
) -> Result<Vec<u8>, SignerError>
where
    P: MlDsaParams,
{
    require_no_hash(hash_alg, scheme)?;
    let seed = seed_from(secret, scheme)?;
    let sk: SigningKey<P> = SigningKey::from_seed(&seed);
    let sig: Signature<P> = sk.sign(message);
    Ok(sig.encode().as_slice().to_vec())
}

/// Inner generic helper: `verify` over any ML-DSA parameter set.
fn verify_inner<P>(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    hash_alg: HashAlg,
    scheme: &'static str,
) -> Result<(), SignerError>
where
    P: MlDsaParams,
{
    require_no_hash(hash_alg, scheme)?;
    let vk_enc = EncodedVerifyingKey::<P>::try_from(public_key).map_err(|_| {
        SignerError::InvalidPublicKey {
            scheme,
            reason: "public key has wrong length for ML-DSA parameter set",
        }
    })?;
    let vk: VerifyingKey<P> = VerifyingKey::decode(&vk_enc);
    let sig_enc =
        EncodedSignature::<P>::try_from(signature).map_err(|_| SignerError::InvalidPublicKey {
            scheme,
            reason: "signature has wrong length for ML-DSA parameter set",
        })?;
    let sig: Signature<P> = Signature::decode(&sig_enc).ok_or(SignerError::VerificationFailed)?;
    vk.verify(message, &sig)
        .map_err(|_| SignerError::VerificationFailed)
}

impl Signer for MlDsa44Signer {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::MlDsa44
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        public_key_inner::<MlDsa44>(secret, "ml_dsa_44")
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        sign_inner::<MlDsa44>(secret, message, hash_alg, "ml_dsa_44")
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        verify_inner::<MlDsa44>(public_key, message, signature, hash_alg, "ml_dsa_44")
    }
}

impl Signer for MlDsa65Signer {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::MlDsa65
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        public_key_inner::<MlDsa65>(secret, "ml_dsa_65")
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        sign_inner::<MlDsa65>(secret, message, hash_alg, "ml_dsa_65")
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        verify_inner::<MlDsa65>(public_key, message, signature, hash_alg, "ml_dsa_65")
    }
}

impl Signer for MlDsa87Signer {
    fn scheme(&self) -> SigningScheme {
        SigningScheme::MlDsa87
    }

    fn public_key(&self, secret: &SecretBytes) -> Result<Vec<u8>, SignerError> {
        public_key_inner::<MlDsa87>(secret, "ml_dsa_87")
    }

    fn sign(
        &self,
        secret: &SecretBytes,
        message: &[u8],
        hash_alg: HashAlg,
    ) -> Result<Vec<u8>, SignerError> {
        sign_inner::<MlDsa87>(secret, message, hash_alg, "ml_dsa_87")
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        hash_alg: HashAlg,
    ) -> Result<(), SignerError> {
        verify_inner::<MlDsa87>(public_key, message, signature, hash_alg, "ml_dsa_87")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(byte: u8) -> SecretBytes {
        SecretBytes::from_slice(&[byte; SEED_BYTES])
    }

    /// FIPS 204 public-key sizes (Table 1). Sanity-check our encoding width.
    #[test]
    fn ml_dsa_44_public_key_is_1312_bytes() {
        let pk = MlDsa44Signer.public_key(&seed(1)).unwrap();
        assert_eq!(pk.len(), 1312);
    }

    #[test]
    fn ml_dsa_65_public_key_is_1952_bytes() {
        let pk = MlDsa65Signer.public_key(&seed(1)).unwrap();
        assert_eq!(pk.len(), 1952);
    }

    #[test]
    fn ml_dsa_87_public_key_is_2592_bytes() {
        let pk = MlDsa87Signer.public_key(&seed(1)).unwrap();
        assert_eq!(pk.len(), 2592);
    }

    /// FIPS 204 signature sizes (Table 2).
    #[test]
    fn ml_dsa_44_signature_is_2420_bytes() {
        let sig = MlDsa44Signer
            .sign(&seed(2), b"hello", HashAlg::None)
            .unwrap();
        assert_eq!(sig.len(), 2420);
    }

    #[test]
    fn ml_dsa_65_signature_is_3309_bytes() {
        let sig = MlDsa65Signer
            .sign(&seed(2), b"hello", HashAlg::None)
            .unwrap();
        assert_eq!(sig.len(), 3309);
    }

    #[test]
    fn ml_dsa_87_signature_is_4627_bytes() {
        let sig = MlDsa87Signer
            .sign(&seed(2), b"hello", HashAlg::None)
            .unwrap();
        assert_eq!(sig.len(), 4627);
    }

    /// Round-trip every level. Verifies that sign() + verify() succeed and
    /// that the scheme accessor matches.
    #[test]
    fn round_trip_all_levels() {
        let signers: Vec<Box<dyn Signer>> = vec![
            Box::new(MlDsa44Signer),
            Box::new(MlDsa65Signer),
            Box::new(MlDsa87Signer),
        ];
        for signer in signers {
            let s = seed(5);
            let pk = signer.public_key(&s).unwrap();
            let msg = b"qfc post-quantum";
            let sig = signer.sign(&s, msg, HashAlg::None).unwrap();
            signer
                .verify(&pk, msg, &sig, HashAlg::None)
                .expect("ML-DSA verify must succeed");
        }
    }

    #[test]
    fn verify_rejects_modified_message() {
        let signers: Vec<Box<dyn Signer>> = vec![
            Box::new(MlDsa44Signer),
            Box::new(MlDsa65Signer),
            Box::new(MlDsa87Signer),
        ];
        for signer in signers {
            let s = seed(7);
            let pk = signer.public_key(&s).unwrap();
            let sig = signer.sign(&s, b"original", HashAlg::None).unwrap();
            let err = signer.verify(&pk, b"modified", &sig, HashAlg::None);
            assert!(matches!(err, Err(SignerError::VerificationFailed)));
        }
    }

    #[test]
    fn verify_rejects_modified_signature() {
        // Flip a byte deep inside the signature blob; for ML-DSA, every
        // signature byte is structural so a single-bit flip must trip the
        // verifier (either as VerificationFailed or as a decode-time
        // norm-check failure surfaced as VerificationFailed).
        let s = seed(11);
        let pk = MlDsa65Signer.public_key(&s).unwrap();
        let mut sig = MlDsa65Signer.sign(&s, b"msg", HashAlg::None).unwrap();
        // Flip a byte in the middle of the signature.
        let mid = sig.len() / 2;
        sig[mid] ^= 0x55;
        let err = MlDsa65Signer.verify(&pk, b"msg", &sig, HashAlg::None);
        assert!(matches!(err, Err(SignerError::VerificationFailed)));
    }

    /// Signing is deterministic — the `Signer` impl uses the
    /// ML-DSA deterministic variant (FIPS 204 §3.6.1).
    #[test]
    fn signing_is_deterministic() {
        let s = seed(13);
        for signer in [
            &MlDsa44Signer as &dyn Signer,
            &MlDsa65Signer,
            &MlDsa87Signer,
        ] {
            let a = signer
                .sign(&s, b"determinism check", HashAlg::None)
                .unwrap();
            let b = signer
                .sign(&s, b"determinism check", HashAlg::None)
                .unwrap();
            assert_eq!(a, b, "ML-DSA signing must be deterministic");
        }
    }

    #[test]
    fn rejects_non_none_hash_alg() {
        let s = seed(1);
        for signer in [
            &MlDsa44Signer as &dyn Signer,
            &MlDsa65Signer,
            &MlDsa87Signer,
        ] {
            for h in [HashAlg::Sha256, HashAlg::Keccak256, HashAlg::Blake3] {
                let err = signer.sign(&s, b"x", h);
                assert!(matches!(err, Err(SignerError::UnsupportedHash { .. })));
            }
        }
    }

    #[test]
    fn rejects_wrong_seed_length() {
        // 16 bytes — too short.
        let bad = SecretBytes::from_slice(&[0u8; 16]);
        let err = MlDsa44Signer.public_key(&bad);
        assert!(matches!(err, Err(SignerError::InvalidSecret { .. })));
    }

    #[test]
    fn rejects_wrong_pk_length() {
        let sig = MlDsa44Signer.sign(&seed(1), b"msg", HashAlg::None).unwrap();
        // ML-DSA-44 pk is 1312 bytes; pass an ML-DSA-65 pk instead.
        let wrong_pk = MlDsa65Signer.public_key(&seed(1)).unwrap();
        let err = MlDsa44Signer.verify(&wrong_pk, b"msg", &sig, HashAlg::None);
        assert!(matches!(err, Err(SignerError::InvalidPublicKey { .. })));
    }

    #[test]
    fn scheme_accessor_matches() {
        assert_eq!(MlDsa44Signer.scheme(), SigningScheme::MlDsa44);
        assert_eq!(MlDsa65Signer.scheme(), SigningScheme::MlDsa65);
        assert_eq!(MlDsa87Signer.scheme(), SigningScheme::MlDsa87);
    }
}
