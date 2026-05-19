//! Hierarchical-deterministic derivation.
//!
//! Two schemes:
//! - **secp256k1**: standard BIP32 via the `bip32` crate.
//! - **ed25519**: SLIP-0010 via a small in-tree impl (HMAC-SHA512 with
//!   `"ed25519 seed"` key). Per SLIP-0010, ed25519 only supports *hardened*
//!   derivation; any non-hardened segment is a parse-time error.
//!
//! PQ schemes have no standard HD construction (RFC §9.1) and return
//! `DerivationError::SchemeNotHd`.

use bip32::{ChildNumber as Bip32ChildNumber, Prefix, XPrv};
use hmac::{Hmac, Mac};
use qfc_wallet_types::{HdPath, HdPathSegment, SecretBytes, SigningScheme};
use sha2::Sha512;

use crate::error::DerivationError;

/// The output of a successful classical-curve derivation.
///
/// `secret` is the derived child private key (32 raw bytes for both schemes).
/// `chain_code` is the BIP32 chain code at that path; included so callers can
/// further derive without re-walking from master.
pub struct ClassicalDerivation {
    /// 32-byte private key material for the derived child.
    pub secret: SecretBytes,
    /// 32-byte chain code at the derived position.
    pub chain_code: [u8; 32],
}

/// Convert a BIP39 mnemonic phrase to a 64-byte seed using PBKDF2-HMAC-SHA512
/// (BIP39 reference construction).
///
/// `passphrase` is the optional BIP39 passphrase (separate from the
/// mnemonic). Pass `""` if not used.
///
/// # Errors
///
/// Returns `DerivationError::Mnemonic` if the phrase fails BIP39 checksum
/// validation.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<SecretBytes, DerivationError> {
    let mnemonic = bip39::Mnemonic::parse_normalized(phrase)
        .map_err(|e| DerivationError::Mnemonic(e.to_string()))?;
    let seed_bytes = mnemonic.to_seed(passphrase);
    Ok(SecretBytes::from_slice(&seed_bytes))
}

/// Derive a child private key for a classical scheme. Returns the raw 32-byte
/// scalar (secp256k1) or 32-byte seed (ed25519).
///
/// `seed` is the BIP39 seed (typically 64 bytes; minimum 16 per BIP39). For
/// ed25519 a 32-byte seed is also accepted and is used directly as the
/// SLIP-0010 master secret.
///
/// # Errors
///
/// - `DerivationError::SchemeNotHd` for any PQ scheme.
/// - `DerivationError::NonHardenedRequired` if ed25519 is asked to derive
///   through a non-hardened segment.
/// - `DerivationError::Underlying` if `bip32` reports a derivation failure.
pub fn derive_classical(
    scheme: SigningScheme,
    seed: &SecretBytes,
    path: &HdPath,
) -> Result<ClassicalDerivation, DerivationError> {
    match scheme {
        SigningScheme::Secp256k1 | SigningScheme::Secp256k1Recoverable => {
            derive_secp256k1(seed, path)
        }
        SigningScheme::Ed25519 => derive_ed25519_slip10(seed, path),
        SigningScheme::MlDsa44 | SigningScheme::MlDsa65 | SigningScheme::MlDsa87 => {
            Err(DerivationError::SchemeNotHd("ml_dsa"))
        }
    }
}

fn derive_secp256k1(
    seed: &SecretBytes,
    path: &HdPath,
) -> Result<ClassicalDerivation, DerivationError> {
    let xprv = XPrv::new(seed.expose()).map_err(|e| DerivationError::Underlying(e.to_string()))?;
    let derived = path.segments().iter().try_fold(xprv, |acc, seg| {
        let raw_index = match seg {
            HdPathSegment::Normal(i) | HdPathSegment::Hardened(i) => *i,
        };
        let child = Bip32ChildNumber::new(raw_index, seg.is_hardened())
            .map_err(|e| DerivationError::Underlying(e.to_string()))?;
        acc.derive_child(child)
            .map_err(|e| DerivationError::Underlying(e.to_string()))
    })?;
    let secret = SecretBytes::from_slice(&derived.to_bytes());
    // Extract chain code from the encoded XPrv. bip32::XPrv::to_extended_key
    // exposes the attributes including chain code.
    let xkey = derived.to_extended_key(Prefix::XPRV);
    let chain_code: [u8; 32] = xkey.attrs.chain_code;
    Ok(ClassicalDerivation { secret, chain_code })
}

fn derive_ed25519_slip10(
    seed: &SecretBytes,
    path: &HdPath,
) -> Result<ClassicalDerivation, DerivationError> {
    // SLIP-0010 master generation: HMAC-SHA512("ed25519 seed", seed).
    type HmacSha512 = Hmac<Sha512>;
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed")
        .map_err(|e| DerivationError::Underlying(e.to_string()))?;
    mac.update(seed.expose());
    let i = mac.finalize().into_bytes();
    let (mut key, mut chain): ([u8; 32], [u8; 32]) = {
        let mut k = [0u8; 32];
        let mut c = [0u8; 32];
        k.copy_from_slice(&i[..32]);
        c.copy_from_slice(&i[32..]);
        (k, c)
    };

    // Each child step: HMAC-SHA512(chain, 0x00 || key || index_be).
    for seg in path.segments() {
        if !seg.is_hardened() {
            return Err(DerivationError::NonHardenedRequired("ed25519"));
        }
        let mut mac = HmacSha512::new_from_slice(&chain)
            .map_err(|e| DerivationError::Underlying(e.to_string()))?;
        mac.update(&[0x00]);
        mac.update(&key);
        mac.update(&seg.child_index().to_be_bytes());
        let out = mac.finalize().into_bytes();
        key.copy_from_slice(&out[..32]);
        chain.copy_from_slice(&out[32..]);
    }

    Ok(ClassicalDerivation {
        secret: SecretBytes::from_slice(&key),
        chain_code: chain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use qfc_wallet_types::HdPathSegment;

    fn seed_bip39(phrase: &str) -> SecretBytes {
        mnemonic_to_seed(phrase, "").unwrap()
    }

    // BIP39 12-word test vector.
    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn mnemonic_to_seed_known_vector() {
        // BIP39 reference vector for the all-"abandon" mnemonic + empty passphrase.
        let seed = mnemonic_to_seed(TEST_MNEMONIC, "").unwrap();
        let expected_prefix =
            hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1")
                .unwrap();
        assert_eq!(seed.len(), 64);
        assert_eq!(&seed.expose()[..32], &expected_prefix[..]);
    }

    #[test]
    fn mnemonic_to_seed_rejects_bad_checksum() {
        let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"; // last word wrong
        let err = mnemonic_to_seed(bad, "");
        assert!(matches!(err, Err(DerivationError::Mnemonic(_))));
    }

    #[test]
    fn secp256k1_master_derivation_matches_bip32_reference() {
        // BIP32 test vector 1: seed = 000102030405060708090a0b0c0d0e0f
        // m -> private key 0xe8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let derived = derive_secp256k1(&seed, &HdPath::master()).unwrap();
        let expected =
            hex::decode("e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35")
                .unwrap();
        assert_eq!(derived.secret.expose(), expected.as_slice());
    }

    #[test]
    fn secp256k1_path_derivation_matches_reference() {
        // BIP32 test vector 1: m/0'/1/2'/2/1000000000 -> known private key.
        // Using the simpler m/0' check: expected 0xedb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let path = HdPath::from_segments([HdPathSegment::Hardened(0)]);
        let derived = derive_secp256k1(&seed, &path).unwrap();
        let expected =
            hex::decode("edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea")
                .unwrap();
        assert_eq!(derived.secret.expose(), expected.as_slice());
    }

    #[test]
    fn ed25519_slip10_master_matches_reference() {
        // SLIP-0010 ed25519 test vector 1, seed = 000102030405060708090a0b0c0d0e0f
        // Master key (k): 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7
        // Chain (c):       90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let derived = derive_ed25519_slip10(&seed, &HdPath::master()).unwrap();
        let expected_k =
            hex::decode("2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
                .unwrap();
        let expected_c =
            hex::decode("90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
                .unwrap();
        assert_eq!(derived.secret.expose(), expected_k.as_slice());
        assert_eq!(&derived.chain_code, expected_c.as_slice());
    }

    #[test]
    fn ed25519_slip10_first_hardened_child_matches_reference() {
        // SLIP-0010 ed25519 test vector 1, m/0':
        // k = 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let path = HdPath::from_segments([HdPathSegment::Hardened(0)]);
        let derived = derive_ed25519_slip10(&seed, &path).unwrap();
        let expected =
            hex::decode("68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3")
                .unwrap();
        assert_eq!(derived.secret.expose(), expected.as_slice());
    }

    #[test]
    fn ed25519_rejects_non_hardened_segment() {
        let seed = seed_bip39(TEST_MNEMONIC);
        let path = HdPath::from_segments([HdPathSegment::Normal(0)]);
        let err = derive_ed25519_slip10(&seed, &path);
        assert!(matches!(err, Err(DerivationError::NonHardenedRequired(_))));
    }

    #[test]
    fn pq_schemes_report_scheme_not_hd() {
        let seed = SecretBytes::from_slice(&[1u8; 32]);
        let path = HdPath::master();
        for scheme in [
            SigningScheme::MlDsa44,
            SigningScheme::MlDsa65,
            SigningScheme::MlDsa87,
        ] {
            let err = derive_classical(scheme, &seed, &path);
            assert!(matches!(err, Err(DerivationError::SchemeNotHd(_))));
        }
    }

    #[test]
    fn classical_dispatch_for_secp256k1() {
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let d = derive_classical(SigningScheme::Secp256k1, &seed, &HdPath::master()).unwrap();
        assert_eq!(d.secret.len(), 32);
    }

    #[test]
    fn classical_dispatch_for_ed25519() {
        let seed =
            SecretBytes::from_slice(&hex::decode("000102030405060708090a0b0c0d0e0f").unwrap());
        let d = derive_classical(SigningScheme::Ed25519, &seed, &HdPath::master()).unwrap();
        assert_eq!(d.secret.len(), 32);
    }
}
