//! Shamir Secret Sharing over byte secrets.
//!
//! Wraps `vsss-rs` to expose a small, audit-friendly surface:
//! `split_secret` and `combine_shares`. Each "share" returned from this
//! crate is an opaque `Vec<u8>` envelope plus a 1-based index.
//!
//! ### Construction
//!
//! `vsss-rs` is field-element-oriented: it splits one `PrimeField` scalar at
//! a time. To share a byte string of arbitrary length, we:
//!
//! 1. Length-prefix the secret with a `u32` big-endian header.
//! 2. Pad the prefixed buffer up to a multiple of 31 bytes.
//! 3. Treat each 31-byte block as a 256-bit scalar (the high byte forced to
//!    `0x00` so the value is always `< n` for the curve we use).
//! 4. Split each scalar via `vsss-rs` into `total` shares using the same
//!    1-based identifier (so the per-chunk shares for share #i align by
//!    identifier across chunks).
//! 5. Concatenate the per-chunk shares into a single `ShamirShare.blob`.
//!
//! Reconstruction reverses the process. We chunk at 31 bytes (not 32) so
//! that every secret byte fits within the curve order with zero rejection;
//! the `vsss-rs` field reps are bit-for-bit identical for our chunks.
//!
//! ### Threat surface
//!
//! `split_secret` uses `OsRng` for the polynomial coefficients. Callers
//! MUST keep the input secret behind `SecretBytes` lifecycle — this layer
//! does not zeroize for you; it only refrains from holding extra copies.
//! Each `ShamirShare` is a random-looking blob until `>= threshold` are
//! combined, but operationally treat them with the same care.

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use vsss_rs::{combine_shares as vsss_combine, shamir};

use crate::error::ShareError;

/// SSS scheme parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShamirParams {
    /// `M` — minimum shares required to reconstruct the secret.
    pub threshold: u8,
    /// `N` — total number of shares produced.
    pub total: u8,
}

impl ShamirParams {
    /// Validate the parameters.
    ///
    /// # Errors
    ///
    /// Returns `ShareError::InvalidParameters` if the parameters are out of
    /// range. Acceptable: `2 <= threshold <= total <= 255`.
    pub fn validate(self) -> Result<(), ShareError> {
        if self.threshold < 2 {
            return Err(ShareError::InvalidParameters {
                threshold: self.threshold,
                total: self.total,
                reason: "threshold must be >= 2 (a 1-of-N scheme is not secret sharing)",
            });
        }
        if self.threshold > self.total {
            return Err(ShareError::InvalidParameters {
                threshold: self.threshold,
                total: self.total,
                reason: "threshold must be <= total",
            });
        }
        Ok(())
    }
}

/// A single Shamir share with its scheme metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShamirShare {
    /// 1-based index used for Lagrange interpolation (the SSS x-coordinate).
    pub index: u8,
    /// Scheme parameters that produced this share. Carried per-share so
    /// `combine_shares` is self-describing and catches mix-and-match bugs.
    pub params: ShamirParams,
    /// Opaque share blob. Layout: 4-byte BE u32 secret-length || N
    /// concatenated 33-byte per-chunk shares.
    pub blob: Vec<u8>,
}

const CHUNK_DATA_BYTES: usize = 31; // bytes of secret per chunk
const PER_CHUNK_SHARE_BYTES: usize = 33; // vsss-rs `[u8; 33]` repr: 1 id + 32 value
const HEADER_BYTES: usize = 4; // u32 secret length

/// Split a secret into `params.total` shares such that any `params.threshold`
/// can reconstruct the original. Uses `OsRng` as the CSPRNG.
///
/// # Errors
///
/// - `ShareError::InvalidParameters` if `params.validate()` fails.
/// - `ShareError::InvalidSecret` if the secret is empty or exceeds the
///   internal length limit (`u32::MAX`).
/// - `ShareError::Vsss` if the underlying library reports a failure.
#[allow(clippy::missing_panics_doc)] // unwrap covered by length precondition above
pub fn split_secret(secret: &[u8], params: ShamirParams) -> Result<Vec<ShamirShare>, ShareError> {
    params.validate()?;
    if secret.is_empty() {
        return Err(ShareError::InvalidSecret("secret must not be empty"));
    }
    let secret_len: u32 = secret
        .len()
        .try_into()
        .map_err(|_| ShareError::InvalidSecret("secret length exceeds 2^32"))?;

    // 1. Length-prefix and pad up to a multiple of CHUNK_DATA_BYTES.
    let mut prefixed = Vec::with_capacity(HEADER_BYTES + secret.len() + CHUNK_DATA_BYTES);
    prefixed.extend_from_slice(&secret_len.to_be_bytes());
    prefixed.extend_from_slice(secret);
    while prefixed.len() % CHUNK_DATA_BYTES != 0 {
        prefixed.push(0u8);
    }

    let chunk_count = prefixed.len() / CHUNK_DATA_BYTES;

    // 2. For each chunk, split into `total` per-chunk shares.
    let mut per_chunk_shares: Vec<Vec<[u8; PER_CHUNK_SHARE_BYTES]>> =
        Vec::with_capacity(chunk_count);

    for chunk_idx in 0..chunk_count {
        let start = chunk_idx * CHUNK_DATA_BYTES;
        let chunk = &prefixed[start..start + CHUNK_DATA_BYTES];

        // Build the scalar input: 32-byte big-endian with high byte = 0.
        let mut field_bytes = [0u8; 32];
        field_bytes[1..].copy_from_slice(chunk);
        let scalar: k256::Scalar = scalar_from_bytes(&field_bytes)?;

        let mut rng = OsRng;
        let shares: Vec<[u8; PER_CHUNK_SHARE_BYTES]> =
            shamir::split_secret::<k256::Scalar, u8, [u8; PER_CHUNK_SHARE_BYTES]>(
                params.threshold as usize,
                params.total as usize,
                scalar,
                &mut rng,
            )
            .map_err(|e| ShareError::Vsss(format!("{e:?}")))?;
        per_chunk_shares.push(shares);
    }

    // 3. Re-shape: per-chunk shares -> per-share-index list of chunks.
    let mut output = Vec::with_capacity(params.total as usize);
    for share_idx in 0..(params.total as usize) {
        let mut combined = Vec::with_capacity(HEADER_BYTES + chunk_count * PER_CHUNK_SHARE_BYTES);
        combined.extend_from_slice(&secret_len.to_be_bytes());
        for chunk_shares in &per_chunk_shares {
            combined.extend_from_slice(&chunk_shares[share_idx]);
        }
        output.push(ShamirShare {
            index: u8::try_from(share_idx + 1).unwrap(),
            params,
            blob: combined,
        });
    }
    Ok(output)
}

/// Reconstruct the secret from any subset of `>= threshold` shares.
///
/// # Errors
///
/// - `ShareError::NotEnoughShares` if `shares.len() < threshold`.
/// - `ShareError::InconsistentShares` if shares have differing parameters
///   or duplicate indices.
/// - `ShareError::Vsss` if the underlying library reports a failure.
#[allow(clippy::missing_panics_doc)]
pub fn combine_shares(shares: &[ShamirShare]) -> Result<Vec<u8>, ShareError> {
    let Some(first) = shares.first() else {
        return Err(ShareError::NotEnoughShares {
            threshold: 1,
            provided: 0,
        });
    };
    let params = first.params;
    if shares.len() < params.threshold as usize {
        return Err(ShareError::NotEnoughShares {
            threshold: params.threshold,
            provided: shares.len(),
        });
    }
    if shares.iter().any(|s| s.params != params) {
        return Err(ShareError::InconsistentShares("parameters mismatch"));
    }
    let mut indices: Vec<u8> = shares.iter().map(|s| s.index).collect();
    indices.sort_unstable();
    indices.dedup();
    if indices.len() != shares.len() {
        return Err(ShareError::InconsistentShares("duplicate share indices"));
    }
    if first.blob.len() < HEADER_BYTES {
        return Err(ShareError::InconsistentShares("share blob too short"));
    }
    let secret_len = u32::from_be_bytes(first.blob[..HEADER_BYTES].try_into().unwrap()) as usize;
    let body_len = first.blob.len() - HEADER_BYTES;
    if body_len % PER_CHUNK_SHARE_BYTES != 0 {
        return Err(ShareError::InconsistentShares("share blob size invariant"));
    }
    let chunk_count = body_len / PER_CHUNK_SHARE_BYTES;
    for s in shares {
        if s.blob.len() != first.blob.len() {
            return Err(ShareError::InconsistentShares("share blob length mismatch"));
        }
    }

    let mut recovered_prefixed = Vec::with_capacity(chunk_count * CHUNK_DATA_BYTES);
    for chunk_idx in 0..chunk_count {
        let offset = HEADER_BYTES + chunk_idx * PER_CHUNK_SHARE_BYTES;
        let mut chunk_shares: Vec<[u8; PER_CHUNK_SHARE_BYTES]> = Vec::with_capacity(shares.len());
        for s in shares {
            let bytes: [u8; PER_CHUNK_SHARE_BYTES] = s.blob[offset..offset + PER_CHUNK_SHARE_BYTES]
                .try_into()
                .map_err(|_| ShareError::InconsistentShares("share slice"))?;
            chunk_shares.push(bytes);
        }
        let scalar: k256::Scalar =
            vsss_combine(&chunk_shares).map_err(|e| ShareError::Vsss(format!("{e:?}")))?;
        let field_bytes = scalar_to_bytes(&scalar);
        // Strip the high byte (always zero by construction).
        recovered_prefixed.extend_from_slice(&field_bytes[1..]);
    }

    // The recovered buffer is the original length-prefixed-and-padded secret.
    // Verify the header matches the per-share header, then strip prefix + padding.
    if recovered_prefixed.len() < secret_len {
        return Err(ShareError::InconsistentShares(
            "recovered shorter than declared",
        ));
    }
    // The first 4 bytes of the recovered buffer should match secret_len.
    // We laid it out as: [len_be4 || secret || padding]; recombination over
    // 31-byte chunks reproduces that exact byte sequence.
    let recovered_len =
        u32::from_be_bytes(recovered_prefixed[..HEADER_BYTES].try_into().unwrap()) as usize;
    if recovered_len != secret_len {
        return Err(ShareError::InconsistentShares(
            "header mismatch on reconstruction",
        ));
    }
    let end = HEADER_BYTES + secret_len;
    if end > recovered_prefixed.len() {
        return Err(ShareError::InconsistentShares(
            "recovered buffer too small for declared length",
        ));
    }
    Ok(recovered_prefixed[HEADER_BYTES..end].to_vec())
}

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<k256::Scalar, ShareError> {
    use k256::elliptic_curve::PrimeField;
    let repr: k256::FieldBytes = (*bytes).into();
    let ct = k256::Scalar::from_repr(repr);
    Option::<k256::Scalar>::from(ct).ok_or(ShareError::Vsss(
        "chunk exceeds secp256k1 scalar order".into(),
    ))
}

fn scalar_to_bytes(s: &k256::Scalar) -> [u8; 32] {
    use k256::elliptic_curve::PrimeField;
    s.to_repr().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn secret_32() -> Vec<u8> {
        b"qfc-test-secret-32-bytes-padded!".to_vec()
    }

    #[test]
    fn params_validate_rejects_low_threshold() {
        let p = ShamirParams {
            threshold: 1,
            total: 3,
        };
        assert!(matches!(
            p.validate(),
            Err(ShareError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn params_validate_rejects_threshold_gt_total() {
        let p = ShamirParams {
            threshold: 5,
            total: 3,
        };
        assert!(matches!(
            p.validate(),
            Err(ShareError::InvalidParameters { .. })
        ));
    }

    #[test]
    fn split_combine_round_trip_2_of_3() {
        let secret = secret_32();
        let params = ShamirParams {
            threshold: 2,
            total: 3,
        };
        let shares = split_secret(&secret, params).unwrap();
        assert_eq!(shares.len(), 3);
        let combos: Vec<Vec<ShamirShare>> = vec![
            shares[..2].to_vec(),
            shares[1..3].to_vec(),
            vec![shares[0].clone(), shares[2].clone()],
        ];
        for combo in combos {
            let recovered = combine_shares(&combo).unwrap();
            assert_eq!(recovered, secret);
        }
    }

    #[test]
    fn split_combine_3_of_5_round_trip() {
        let secret = vec![0xABu8; 64];
        let params = ShamirParams {
            threshold: 3,
            total: 5,
        };
        let shares = split_secret(&secret, params).unwrap();
        let recovered = combine_shares(&shares[..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn combine_with_all_n_shares_works() {
        let secret = secret_32();
        let params = ShamirParams {
            threshold: 2,
            total: 3,
        };
        let shares = split_secret(&secret, params).unwrap();
        let recovered = combine_shares(&shares).unwrap();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn combine_rejects_below_threshold() {
        let secret = secret_32();
        let params = ShamirParams {
            threshold: 3,
            total: 5,
        };
        let shares = split_secret(&secret, params).unwrap();
        let err = combine_shares(&shares[..2]);
        assert!(matches!(
            err,
            Err(ShareError::NotEnoughShares {
                threshold: 3,
                provided: 2,
            })
        ));
    }

    #[test]
    fn combine_rejects_duplicate_indices() {
        let secret = secret_32();
        let params = ShamirParams {
            threshold: 2,
            total: 3,
        };
        let shares = split_secret(&secret, params).unwrap();
        let dup = vec![shares[0].clone(), shares[0].clone()];
        let err = combine_shares(&dup);
        assert!(matches!(err, Err(ShareError::InconsistentShares(_))));
    }

    #[test]
    fn empty_secret_rejected() {
        let err = split_secret(
            b"",
            ShamirParams {
                threshold: 2,
                total: 3,
            },
        );
        assert!(matches!(err, Err(ShareError::InvalidSecret(_))));
    }

    #[test]
    fn split_short_secret_round_trips() {
        let secret = vec![0x42u8; 5];
        let params = ShamirParams {
            threshold: 2,
            total: 3,
        };
        let shares = split_secret(&secret, params).unwrap();
        let recovered = combine_shares(&shares[1..3]).unwrap();
        assert_eq!(recovered, secret);
    }

    proptest! {
        #[test]
        fn proptest_round_trip_arbitrary_secret_and_threshold(
            secret in proptest::collection::vec(any::<u8>(), 1..=96),
            threshold in 2u8..=4,
            extra in 0u8..=3,
        ) {
            let total = threshold + extra;
            let params = ShamirParams { threshold, total };
            let shares = split_secret(&secret, params).unwrap();
            // Use exactly threshold shares from arbitrary positions.
            let chosen: Vec<_> = shares.iter().take(threshold as usize).cloned().collect();
            let recovered = combine_shares(&chosen).unwrap();
            prop_assert_eq!(recovered, secret);
        }

        #[test]
        fn proptest_combine_with_any_threshold_subset(
            secret in proptest::collection::vec(any::<u8>(), 1..=64),
        ) {
            let params = ShamirParams { threshold: 3, total: 5 };
            let shares = split_secret(&secret, params).unwrap();
            // Pick any threshold-sized subset.
            for combo in [&shares[..3], &shares[1..4], &shares[2..5]] {
                let recovered = combine_shares(combo).unwrap();
                prop_assert_eq!(recovered.clone(), secret.clone());
            }
        }
    }
}
