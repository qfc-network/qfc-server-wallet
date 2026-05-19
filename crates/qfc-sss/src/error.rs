//! Error types for SSS / share-store layer.

use thiserror::Error;

/// Errors raised by the SSS layer.
#[derive(Debug, Error)]
pub enum ShareError {
    /// `threshold` is not in `1..=total` or `total` exceeds the scheme's max.
    #[error("invalid SSS parameters: threshold={threshold}, total={total}: {reason}")]
    InvalidParameters {
        /// `M` — minimum shares required to reconstruct.
        threshold: u8,
        /// `N` — total number of shares produced.
        total: u8,
        /// Human-readable explanation.
        reason: &'static str,
    },

    /// The supplied secret is empty or exceeds an implementation limit.
    #[error("invalid secret length: {0}")]
    InvalidSecret(&'static str),

    /// Underlying `vsss-rs` reported a failure.
    #[error("vsss-rs error: {0}")]
    Vsss(String),

    /// Caller provided fewer than `threshold` shares to `combine_shares`.
    #[error("not enough shares: need at least {threshold}, got {provided}")]
    NotEnoughShares {
        /// Minimum required.
        threshold: u8,
        /// Number of shares supplied.
        provided: usize,
    },

    /// Provided shares have inconsistent metadata (different parameters or
    /// different share IDs).
    #[error("inconsistent shares: {0}")]
    InconsistentShares(&'static str),
}
