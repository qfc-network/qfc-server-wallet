//! Shared error types.

use thiserror::Error;

/// A parsing error returned when a string fails to deserialize into a typed value.
#[derive(Debug, Error)]
pub enum ParseError {
    /// The input was not valid for a ULID-shaped identifier.
    #[error("invalid ULID: {0}")]
    InvalidUlid(String),

    /// The input was not valid for an HD derivation path.
    #[error("invalid HD path: {0}")]
    InvalidHdPath(String),

    /// Length mismatch when parsing a fixed-size byte string.
    #[error("invalid length for {what}: expected {expected}, got {got}")]
    InvalidLength {
        /// Symbolic name of the value being parsed (e.g. `"share-index"`).
        what: &'static str,
        /// Expected byte length.
        expected: usize,
        /// Actual byte length received.
        got: usize,
    },

    /// Hex decoding failed.
    #[error("invalid hex: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

/// Generic type-system errors raised by helpers in this crate.
#[derive(Debug, Error)]
pub enum TypeError {
    /// A scheme was used outside its supported domain (e.g. PQ scheme asked for HD derivation).
    #[error("unsupported scheme combination: {0}")]
    UnsupportedScheme(&'static str),
}
