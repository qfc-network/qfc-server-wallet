//! `qfc-sss` — Shamir Secret Sharing wrapper and `ShareStore` abstraction.
//! See `docs/server-wallet-rfc.md` §2.2.
//!
//! Status:
//! - M1: byte-secret Shamir split / combine via `vsss-rs` (P2);
//!   `ShareStore` trait + `MockShareStore` / `LocalFsShareStore` land in P3.
//! - M3: `S3KmsShareStore` with attestation-conditional KMS decrypt.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod error;
pub mod shamir;

pub use error::ShareError;
pub use shamir::{combine_shares, split_secret, ShamirParams, ShamirShare};
