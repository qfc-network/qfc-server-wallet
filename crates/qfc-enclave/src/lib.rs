//! `qfc-enclave` — TEE boundary abstraction. See `docs/server-wallet-rfc.md` §2.1.
//!
//! Status: pre-M1 skeleton; the `Enclave` trait + `MockEnclave` land in M1,
//! `NitroEnclave` in M3.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
