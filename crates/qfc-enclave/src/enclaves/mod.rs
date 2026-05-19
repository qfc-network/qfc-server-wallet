//! Concrete `Enclave` impls.
//!
//! M1 ships only `MockEnclave` (in-process, no real isolation). The
//! `NitroEnclave` impl lands in M3.

mod mock;

pub use mock::MockEnclave;
