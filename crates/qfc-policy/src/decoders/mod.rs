//! Per-VM transaction decoders for the policy engine.
//!
//! Each decoder turns a raw transaction envelope into a strongly-typed
//! `Decoded<Vm>Tx` struct. The policy evaluator pulls fields off the
//! decoded shape to enforce contract / method / value constraints
//! (RFC §2.4, §7).
//!
//! Status:
//! - `evm` — full envelope decoder for legacy, EIP-2930, EIP-1559, EIP-4844
//!   (M2 P4). Structural decode only — no signature recovery, no blob KZG
//!   verification.
//! - QVM / WASM — deferred per RFC §9.6.
//!
//! The decoder primitives are intentionally independent of the `Policy`
//! trait: P3 (the DSL) calls them via a thin `VmDecoder` shim defined in
//! [`crate::vm`].

pub mod evm;

pub use evm::{decode_evm_tx, AccessListItem, DecodedEvmTx, EvmDecodeError, EvmDecoder, EvmTxType};
