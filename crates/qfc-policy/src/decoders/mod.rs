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
//! - `qvm` — minimal envelope decoder (M5; RFC §9.6 option (b)). Parses
//!   `chain_id`, `to`, `value`, `gas_limit` from the borsh envelope; treats
//!   `data` as opaque (method-level QVM policy deferred to M6).
//! - WASM — deferred per RFC §9.6 (qfc-core has no WASM execution path).
//!
//! The decoder primitives are intentionally independent of the `Policy`
//! trait: P3 (the DSL) calls them via a thin `VmDecoder` shim defined in
//! [`crate::vm`].

pub mod evm;
pub mod qvm;

pub use evm::{decode_evm_tx, AccessListItem, DecodedEvmTx, EvmDecodeError, EvmDecoder, EvmTxType};
pub use qvm::{decode_qvm_tx, DecodedQvmTx, QvmDecodeError, QvmDecoder, QvmTxType};
