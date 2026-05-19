//! `qfc-policy` — policy DSL and evaluator. See `docs/server-wallet-rfc.md` §2.4.
//!
//! Status:
//! - M1: `Policy` trait + `StaticAllowDenyPolicy` (allow/deny lists for
//!   chains, requesters, methods — no rate limits, no VM decoders yet).
//! - M2: full DSL with chain/contract/method allowlists, value caps, time
//!   windows, rate limits, VM-shape constraints; EVM/QVM(minimal)/WASM
//!   decoders (per RFC §9.6 the WASM and full QVM decoders are deferred
//!   pending qfc-core support).
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

pub mod decision;
pub mod policy;
pub mod request;
pub mod static_policy;

pub use decision::{DenyReason, PolicyDecision, PolicyError, RuleHit};
pub use policy::Policy;
pub use request::{Requester, SigningPayload, SigningRequest, VmType};
pub use static_policy::{AllowDefault, StaticAllowDenyPolicy};
