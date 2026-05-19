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
pub mod decoders;
pub mod policy;
pub mod rate_limit;
pub mod request;
pub mod rule_set_policy;
pub mod rules;
pub mod static_policy;
pub mod vm;

pub use decision::{DenyReason, PolicyDecision, PolicyError, RuleEffect, RuleHit};
pub use decoders::{
    decode_evm_tx, AccessListItem, DecodedEvmTx, EvmDecodeError, EvmDecoder, EvmTxType,
};
pub use policy::Policy;
pub use rate_limit::{Clock, ManualClock, SystemClock, TokenBucketLimiter};
pub use request::{Requester, SigningPayload, SigningRequest, VmType};
pub use rule_set_policy::RuleSetPolicy;
pub use rules::{QuorumTrigger, RateLimitScope, Rule, RuleSet, VmShapeConstraints};
pub use static_policy::{AllowDefault, StaticAllowDenyPolicy};
pub use vm::{DecodedTx, VmDecoder};
