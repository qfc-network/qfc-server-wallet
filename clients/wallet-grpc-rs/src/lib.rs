//! `qfc-wallet-grpc` — reference Rust gRPC client SDK for the QFC
//! server wallet.
//!
//! This crate is a stand-alone library that wraps the `tonic`-generated
//! client stubs for the `qfc.wallet.v1` package with ergonomic builders,
//! typed errors, and a client-side `x-api-key` interceptor. It is
//! deliberately **outside the main workspace** (mirroring
//! `clients/approver-rs/`) so production integrators can fork this
//! directory without inheriting the wallet's dep tree.
//!
//! ## Quickstart
//!
//! ```no_run
//! use qfc_wallet_grpc::{WalletClient, CreateWalletParams, SigningScheme};
//! # async fn run() -> Result<(), qfc_wallet_grpc::SdkError> {
//! let mut client = WalletClient::connect("http://127.0.0.1:9090")
//!     .api_key("dev-key-1")
//!     .wallet()
//!     .await?;
//!
//! let wallet = client
//!     .create_wallet(CreateWalletParams {
//!         scheme: SigningScheme::Ed25519,
//!         threshold: 2,
//!         total: 3,
//!         display_name: "demo".into(),
//!         owner_id: "tenant-a".into(),
//!         policy_id: None,
//!     })
//!     .await?;
//! println!("wallet_id: {}", wallet.wallet_id);
//! # Ok(()) }
//! ```
//!
//! See `examples/` for runnable demos of every supported flow.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![warn(clippy::pedantic)]
// Generated proto code triggers a handful of pedantic lints; allow them
// only inside the `proto` module below.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
// `SdkError` embeds `tonic::Status` (~176 B) in its `Rpc` variant.
// Boxing it would force every call site to unbox, defeat the auto-impls
// the generated client stubs rely on, and break the standard tonic
// ergonomics. Server-side allows the same lint with the same rationale
// (see `docs/grpc-decisions.md` D49 / D58).
#![allow(clippy::result_large_err)]

pub mod auth;
pub mod client;
pub mod convert;
pub mod error;

/// Auto-generated protobuf + tonic types for `qfc.wallet.v1`.
///
/// Re-exported so callers building advanced flows can reach for raw
/// proto messages when the ergonomic wrapper isn't enough. Most users
/// should reach for the re-exports in [`crate::convert`] instead.
pub mod proto {
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]
    #![allow(missing_docs)]
    #![allow(rustdoc::all)]
    tonic::include_proto!("qfc.wallet.v1");
}

// ---------------------------------------------------------------------------
// Crate-root re-exports (the public surface most users will touch).
// ---------------------------------------------------------------------------

pub use auth::{ApiKeyInterceptor, API_KEY_HEADER};
pub use client::{ApproverClient, ClientBuilder, WalletClient};
pub use convert::{
    approver_identity, requester, signing_payload, ApprovalDecision, ApprovalView,
    ApproverIdentity, ApproverSetView, ApproverStatus, ApproverView, AuditEventView,
    AuditEventsQuery, AuditKind, CreateApproverSetParams, CreateWalletParams, HashAlg,
    RegisterApproverParams, Requester, SignParams, Signed, SigningContext, SigningPayload,
    SigningScheme, SubmitApprovalParams, VmType, WalletStatus, WalletView,
};
pub use error::SdkError;
