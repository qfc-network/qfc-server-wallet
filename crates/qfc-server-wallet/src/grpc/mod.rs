//! gRPC API surface for `qfc-server-wallet` (RFC decision #7).
//!
//! Mirrors the HTTP routes onto the same `WalletService` handler core.
//! There is *zero* logic duplication: each gRPC handler unwraps the proto
//! request, lowers it via `convert::*`, calls into `Arc<WalletService>`,
//! and re-encodes the response as a proto.
//!
//! Layout:
//!
//! - [`convert`] — proto ↔ domain conversion helpers
//! - [`auth`]    — `x-api-key` metadata interceptor (HTTP-parity)
//! - [`wallet`]  — `Wallet` service impl (CreateWallet / GetWallet / Sign / GetAuditEvents)
//! - [`approver`] — `Approver` service impl (M4 quorum surface)
//!
//! Wire on the binary via [`build_router`] which returns a fully-composed
//! `tonic` server. `main.rs` runs it concurrently with the axum HTTP server.
//!
//! Auto-generated proto code is pulled in below via `tonic::include_proto!`.
//! It lives in `OUT_DIR` and is not committed; rebuilds happen any time a
//! `proto/*.proto` file changes.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
// Generated proto code triggers a handful of pedantic lints — these are
// scoped to this module rather than the crate root so the rest of the
// crate keeps its strict lint posture.
#![allow(clippy::pedantic)]

pub mod approver;
pub mod auth;
pub mod convert;
pub mod wallet;

/// Auto-generated protobuf + tonic types for `qfc.wallet.v1`.
///
/// This module re-exports the `tonic-build` output (server stubs, client
/// stubs, message structs, enum types) so consumers don't have to know
/// the on-disk codegen layout.
pub mod proto {
    #![allow(clippy::all)]
    #![allow(clippy::pedantic)]
    #![allow(missing_docs)]
    #![allow(rustdoc::all)]
    tonic::include_proto!("qfc.wallet.v1");

    /// `FileDescriptorSet` bytes for the three protos. Fed into
    /// `tonic-reflection` so `grpcurl` can list services in dev.
    pub const FILE_DESCRIPTOR_SET: &[u8] =
        include_bytes!(concat!(env!("OUT_DIR"), "/qfc_descriptor.bin"));
}

use std::sync::Arc;

use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::Router;
use tonic::transport::Server;

use crate::api::AppState;
use crate::grpc::approver::ApproverServiceImpl;
use crate::grpc::auth::ApiKeyInterceptor;
use crate::grpc::wallet::WalletServiceImpl;
use proto::approver_server::ApproverServer;
use proto::wallet_server::WalletServer;

/// Returned by [`build_router`] so `main.rs` knows whether reflection was
/// actually wired (operators can disable it in prod).
#[derive(Clone, Copy, Debug)]
pub struct GrpcOptions {
    /// When `true`, expose the `grpc.reflection.v1alpha.ServerReflection`
    /// service so `grpcurl` / `evans` can introspect the schema without
    /// compiled stubs. Off in prod via the `--no-reflection` CLI flag.
    pub reflection: bool,
}

impl Default for GrpcOptions {
    fn default() -> Self {
        Self { reflection: true }
    }
}

/// Build a `tonic` server router holding the Wallet + Approver services,
/// the `x-api-key` auth interceptor, and (optionally) reflection.
///
/// The returned router is ready to call `.serve(addr)` on. Callers wire
/// graceful shutdown themselves so the HTTP server and the gRPC server can
/// share a single signal future.
#[must_use]
pub fn build_router(state: Arc<AppState>, opts: GrpcOptions) -> Router {
    let wallet_svc = WalletServiceImpl::new(state.clone());
    let approver_svc = ApproverServiceImpl::new(state.clone());
    let interceptor = ApiKeyInterceptor::new(state.api_keys.clone());

    let mut server = Server::builder()
        .add_service(InterceptedService::new(
            WalletServer::new(wallet_svc),
            interceptor.clone(),
        ))
        .add_service(InterceptedService::new(
            ApproverServer::new(approver_svc),
            interceptor,
        ));

    #[cfg(feature = "reflection")]
    {
        if opts.reflection {
            server = add_reflection(server);
        }
    }
    // Suppress the "unused on `--no-default-features`" warning.
    let _ = opts;
    server
}

#[cfg(feature = "reflection")]
fn add_reflection(server: Router) -> Router {
    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(proto::FILE_DESCRIPTOR_SET)
        .build_v1()
        .expect("tonic-reflection build_v1 should succeed against our static descriptor set");
    server.add_service(reflection)
}
