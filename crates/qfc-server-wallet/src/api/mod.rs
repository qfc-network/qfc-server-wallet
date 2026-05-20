//! HTTP API surface for `qfc-server-wallet` (M2 P1).
//!
//! Layout:
//!
//! - `auth`     — `X-API-Key` middleware + helpers
//! - `error`    — `ApiError` -> HTTP status mapping with a uniform
//!   `{error, hint}` body
//! - `schemas`  — wire DTOs (request / response shapes) annotated for
//!   `utoipa`
//! - `handlers` — per-endpoint functions + the `ApiDoc` derive
//!
//! The router is built by `router()` and consumed either by `main.rs`
//! (the binary) or by `tests/api.rs` (integration tests that drive the
//! `axum::Router::oneshot` path).
//!
//! Lint allowances scoped to this module: the per-handler `# Errors`
//! sections live in the OpenAPI schema (utoipa attribute macros), not in
//! rustdoc, so the `missing_errors_doc` lint is noisy here. `OpenAPI` /
//! `axum` proper-noun spellings would otherwise trip `doc_markdown` on
//! every doc comment.
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::double_must_use)]

pub mod auth;
pub mod error;
pub mod handlers;
pub mod schemas;

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use axum::middleware;
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::Router;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::service::WalletService;

/// Shared application state. Every handler receives this by `State`.
#[derive(Clone)]
pub struct AppState {
    /// The orchestrator. Cheap to clone (it holds `Arc`s internally).
    pub service: Arc<WalletService>,
    /// Set of accepted `X-API-Key` values. Membership is constant-time.
    pub api_keys: Arc<HashSet<String>>,
    /// On-disk path to the `FileAuditSink` NDJSON file. Read by the
    /// `GET /audit/events` handler.
    pub audit_path: PathBuf,
}

/// Build the public `axum::Router`. Returns a fully composed app — auth
/// middleware applied to every route except `/health`, `/metrics`, and
/// the OpenAPI documentation endpoints.
///
/// The split is `protected.merge(public)` so the open-access routes are
/// invisible to the auth layer.
#[must_use]
pub fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/wallets", post(handlers::create_wallet))
        .route("/wallets/:id", get(handlers::get_wallet))
        .route("/wallets/:id/sign", post(handlers::sign))
        .route("/audit/events", get(handlers::list_audit_events))
        .route(
            "/approvers",
            post(handlers::create_approver).get(handlers::list_approvers),
        )
        .route(
            "/approvers/:id",
            get(handlers::get_approver).delete(handlers::revoke_approver),
        )
        .route(
            "/approver-sets",
            post(handlers::create_approver_set).get(handlers::list_approver_sets),
        )
        .route("/approver-sets/:id", get(handlers::get_approver_set))
        .route(
            "/requests/:request_id/approvals",
            post(handlers::submit_approval).get(handlers::list_approvals),
        )
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_api_key,
        ));

    let public = Router::new()
        .route("/health", get(handlers::health))
        .route("/metrics", get(handlers::metrics))
        // Convenience redirect: `/` → Swagger UI so a stray browser hit
        // lands on the docs instead of 404.
        .route("/", get(|| async { Redirect::permanent("/docs") }));

    // SwaggerUi registers BOTH `/docs/*` and `/openapi.json`, so we don't
    // add a separate /openapi.json route — it would clash.
    protected
        .merge(public)
        .merge(SwaggerUi::new("/docs").url("/openapi.json", handlers::ApiDoc::openapi()))
        .with_state(state)
}
