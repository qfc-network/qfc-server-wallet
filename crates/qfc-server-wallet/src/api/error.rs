//! HTTP error mapping for the API surface.
//!
//! Translates `ServiceError` (and a small set of API-only failure modes —
//! auth, bad JSON) into uniform JSON `{error, hint}` responses with the
//! status codes documented in the M2 P1 task.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::service::ServiceError;

/// Uniform error body returned by every non-2xx response. The hint is a
/// short operator-facing diagnostic; it MUST NOT leak secret material.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ApiErrorBody {
    /// Stable kebab-case classification (`wallet_not_found`, `unauthorized`,
    /// `policy_denied`, `quorum_failed`, `bad_request`, `internal_error`).
    pub error: String,
    /// Human-readable diagnostic. Safe to surface to API consumers.
    pub hint: String,
}

/// API-layer error envelope. Convertible from `ServiceError` and from the
/// auth / parsing failures the handlers raise directly.
#[derive(Debug)]
pub enum ApiError {
    /// 400 — request body / query parameters could not be parsed.
    BadRequest(String),
    /// 401 — missing or invalid `X-API-Key`.
    Unauthorized(String),
    /// 403 — policy denied the operation.
    Forbidden(String),
    /// 404 — wallet or other resource not found.
    NotFound(String),
    /// 409 — quorum collection failed (timeout, reject, …) or duplicate approval.
    Conflict(String),
    /// 422 — semantically invalid request (e.g. unverified signature).
    UnprocessableEntity(String),
    /// 500 — anything else (enclave fault, store I/O, audit I/O, …).
    Internal(String),
}

impl ApiError {
    fn parts(&self) -> (StatusCode, &'static str, &str) {
        match self {
            Self::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m.as_str()),
            Self::Unauthorized(m) => (StatusCode::UNAUTHORIZED, "unauthorized", m.as_str()),
            Self::Forbidden(m) => (StatusCode::FORBIDDEN, "policy_denied", m.as_str()),
            Self::NotFound(m) => (StatusCode::NOT_FOUND, "wallet_not_found", m.as_str()),
            Self::Conflict(m) => (StatusCode::CONFLICT, "quorum_failed", m.as_str()),
            Self::UnprocessableEntity(m) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                "approval_verification_failed",
                m.as_str(),
            ),
            Self::Internal(m) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                m.as_str(),
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error, hint) = self.parts();
        let body = ApiErrorBody {
            error: error.to_string(),
            hint: hint.to_string(),
        };
        (status, Json(body)).into_response()
    }
}

impl From<ServiceError> for ApiError {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::WalletNotFound(id) => Self::NotFound(format!("wallet {id} not found")),
            ServiceError::PolicyDenied(msg) => Self::Forbidden(msg),
            ServiceError::Quorum(e) => Self::Conflict(e.to_string()),
            ServiceError::Enclave(e) => Self::Internal(format!("enclave: {e}")),
            ServiceError::Audit(e) => Self::Internal(format!("audit: {e}")),
            ServiceError::Store(e) => Self::Internal(format!("store: {e}")),
            ServiceError::Policy(e) => Self::Internal(format!("policy: {e}")),
            ServiceError::InsufficientShares(e) => Self::Internal(format!("shares: {e}")),
        }
    }
}
