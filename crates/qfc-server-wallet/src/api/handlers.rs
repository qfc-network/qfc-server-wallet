//! HTTP handlers.
//!
//! Each handler is a thin translator: deserialize the DTO, lower it to
//! the domain type, call `WalletService`, and re-encode the result. The
//! actual orchestration logic lives in `service.rs`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use qfc_audit::AuditEvent;
use qfc_wallet_types::WalletId;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use utoipa::OpenApi;

use super::error::{ApiError, ApiErrorBody};
use super::schemas::{
    AuditEventView, AuditEventsQuery, AuditKindDto, CreateWalletRequest, HashAlgDto, RequesterDto,
    SignRequest, SignResponse, SigningContextDto, SigningPayloadDto, SigningSchemeDto, VmTypeDto,
    WalletStatusDto, WalletView,
};
use super::AppState;
use qfc_audit::Actor as AuditActor;

/// `POST /wallets` — create a new wallet.
#[utoipa::path(
    post,
    path = "/wallets",
    tag = "wallets",
    request_body = CreateWalletRequest,
    security(("api_key" = [])),
    responses(
        (status = 201, description = "Wallet created", body = WalletView),
        (status = 400, description = "Malformed request body", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 500, description = "Backend failure", body = ApiErrorBody),
    ),
)]
pub async fn create_wallet(
    State(state): State<AppState>,
    Json(req): Json<CreateWalletRequest>,
) -> Result<(StatusCode, Json<WalletView>), ApiError> {
    let config = req.into_config()?;
    let record = state
        .service
        .create_wallet(config, AuditActor::System)
        .await?;
    Ok((StatusCode::CREATED, Json(WalletView::from(record))))
}

/// `GET /wallets/{id}` — fetch a wallet by ULID.
#[utoipa::path(
    get,
    path = "/wallets/{id}",
    tag = "wallets",
    params(("id" = String, Path, description = "Wallet ULID")),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Wallet record", body = WalletView),
        (status = 400, description = "Malformed wallet id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Wallet not found", body = ApiErrorBody),
    ),
)]
pub async fn get_wallet(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<WalletView>, ApiError> {
    let wallet_id = id
        .parse::<WalletId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid wallet_id: {e}")))?;
    let record = state.service.get_wallet(wallet_id).await?;
    Ok(Json(WalletView::from(record)))
}

/// `POST /wallets/{id}/sign` — sign a payload under wallet `{id}`.
#[utoipa::path(
    post,
    path = "/wallets/{id}/sign",
    tag = "wallets",
    params(("id" = String, Path, description = "Wallet ULID")),
    request_body = SignRequest,
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Signature produced", body = SignResponse),
        (status = 400, description = "Malformed request", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 403, description = "Policy denied", body = ApiErrorBody),
        (status = 404, description = "Wallet not found", body = ApiErrorBody),
        (status = 409, description = "Quorum failed", body = ApiErrorBody),
        (status = 500, description = "Backend failure", body = ApiErrorBody),
    ),
)]
pub async fn sign(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, ApiError> {
    let wallet_id = id
        .parse::<WalletId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid wallet_id: {e}")))?;
    let hd_path = req.hd_path_parsed()?;
    let hash_alg = req.hash_alg;
    let context = req.context.unwrap_or_default().into();
    let requester = req.requester.into_domain()?;
    let payload = req.payload.into_domain()?;

    let resp = state
        .service
        .sign(
            wallet_id,
            payload,
            requester,
            hd_path,
            context,
            hash_alg.into(),
        )
        .await?;

    let attestation = serde_json::to_value(&resp.attestation)
        .map_err(|e| ApiError::Internal(format!("attestation encode: {e}")))?;
    Ok(Json(SignResponse {
        signature_hex: hex::encode(&resp.signature),
        public_key_hex: hex::encode(&resp.public_key),
        attestation,
    }))
}

/// `GET /audit/events` — query the local NDJSON audit log.
///
/// Reads the on-disk audit file end-to-end. M2 P1 expects modest log
/// sizes (single-process, single-file); the Postgres-backed
/// `pg_audit_sink` lands in M2 P2 and replaces this.
#[utoipa::path(
    get,
    path = "/audit/events",
    tag = "audit",
    params(AuditEventsQuery),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Recent audit events (most recent last)", body = [AuditEventView]),
        (status = 400, description = "Malformed query", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 500, description = "Failed to read audit log", body = ApiErrorBody),
    ),
)]
pub async fn list_audit_events(
    State(state): State<AppState>,
    Query(q): Query<AuditEventsQuery>,
) -> Result<Json<Vec<AuditEventView>>, ApiError> {
    let wallet_filter = match &q.wallet_id {
        Some(s) => Some(
            s.parse::<WalletId>()
                .map_err(|e| ApiError::BadRequest(format!("invalid wallet_id: {e}")))?,
        ),
        None => None,
    };
    let limit = q.limit.unwrap_or(100).min(1000);

    let events = read_audit_events(&state.audit_path, wallet_filter, limit).await?;
    Ok(Json(events.into_iter().map(AuditEventView::from).collect()))
}

async fn read_audit_events(
    path: &std::path::Path,
    wallet_filter: Option<WalletId>,
    limit: usize,
) -> Result<Vec<AuditEvent>, ApiError> {
    // If the file does not exist yet (no events emitted), return empty
    // gracefully rather than 500-ing.
    let file = match File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(ApiError::Internal(format!("audit open: {e}"))),
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut events: Vec<AuditEvent> = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| ApiError::Internal(format!("audit read: {e}")))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent = serde_json::from_str(trimmed)
            .map_err(|e| ApiError::Internal(format!("audit parse: {e}")))?;
        if let Some(w) = wallet_filter {
            if event.wallet_id != Some(w) {
                continue;
            }
        }
        events.push(event);
    }
    // Keep the most recent `limit`. NDJSON is append-only and event_id is
    // monotonic ULID — file order *is* chronological — so we trim from the
    // front.
    if events.len() > limit {
        let drop = events.len() - limit;
        events.drain(0..drop);
    }
    Ok(events)
}

/// `GET /health` — liveness probe. Always 200 when the process is up.
#[utoipa::path(
    get,
    path = "/health",
    tag = "ops",
    responses((status = 200, description = "Service healthy"))
)]
pub async fn health() -> &'static str {
    "ok"
}

/// `GET /metrics` — placeholder for the Prometheus exporter that M2 P5
/// will install. Returns an empty exposition so scrape configs can be
/// wired up early.
#[utoipa::path(
    get,
    path = "/metrics",
    tag = "ops",
    responses((status = 200, description = "Prometheus exposition (placeholder)"))
)]
pub async fn metrics() -> &'static str {
    "# placeholder for M2 P5\n"
}

/// OpenAPI document covering every public route. Served at
/// `/openapi.json`; the bundled Swagger UI consumes it at `/docs`.
#[derive(OpenApi)]
#[openapi(
    paths(
        create_wallet,
        get_wallet,
        sign,
        list_audit_events,
        health,
        metrics,
    ),
    components(
        schemas(
            ApiErrorBody,
            CreateWalletRequest,
            WalletView,
            SignRequest,
            SignResponse,
            AuditEventsQuery,
            AuditEventView,
            RequesterDto,
            SigningPayloadDto,
            SigningContextDto,
            AuditKindDto,
            WalletStatusDto,
            SigningSchemeDto,
            HashAlgDto,
            VmTypeDto,
        )
    ),
    tags(
        (name = "wallets", description = "Wallet lifecycle and signing"),
        (name = "audit", description = "Audit log query"),
        (name = "ops", description = "Operational endpoints"),
    ),
    modifiers(&SecurityAddon),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
            );
        }
    }
}
