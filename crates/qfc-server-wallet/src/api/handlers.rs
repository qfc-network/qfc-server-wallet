//! HTTP handlers.
//!
//! Each handler is a thin translator: deserialize the DTO, lower it to
//! the domain type, call `WalletService`, and re-encode the result. The
//! actual orchestration logic lives in `service.rs`.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use qfc_audit::AuditEvent;
use qfc_wallet_types::{ApproverId, ApproverSetId, OwnerId, RequestId, WalletId};
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use utoipa::OpenApi;

use super::error::{ApiError, ApiErrorBody};
use super::schemas::{
    ApprovalDecisionDto, ApprovalView, ApproverIdentityDto, ApproverSetView, ApproverStatusDto,
    ApproverView, AuditEventView, AuditEventsQuery, AuditKindDto, CreateApproverRequest,
    CreateApproverSetRequest, CreateWalletRequest, HashAlgDto, ListApproverSetsQuery,
    ListApproversQuery, RequesterDto, SignRequest, SignResponse, SigningContextDto,
    SigningPayloadDto, SigningSchemeDto, SubmitApprovalRequest, SubmitApprovalResponse, VmTypeDto,
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

// =============================================================================
// M4: approver registry + approval submission handlers
// =============================================================================

/// `POST /approvers` — register a new approver (admin).
#[utoipa::path(
    post,
    path = "/approvers",
    tag = "approvers",
    request_body = CreateApproverRequest,
    security(("api_key" = [])),
    responses(
        (status = 201, description = "Approver created", body = ApproverView),
        (status = 400, description = "Malformed body", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 500, description = "Backend failure", body = ApiErrorBody),
    ),
)]
pub async fn create_approver(
    State(state): State<AppState>,
    Json(body): Json<CreateApproverRequest>,
) -> Result<(StatusCode, Json<ApproverView>), ApiError> {
    let identity = body.identity.into_domain()?;
    let create = qfc_quorum::ApproverCreate {
        identity,
        label: body.label,
        owner_id: OwnerId::new(body.owner_id),
        webhook_url: body.webhook_url,
    };
    let record = state
        .service
        .approver_registry()
        .add_approver(create)
        .await
        .map_err(map_registry_err)?;
    Ok((StatusCode::CREATED, Json(ApproverView::from(record))))
}

/// `DELETE /approvers/{id}` — revoke an approver.
#[utoipa::path(
    delete,
    path = "/approvers/{id}",
    tag = "approvers",
    params(("id" = String, Path, description = "Approver ULID")),
    security(("api_key" = [])),
    responses(
        (status = 204, description = "Approver revoked"),
        (status = 400, description = "Malformed id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Approver not found", body = ApiErrorBody),
    ),
)]
pub async fn revoke_approver(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let approver_id = id
        .parse::<ApproverId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid approver_id: {e}")))?;
    state
        .service
        .approver_registry()
        .revoke_approver(approver_id)
        .await
        .map_err(map_registry_err)?;
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /approvers/{id}` — fetch one approver.
#[utoipa::path(
    get,
    path = "/approvers/{id}",
    tag = "approvers",
    params(("id" = String, Path, description = "Approver ULID")),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Approver record", body = ApproverView),
        (status = 400, description = "Malformed id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Approver not found", body = ApiErrorBody),
    ),
)]
pub async fn get_approver(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApproverView>, ApiError> {
    let approver_id = id
        .parse::<ApproverId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid approver_id: {e}")))?;
    let rec = state
        .service
        .approver_registry()
        .get_approver(approver_id)
        .await
        .map_err(map_registry_err)?;
    Ok(Json(ApproverView::from(rec)))
}

/// `GET /approvers?owner=...` — list approvers for a tenant.
#[utoipa::path(
    get,
    path = "/approvers",
    tag = "approvers",
    params(ListApproversQuery),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Approvers list", body = [ApproverView]),
        (status = 400, description = "Missing owner", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
    ),
)]
pub async fn list_approvers(
    State(state): State<AppState>,
    Query(q): Query<ListApproversQuery>,
) -> Result<Json<Vec<ApproverView>>, ApiError> {
    let owner = OwnerId::new(q.owner);
    let include_revoked = q.include_revoked.unwrap_or(false);
    let recs = state
        .service
        .approver_registry()
        .list_approvers_by_owner(&owner, include_revoked)
        .await
        .map_err(map_registry_err)?;
    Ok(Json(recs.into_iter().map(ApproverView::from).collect()))
}

/// `POST /approver-sets` — create a new M-of-N set.
#[utoipa::path(
    post,
    path = "/approver-sets",
    tag = "approvers",
    request_body = CreateApproverSetRequest,
    security(("api_key" = [])),
    responses(
        (status = 201, description = "Set created", body = ApproverSetView),
        (status = 400, description = "Malformed body", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 422, description = "Cycle / depth / invalid threshold", body = ApiErrorBody),
        (status = 500, description = "Backend failure", body = ApiErrorBody),
    ),
)]
pub async fn create_approver_set(
    State(state): State<AppState>,
    Json(req): Json<CreateApproverSetRequest>,
) -> Result<(StatusCode, Json<ApproverSetView>), ApiError> {
    let domain = req.into_domain()?;
    let set = state
        .service
        .approver_registry()
        .create_approver_set(domain)
        .await
        .map_err(map_registry_err)?;
    Ok((StatusCode::CREATED, Json(ApproverSetView::from(set))))
}

/// `GET /approver-sets/{id}` — fetch a set by id.
#[utoipa::path(
    get,
    path = "/approver-sets/{id}",
    tag = "approvers",
    params(("id" = String, Path, description = "Approver-set ULID")),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Set", body = ApproverSetView),
        (status = 400, description = "Malformed id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Set not found", body = ApiErrorBody),
    ),
)]
pub async fn get_approver_set(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApproverSetView>, ApiError> {
    let set_id = id
        .parse::<ApproverSetId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid approver_set_id: {e}")))?;
    let set = state
        .service
        .approver_registry()
        .get_approver_set(set_id)
        .await
        .map_err(map_registry_err)?;
    Ok(Json(ApproverSetView::from(set)))
}

/// `GET /approver-sets?owner=...` — list sets for a tenant.
#[utoipa::path(
    get,
    path = "/approver-sets",
    tag = "approvers",
    params(ListApproverSetsQuery),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Sets list", body = [ApproverSetView]),
        (status = 400, description = "Missing owner", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
    ),
)]
pub async fn list_approver_sets(
    State(state): State<AppState>,
    Query(q): Query<ListApproverSetsQuery>,
) -> Result<Json<Vec<ApproverSetView>>, ApiError> {
    let owner = OwnerId::new(q.owner);
    let sets = state
        .service
        .approver_registry()
        .list_approver_sets(&owner)
        .await
        .map_err(map_registry_err)?;
    Ok(Json(sets.into_iter().map(ApproverSetView::from).collect()))
}

/// `POST /requests/{request_id}/approvals` — submit a signed approval.
#[utoipa::path(
    post,
    path = "/requests/{request_id}/approvals",
    tag = "approvers",
    params(("request_id" = String, Path, description = "Signing-request ULID")),
    request_body = SubmitApprovalRequest,
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Recorded (or idempotent re-submission)", body = SubmitApprovalResponse),
        (status = 400, description = "Malformed body", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
        (status = 404, description = "Approver not found", body = ApiErrorBody),
        (status = 409, description = "Duplicate approval payload", body = ApiErrorBody),
        (status = 422, description = "Signature / freshness / binding failed", body = ApiErrorBody),
        (status = 500, description = "Backend failure", body = ApiErrorBody),
    ),
)]
pub async fn submit_approval(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
    Json(req): Json<SubmitApprovalRequest>,
) -> Result<Json<SubmitApprovalResponse>, ApiError> {
    let request_id = request_id
        .parse::<RequestId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid request_id: {e}")))?;
    let approval_id_str = req.approval_id.clone();
    let message_hash_hex = req.message_hash_hex.clone();
    let (signed, approver_id) = req.into_signed(request_id)?;
    let expected_hash: [u8; 32] = {
        let bytes = hex::decode(&message_hash_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid message_hash_hex: {e}")))?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ApiError::BadRequest("message_hash_hex must be 32 bytes".into()))?
    };
    let outcome = state
        .service
        .record_approval(signed, approver_id, expected_hash)
        .await
        .map_err(map_submit_err)?;
    Ok(Json(SubmitApprovalResponse {
        recorded: matches!(outcome, qfc_quorum::RecordOutcome::Inserted),
        approval_id: approval_id_str,
    }))
}

/// `GET /requests/{request_id}/approvals` — list approvals on record.
#[utoipa::path(
    get,
    path = "/requests/{request_id}/approvals",
    tag = "approvers",
    params(("request_id" = String, Path, description = "Signing-request ULID")),
    security(("api_key" = [])),
    responses(
        (status = 200, description = "Approvals list", body = [ApprovalView]),
        (status = 400, description = "Malformed id", body = ApiErrorBody),
        (status = 401, description = "Missing or invalid API key", body = ApiErrorBody),
    ),
)]
pub async fn list_approvals(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> Result<Json<Vec<ApprovalView>>, ApiError> {
    let request_id = request_id
        .parse::<RequestId>()
        .map_err(|e| ApiError::BadRequest(format!("invalid request_id: {e}")))?;
    let approvals = state
        .service
        .approval_store()
        .list_for_request(request_id)
        .await
        .map_err(|e| ApiError::Internal(format!("approval store: {e}")))?;
    Ok(Json(
        approvals.into_iter().map(ApprovalView::from).collect(),
    ))
}

#[allow(clippy::needless_pass_by_value)]
fn map_registry_err(err: qfc_quorum::RegistryError) -> ApiError {
    use qfc_quorum::RegistryError as R;
    let msg = err.to_string();
    match err {
        R::ApproverNotFound(_) | R::ApproverSetNotFound(_) => ApiError::NotFound(msg),
        R::UnknownMember(_)
        | R::RevokedMember(_)
        | R::MemberCountMismatch { .. }
        | R::InvalidThreshold { .. }
        | R::DuplicateMember(_)
        | R::NestingCycle(_)
        | R::NestingTooDeep(_) => ApiError::UnprocessableEntity(msg),
        R::Io(_) => ApiError::Internal(msg),
    }
}

fn map_submit_err(e: crate::service::ServiceError) -> ApiError {
    use crate::service::ServiceError as S;
    match e {
        S::Quorum(qfc_quorum::QuorumError::InvalidApproval(inner)) => {
            ApiError::UnprocessableEntity(format!("approval verification failed: {inner}"))
        }
        S::Quorum(qfc_quorum::QuorumError::UnknownApprover(msg)) => ApiError::NotFound(msg),
        S::Quorum(qfc_quorum::QuorumError::Transport(msg)) => {
            if msg.contains("duplicate approval") {
                ApiError::Conflict(msg)
            } else {
                ApiError::Internal(msg)
            }
        }
        other => other.into(),
    }
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
        create_approver,
        revoke_approver,
        get_approver,
        list_approvers,
        create_approver_set,
        get_approver_set,
        list_approver_sets,
        submit_approval,
        list_approvals,
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
            ApproverIdentityDto,
            ApproverStatusDto,
            CreateApproverRequest,
            ApproverView,
            CreateApproverSetRequest,
            ApproverSetView,
            ApprovalDecisionDto,
            SubmitApprovalRequest,
            SubmitApprovalResponse,
            ApprovalView,
        )
    ),
    tags(
        (name = "wallets", description = "Wallet lifecycle and signing"),
        (name = "audit", description = "Audit log query"),
        (name = "approvers", description = "Approver registry + approvals (M4 quorum)"),
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
