//! `Wallet` gRPC service impl.
//!
//! Wraps the same `Arc<WalletService>` the HTTP layer uses. Each RPC is a
//! thin lower → call → raise translator; the orchestration logic stays in
//! `service.rs`.
#![allow(clippy::result_large_err)] // tonic::Status is intrinsically ~176B

use std::path::PathBuf;
use std::sync::Arc;

use qfc_audit::Actor as AuditActor;
use qfc_audit::AuditEvent;
use qfc_wallet_types::WalletId;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt, BufReader};
use tonic::{Request, Response, Status};

use crate::api::AppState;
use crate::grpc::convert::{
    hash_alg_from_i32, lower_context, lower_create_wallet, lower_hd_path, lower_payload,
    lower_requester, map_service_error, parse_ulid, raise_audit_event, raise_wallet_view,
    require_field,
};
use crate::grpc::proto;
use proto::wallet_server::Wallet;

/// gRPC adapter over `Arc<WalletService>`.
pub struct WalletServiceImpl {
    state: Arc<AppState>,
}

impl WalletServiceImpl {
    /// Build a new adapter sharing state with the HTTP server.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Wallet for WalletServiceImpl {
    async fn create_wallet(
        &self,
        request: Request<proto::CreateWalletRequest>,
    ) -> Result<Response<proto::CreateWalletResponse>, Status> {
        let req = request.into_inner();
        let config = lower_create_wallet(req)?;
        let record = self
            .state
            .service
            .create_wallet(config, AuditActor::System)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::CreateWalletResponse {
            wallet: Some(raise_wallet_view(record)),
        }))
    }

    async fn get_wallet(
        &self,
        request: Request<proto::GetWalletRequest>,
    ) -> Result<Response<proto::GetWalletResponse>, Status> {
        let req = request.into_inner();
        let wallet_id = parse_ulid::<WalletId>("wallet_id", &req.wallet_id)?;
        let record = self
            .state
            .service
            .get_wallet(wallet_id)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::GetWalletResponse {
            wallet: Some(raise_wallet_view(record)),
        }))
    }

    async fn sign(
        &self,
        request: Request<proto::SignRequest>,
    ) -> Result<Response<proto::SignResponse>, Status> {
        let req = request.into_inner();
        let wallet_id = parse_ulid::<WalletId>("wallet_id", &req.wallet_id)?;
        let payload = lower_payload(require_field("payload", req.payload)?)?;
        let requester = lower_requester(require_field("requester", req.requester)?)?;
        let hd_path = lower_hd_path(&req.hd_path)?;
        let hash_alg = hash_alg_from_i32(req.hash_alg)?;
        let context = lower_context(req.context)?;

        let resp = self
            .state
            .service
            .sign(wallet_id, payload, requester, hd_path, context, hash_alg)
            .await
            .map_err(map_service_error)?;

        let attestation_json = serde_json::to_string(&resp.attestation)
            .map_err(|e| Status::internal(format!("attestation encode: {e}")))?;
        Ok(Response::new(proto::SignResponse {
            signature: resp.signature,
            public_key: resp.public_key,
            attestation_json,
        }))
    }

    async fn get_audit_events(
        &self,
        request: Request<proto::GetAuditEventsRequest>,
    ) -> Result<Response<proto::GetAuditEventsResponse>, Status> {
        let req = request.into_inner();
        let wallet_filter = if req.wallet_id.is_empty() {
            None
        } else {
            Some(parse_ulid::<WalletId>("wallet_id", &req.wallet_id)?)
        };
        // Default 100, hard cap 1000 — same as the HTTP handler.
        let limit_raw = if req.limit == 0 { 100 } else { req.limit };
        let limit = (limit_raw as usize).min(1000);

        let events = read_audit_events(&self.state.audit_path, wallet_filter, limit)
            .await
            .map_err(|e| Status::internal(format!("audit read: {e}")))?;

        Ok(Response::new(proto::GetAuditEventsResponse {
            events: events.into_iter().map(raise_audit_event).collect(),
        }))
    }
}

/// File-tailing read of the NDJSON audit log. Mirrors the HTTP handler's
/// implementation in `api::handlers::read_audit_events`. Kept private so
/// the two surfaces don't accidentally diverge — both surfaces are
/// expected to retire this in favor of `pg_audit_sink` once M2 P2 lands.
async fn read_audit_events(
    path: &PathBuf,
    wallet_filter: Option<WalletId>,
    limit: usize,
) -> Result<Vec<AuditEvent>, String> {
    let file = match File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("audit open: {e}")),
    };
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut events: Vec<AuditEvent> = Vec::new();
    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("audit read: {e}"))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches('\n');
        if trimmed.is_empty() {
            continue;
        }
        let event: AuditEvent =
            serde_json::from_str(trimmed).map_err(|e| format!("audit parse: {e}"))?;
        if let Some(w) = wallet_filter {
            if event.wallet_id != Some(w) {
                continue;
            }
        }
        events.push(event);
    }
    if events.len() > limit {
        let drop = events.len() - limit;
        events.drain(0..drop);
    }
    Ok(events)
}
