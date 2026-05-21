//! `Approver` gRPC service impl.
//!
//! Wraps the same `Arc<WalletService>` the HTTP layer uses — registry +
//! approval-store calls go through `WalletService::approver_registry` /
//! `WalletService::approval_store` for the read paths, and
//! `WalletService::record_approval` for the verify-and-persist path. Zero
//! logic duplication.
#![allow(clippy::result_large_err)] // tonic::Status is intrinsically ~176B

use std::sync::Arc;

use qfc_quorum::ApproverCreate;
use qfc_wallet_types::{ApproverId, ApproverSetId, OwnerId, RequestId};
use tonic::{Request, Response, Status};

use crate::api::AppState;
use crate::grpc::convert::{
    lower_approver_identity, lower_create_approver_set, lower_submit_approval, map_registry_error,
    map_service_error, parse_ulid, raise_approver_record, raise_approver_set,
    raise_signed_approval, require_field,
};
use crate::grpc::proto;
use proto::approver_server::Approver;

/// gRPC adapter for the approver / approval admin surface.
pub struct ApproverServiceImpl {
    state: Arc<AppState>,
}

impl ApproverServiceImpl {
    /// Build a new adapter sharing state with the HTTP server.
    #[must_use]
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl Approver for ApproverServiceImpl {
    async fn register_approver(
        &self,
        request: Request<proto::RegisterApproverRequest>,
    ) -> Result<Response<proto::RegisterApproverResponse>, Status> {
        let req = request.into_inner();
        let identity = lower_approver_identity(require_field("identity", req.identity)?)?;
        let webhook_url = if req.webhook_url.is_empty() {
            None
        } else {
            Some(req.webhook_url)
        };
        let create = ApproverCreate {
            identity,
            label: req.label,
            owner_id: OwnerId::new(req.owner_id),
            webhook_url,
        };
        let record = self
            .state
            .service
            .approver_registry()
            .add_approver(create)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::RegisterApproverResponse {
            approver: Some(raise_approver_record(record)),
        }))
    }

    async fn revoke_approver(
        &self,
        request: Request<proto::RevokeApproverRequest>,
    ) -> Result<Response<proto::RevokeApproverResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid::<ApproverId>("approver_id", &req.approver_id)?;
        self.state
            .service
            .approver_registry()
            .revoke_approver(id)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::RevokeApproverResponse {}))
    }

    async fn get_approver(
        &self,
        request: Request<proto::GetApproverRequest>,
    ) -> Result<Response<proto::GetApproverResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid::<ApproverId>("approver_id", &req.approver_id)?;
        let rec = self
            .state
            .service
            .approver_registry()
            .get_approver(id)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::GetApproverResponse {
            approver: Some(raise_approver_record(rec)),
        }))
    }

    async fn list_approvers(
        &self,
        request: Request<proto::ListApproversRequest>,
    ) -> Result<Response<proto::ListApproversResponse>, Status> {
        let req = request.into_inner();
        let owner = OwnerId::new(req.owner);
        let recs = self
            .state
            .service
            .approver_registry()
            .list_approvers_by_owner(&owner, req.include_revoked)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::ListApproversResponse {
            approvers: recs.into_iter().map(raise_approver_record).collect(),
        }))
    }

    async fn create_approver_set(
        &self,
        request: Request<proto::CreateApproverSetRequest>,
    ) -> Result<Response<proto::CreateApproverSetResponse>, Status> {
        let req = request.into_inner();
        let create = lower_create_approver_set(req)?;
        let set = self
            .state
            .service
            .approver_registry()
            .create_approver_set(create)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::CreateApproverSetResponse {
            approver_set: Some(raise_approver_set(set)),
        }))
    }

    async fn get_approver_set(
        &self,
        request: Request<proto::GetApproverSetRequest>,
    ) -> Result<Response<proto::GetApproverSetResponse>, Status> {
        let req = request.into_inner();
        let id = parse_ulid::<ApproverSetId>("approver_set_id", &req.approver_set_id)?;
        let set = self
            .state
            .service
            .approver_registry()
            .get_approver_set(id)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::GetApproverSetResponse {
            approver_set: Some(raise_approver_set(set)),
        }))
    }

    async fn list_approver_sets(
        &self,
        request: Request<proto::ListApproverSetsRequest>,
    ) -> Result<Response<proto::ListApproverSetsResponse>, Status> {
        let req = request.into_inner();
        let owner = OwnerId::new(req.owner);
        let sets = self
            .state
            .service
            .approver_registry()
            .list_approver_sets(&owner)
            .await
            .map_err(map_registry_error)?;
        Ok(Response::new(proto::ListApproverSetsResponse {
            approver_sets: sets.into_iter().map(raise_approver_set).collect(),
        }))
    }

    async fn submit_approval(
        &self,
        request: Request<proto::SubmitApprovalRequest>,
    ) -> Result<Response<proto::SubmitApprovalResponse>, Status> {
        let req = request.into_inner();
        let approval_id_echo = req.approval_id.clone();
        let (signed, approver_id, expected_hash) = lower_submit_approval(req)?;
        let outcome = self
            .state
            .service
            .record_approval(signed, approver_id, expected_hash)
            .await
            .map_err(map_service_error)?;
        Ok(Response::new(proto::SubmitApprovalResponse {
            recorded: matches!(outcome, qfc_quorum::RecordOutcome::Inserted),
            approval_id: approval_id_echo,
        }))
    }

    async fn list_approvals(
        &self,
        request: Request<proto::ListApprovalsRequest>,
    ) -> Result<Response<proto::ListApprovalsResponse>, Status> {
        let req = request.into_inner();
        let request_id = parse_ulid::<RequestId>("request_id", &req.request_id)?;
        let approvals = self
            .state
            .service
            .approval_store()
            .list_for_request(request_id)
            .await
            .map_err(|e| Status::internal(format!("approval store: {e}")))?;
        Ok(Response::new(proto::ListApprovalsResponse {
            approvals: approvals.into_iter().map(raise_signed_approval).collect(),
        }))
    }
}
