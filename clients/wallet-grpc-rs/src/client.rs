//! Ergonomic `WalletClient` + `ApproverClient` wrappers around the
//! `tonic`-generated stubs.
//!
//! The generated stubs (`proto::wallet_client::WalletClient<Channel>`,
//! `proto::approver_client::ApproverClient<Channel>`) work but require
//! the caller to:
//!
//!   * build their own `tonic::transport::Channel`;
//!   * remember to inject `x-api-key` into every `Request::metadata`;
//!   * decode `Option<*View>` envelopes by hand on every response.
//!
//! These wrappers do all of that. The builder pattern (`connect`)
//! mirrors the `reqwest::ClientBuilder` shape Rust developers expect.

use std::time::Duration;

use tonic::codegen::InterceptedService;
use tonic::transport::{Channel, Endpoint};

use crate::auth::ApiKeyInterceptor;
use crate::convert::{
    require, AuditEventView, AuditEventsQuery, CreateApproverSetParams, CreateWalletParams,
    RegisterApproverParams, SignParams, Signed, SubmitApprovalParams,
};
use crate::error::SdkError;
use crate::proto;

// Type aliases for the per-channel intercepted stubs. The aliases keep
// the public signatures readable: every method returns `Result<X,
// SdkError>` so callers never have to know about `tonic::Status` or
// `InterceptedService` in normal use.
type IntercepedChannel = InterceptedService<Channel, ApiKeyInterceptor>;
type InnerWalletClient = proto::wallet_client::WalletClient<IntercepedChannel>;
type InnerApproverClient = proto::approver_client::ApproverClient<IntercepedChannel>;

// ============================================================================
// Builder
// ============================================================================

/// Builder for either client type.
///
/// Constructed via [`WalletClient::connect`] / [`ApproverClient::connect`]
/// (which both delegate here). Fields are wired in one at a time; the
/// terminal `.wallet()` / `.approver()` call performs the actual TCP
/// connect.
#[derive(Debug, Clone)]
pub struct ClientBuilder {
    endpoint: String,
    api_key: Option<String>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
}

impl ClientBuilder {
    /// Start a builder targeting `endpoint` (e.g. `http://127.0.0.1:9090`).
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            api_key: None,
            timeout: None,
            connect_timeout: None,
        }
    }

    /// Set the `x-api-key` metadata value the interceptor will inject on
    /// every RPC. Required for any non-`/health` call against a real
    /// server.
    #[must_use]
    pub fn api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    /// Set a per-request timeout. Applies to the entire RPC (not just
    /// the TCP connect).
    #[must_use]
    pub fn timeout(mut self, d: Duration) -> Self {
        self.timeout = Some(d);
        self
    }

    /// Set a TCP connect timeout — distinct from the per-request timeout.
    #[must_use]
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = Some(d);
        self
    }

    /// Build the underlying channel + interceptor. Shared by both client
    /// variants — they're identical in transport setup.
    async fn build_channel(self) -> Result<(IntercepedChannel, Self), SdkError> {
        // We need the api_key for the interceptor but also want to keep
        // the rest of the builder around (mainly for symmetry / future
        // extension). Pull api_key out, then re-emit the builder.
        let api_key = self.api_key.clone().unwrap_or_default();
        let mut endpoint = Endpoint::from_shared(self.endpoint.clone())
            .map_err(|e| SdkError::BadInput(format!("invalid endpoint: {e}")))?;
        if let Some(d) = self.timeout {
            endpoint = endpoint.timeout(d);
        }
        if let Some(d) = self.connect_timeout {
            endpoint = endpoint.connect_timeout(d);
        }
        let channel = endpoint.connect().await?;
        let interceptor = ApiKeyInterceptor::new(api_key);
        Ok((InterceptedService::new(channel, interceptor), self))
    }

    /// Finalise as a `WalletClient`.
    pub async fn wallet(self) -> Result<WalletClient, SdkError> {
        let (ch, _) = self.build_channel().await?;
        Ok(WalletClient {
            inner: InnerWalletClient::new(ch),
        })
    }

    /// Finalise as an `ApproverClient`.
    pub async fn approver(self) -> Result<ApproverClient, SdkError> {
        let (ch, _) = self.build_channel().await?;
        Ok(ApproverClient {
            inner: InnerApproverClient::new(ch),
        })
    }
}

// ============================================================================
// WalletClient
// ============================================================================

/// Wallet RPC client. Wraps the tonic-generated stub and applies the
/// `x-api-key` interceptor automatically.
#[derive(Debug, Clone)]
pub struct WalletClient {
    inner: InnerWalletClient,
}

impl WalletClient {
    /// Start a builder targeting `endpoint`. Terminate with `.wallet()`.
    #[must_use]
    pub fn connect(endpoint: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// `POST /wallets` — create a new wallet end-to-end.
    pub async fn create_wallet(
        &mut self,
        params: CreateWalletParams,
    ) -> Result<proto::WalletView, SdkError> {
        let req: proto::CreateWalletRequest = params.into();
        let resp = self.inner.create_wallet(req).await?.into_inner();
        require("wallet", resp.wallet)
    }

    /// `GET /wallets/{id}` — fetch a wallet by ULID.
    pub async fn get_wallet(&mut self, wallet_id: &str) -> Result<proto::WalletView, SdkError> {
        let req = proto::GetWalletRequest {
            wallet_id: wallet_id.to_string(),
        };
        let resp = self.inner.get_wallet(req).await?.into_inner();
        require("wallet", resp.wallet)
    }

    /// `POST /wallets/{id}/sign` — sign a payload.
    pub async fn sign(&mut self, params: SignParams) -> Result<Signed, SdkError> {
        let req: proto::SignRequest = params.into();
        let resp = self.inner.sign(req).await?.into_inner();
        Ok(resp.into())
    }

    /// `GET /audit/events` — read recent audit events.
    pub async fn get_audit_events(
        &mut self,
        query: AuditEventsQuery,
    ) -> Result<Vec<AuditEventView>, SdkError> {
        let req: proto::GetAuditEventsRequest = query.into();
        let resp = self.inner.get_audit_events(req).await?.into_inner();
        Ok(resp.events)
    }
}

// ============================================================================
// ApproverClient
// ============================================================================

/// Approver / approver-set / approval RPC client.
#[derive(Debug, Clone)]
pub struct ApproverClient {
    inner: InnerApproverClient,
}

impl ApproverClient {
    /// Start a builder targeting `endpoint`. Terminate with `.approver()`.
    #[must_use]
    pub fn connect(endpoint: impl Into<String>) -> ClientBuilder {
        ClientBuilder::new(endpoint)
    }

    /// `POST /approvers` — register an approver identity.
    pub async fn register_approver(
        &mut self,
        params: RegisterApproverParams,
    ) -> Result<proto::ApproverView, SdkError> {
        let req: proto::RegisterApproverRequest = params.into();
        let resp = self.inner.register_approver(req).await?.into_inner();
        require("approver", resp.approver)
    }

    /// `DELETE /approvers/{id}` — revoke an approver. No payload returned.
    pub async fn revoke_approver(&mut self, approver_id: &str) -> Result<(), SdkError> {
        let req = proto::RevokeApproverRequest {
            approver_id: approver_id.to_string(),
        };
        self.inner.revoke_approver(req).await?;
        Ok(())
    }

    /// `GET /approvers/{id}` — fetch an approver.
    pub async fn get_approver(
        &mut self,
        approver_id: &str,
    ) -> Result<proto::ApproverView, SdkError> {
        let req = proto::GetApproverRequest {
            approver_id: approver_id.to_string(),
        };
        let resp = self.inner.get_approver(req).await?.into_inner();
        require("approver", resp.approver)
    }

    /// `GET /approvers?owner=` — list approvers for a tenant.
    pub async fn list_approvers(
        &mut self,
        owner: &str,
        include_revoked: bool,
    ) -> Result<Vec<proto::ApproverView>, SdkError> {
        let req = proto::ListApproversRequest {
            owner: owner.to_string(),
            include_revoked,
        };
        Ok(self.inner.list_approvers(req).await?.into_inner().approvers)
    }

    /// `POST /approver-sets` — create an approver set.
    pub async fn create_approver_set(
        &mut self,
        params: CreateApproverSetParams,
    ) -> Result<proto::ApproverSetView, SdkError> {
        let req: proto::CreateApproverSetRequest = params.into();
        let resp = self.inner.create_approver_set(req).await?.into_inner();
        require("approver_set", resp.approver_set)
    }

    /// `GET /approver-sets/{id}` — fetch an approver set.
    pub async fn get_approver_set(
        &mut self,
        approver_set_id: &str,
    ) -> Result<proto::ApproverSetView, SdkError> {
        let req = proto::GetApproverSetRequest {
            approver_set_id: approver_set_id.to_string(),
        };
        let resp = self.inner.get_approver_set(req).await?.into_inner();
        require("approver_set", resp.approver_set)
    }

    /// `GET /approver-sets?owner=` — list approver sets for a tenant.
    pub async fn list_approver_sets(
        &mut self,
        owner: &str,
    ) -> Result<Vec<proto::ApproverSetView>, SdkError> {
        let req = proto::ListApproverSetsRequest {
            owner: owner.to_string(),
        };
        Ok(self
            .inner
            .list_approver_sets(req)
            .await?
            .into_inner()
            .approver_sets)
    }

    /// `POST /requests/{id}/approvals` — submit a signed approval.
    ///
    /// Returns `(recorded, approval_id)` — `recorded == false` indicates
    /// an idempotent re-submission of an already-stored approval.
    pub async fn submit_approval(
        &mut self,
        params: SubmitApprovalParams,
    ) -> Result<(bool, String), SdkError> {
        params.validate()?;
        let req: proto::SubmitApprovalRequest = params.into();
        let resp = self.inner.submit_approval(req).await?.into_inner();
        Ok((resp.recorded, resp.approval_id))
    }

    /// `GET /requests/{id}/approvals` — list approvals for a request.
    pub async fn list_approvals(
        &mut self,
        request_id: &str,
    ) -> Result<Vec<proto::ApprovalView>, SdkError> {
        let req = proto::ListApprovalsRequest {
            request_id: request_id.to_string(),
        };
        Ok(self.inner.list_approvals(req).await?.into_inner().approvals)
    }
}
