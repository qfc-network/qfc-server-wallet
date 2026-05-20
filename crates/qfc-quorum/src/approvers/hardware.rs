//! `HardwareApproverNotifier` — dispatcher to hardware-token-backed
//! approvers. The notifier itself does NOT perform any hardware signing;
//! the approver-side client uses the device. This type fans out the
//! `ApprovalRequest` to a registered URL (typically a long-poll endpoint
//! the hardware client listens on) with HMAC-SHA256 authentication, same
//! pattern as `WebhookApprover`.
//!
//! The split between `WebhookApprover` and this type is intentional: in
//! the system metadata they appear as distinct notification channels even
//! though the wire shape is similar, so audit logs and the "what surfaces
//! does this approver use" admin UI can distinguish hardware-approver
//! dispatch from generic webhook dispatch.

use std::time::Duration;

use async_trait::async_trait;
use qfc_wallet_types::RequestId;

use crate::approval::{ApprovalRequest, SignedApproval};
use crate::approver::{QuorumApprover, QuorumError};
use crate::approvers::orchestrating::ApproverNotifier;
use crate::approvers::webhook::{hmac_sha256_hex, WEBHOOK_SIGNATURE_HEADER};

/// Configuration for `HardwareApproverNotifier`.
#[derive(Clone, Debug)]
pub struct HardwareApproverNotifierConfig {
    /// Dispatcher endpoint URL.
    pub endpoint: String,
    /// HMAC-SHA256 shared secret.
    pub hmac_secret: Vec<u8>,
    /// Per-request timeout.
    pub timeout: Duration,
}

impl HardwareApproverNotifierConfig {
    /// Build with a default 5s timeout.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, hmac_secret: Vec<u8>) -> Self {
        Self {
            endpoint: endpoint.into(),
            hmac_secret,
            timeout: Duration::from_secs(5),
        }
    }
}

/// Hardware-token approver notifier. Dispatch-only.
#[derive(Clone)]
pub struct HardwareApproverNotifier {
    client: reqwest::Client,
    config: HardwareApproverNotifierConfig,
}

impl HardwareApproverNotifier {
    /// Build a notifier with the supplied config.
    ///
    /// # Errors
    ///
    /// `QuorumError::Transport` on `reqwest::Client` build failure.
    pub fn new(config: HardwareApproverNotifierConfig) -> Result<Self, QuorumError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| QuorumError::Transport(format!("build reqwest: {e}")))?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl QuorumApprover for HardwareApproverNotifier {
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        dispatch(&self.client, &self.config, req).await
    }

    async fn collect_approvals(
        &self,
        _request_id: &RequestId,
        _threshold: u8,
        _timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError> {
        Err(QuorumError::Transport(
            "HardwareApproverNotifier is dispatch-only; use OrchestratingApprover".into(),
        ))
    }
}

#[async_trait]
impl ApproverNotifier for HardwareApproverNotifier {
    async fn notify(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        dispatch(&self.client, &self.config, req).await
    }

    fn label(&self) -> &'static str {
        "hardware"
    }
}

async fn dispatch(
    client: &reqwest::Client,
    config: &HardwareApproverNotifierConfig,
    req: &ApprovalRequest,
) -> Result<(), QuorumError> {
    let body = serde_json::to_vec(req)
        .map_err(|e| QuorumError::Transport(format!("encode request: {e}")))?;
    let sig = hmac_sha256_hex(&config.hmac_secret, &body);
    let resp = client
        .post(&config.endpoint)
        .header("content-type", "application/json")
        .header(WEBHOOK_SIGNATURE_HEADER, &sig)
        .body(body)
        .send()
        .await
        .map_err(|e| QuorumError::Transport(format!("send hw notify: {e}")))?;
    if !resp.status().is_success() {
        return Err(QuorumError::Transport(format!(
            "hw notify returned {}",
            resp.status()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ApproverIdentity;
    use qfc_wallet_types::SigningScheme;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn dispatches_with_hmac() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hw"))
            .and(header_exists(WEBHOOK_SIGNATURE_HEADER))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        let notifier = HardwareApproverNotifier::new(HardwareApproverNotifierConfig::new(
            format!("{}/hw", server.uri()),
            b"hwsecret".to_vec(),
        ))
        .unwrap();
        notifier
            .request_approval(&ApprovalRequest {
                request_id: RequestId::new(),
                message_hash: [0u8; 32],
                approver_set: vec![ApproverIdentity::External {
                    id: "alice".into(),
                    public_key: vec![0u8; 32],
                    scheme: SigningScheme::Ed25519,
                }],
                threshold: 1,
            })
            .await
            .unwrap();
    }
}
