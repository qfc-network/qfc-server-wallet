//! `WebhookApprover` — POST notifications to a registered URL with an
//! HMAC-SHA256 signature so receivers can authenticate the server.
//!
//! HMAC is computed over the raw request body bytes; the receiver
//! re-computes with the shared secret and compares constant-time. Header
//! name is `X-QFC-Signature` (lowercase canonical, hex-encoded).

use std::time::Duration;

use async_trait::async_trait;
use hmac::{Hmac, Mac};
use qfc_wallet_types::RequestId;
use sha2::Sha256;

use crate::approval::{ApprovalRequest, SignedApproval};
use crate::approver::{QuorumApprover, QuorumError};
use crate::approvers::orchestrating::ApproverNotifier;

/// HTTP header carrying the per-payload HMAC-SHA256, hex-lowercased.
pub const WEBHOOK_SIGNATURE_HEADER: &str = "x-qfc-signature";

/// Convenience export for callers building their own clients.
pub struct WebhookSignatureHeader;

impl WebhookSignatureHeader {
    /// Header name in canonical lowercase form.
    #[must_use]
    pub const fn name() -> &'static str {
        WEBHOOK_SIGNATURE_HEADER
    }
}

/// Tunables for `WebhookApprover`.
#[derive(Clone, Debug)]
pub struct WebhookApproverConfig {
    /// Per-request timeout. Default 5s.
    pub timeout: Duration,
    /// Endpoint URL to POST notifications to.
    pub endpoint: String,
    /// Shared secret for HMAC-SHA256 signing of request bodies.
    pub hmac_secret: Vec<u8>,
}

impl WebhookApproverConfig {
    /// Build with sensible defaults except for endpoint + secret.
    #[must_use]
    pub fn new(endpoint: impl Into<String>, hmac_secret: Vec<u8>) -> Self {
        Self {
            timeout: Duration::from_secs(5),
            endpoint: endpoint.into(),
            hmac_secret,
        }
    }
}

/// HTTP webhook notifier. Holds a `reqwest::Client`; cheap to clone.
#[derive(Clone)]
pub struct WebhookApprover {
    client: reqwest::Client,
    config: WebhookApproverConfig,
}

impl WebhookApprover {
    /// Build a new webhook notifier with the supplied config.
    ///
    /// # Errors
    ///
    /// `QuorumError::Transport` if the `reqwest::Client` cannot be constructed.
    pub fn new(config: WebhookApproverConfig) -> Result<Self, QuorumError> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| QuorumError::Transport(format!("build reqwest: {e}")))?;
        Ok(Self { client, config })
    }
}

#[async_trait]
impl QuorumApprover for WebhookApprover {
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        notify(&self.client, &self.config, req).await
    }

    async fn collect_approvals(
        &self,
        _request_id: &RequestId,
        _threshold: u8,
        _timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError> {
        Err(QuorumError::Transport(
            "WebhookApprover is notify-only; use OrchestratingApprover for collection".into(),
        ))
    }
}

#[async_trait]
impl ApproverNotifier for WebhookApprover {
    async fn notify(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        notify(&self.client, &self.config, req).await
    }

    fn label(&self) -> &'static str {
        "webhook"
    }
}

async fn notify(
    client: &reqwest::Client,
    config: &WebhookApproverConfig,
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
        .map_err(|e| QuorumError::Transport(format!("send webhook: {e}")))?;
    if !resp.status().is_success() {
        return Err(QuorumError::Transport(format!(
            "webhook returned {}",
            resp.status()
        )));
    }
    Ok(())
}

/// Helper: compute hex-encoded HMAC-SHA256(`secret`, `payload`). Exposed so
/// approver-side clients can verify the same way the server signs.
///
/// # Panics
///
/// Never in practice — `Hmac::new_from_slice` accepts any key length and
/// returns `Err` only for invalid lengths, which the SHA-256 variant does
/// not have.
#[must_use]
pub fn hmac_sha256_hex(secret: &[u8], payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(payload);
    let out = mac.finalize().into_bytes();
    hex::encode(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ApproverIdentity;
    use qfc_wallet_types::{RequestId, SigningScheme};
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn posts_with_hmac_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .and(header_exists(WEBHOOK_SIGNATURE_HEADER))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let approver = WebhookApprover::new(WebhookApproverConfig::new(
            format!("{}/notify", server.uri()),
            b"top-secret".to_vec(),
        ))
        .unwrap();

        let request_id = RequestId::new();
        let req = ApprovalRequest {
            request_id,
            message_hash: [0u8; 32],
            approver_set: vec![ApproverIdentity::External {
                id: "alice".into(),
                public_key: vec![0u8; 32],
                scheme: SigningScheme::Ed25519,
            }],
            threshold: 1,
        };
        approver.request_approval(&req).await.unwrap();
    }

    #[tokio::test]
    async fn non_200_returns_transport_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/notify"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let approver = WebhookApprover::new(WebhookApproverConfig::new(
            format!("{}/notify", server.uri()),
            b"k".to_vec(),
        ))
        .unwrap();
        let req = ApprovalRequest {
            request_id: RequestId::new(),
            message_hash: [0u8; 32],
            approver_set: vec![],
            threshold: 1,
        };
        let err = approver.request_approval(&req).await;
        assert!(matches!(err, Err(QuorumError::Transport(_))));
    }

    #[test]
    fn hmac_helper_stable() {
        let h = hmac_sha256_hex(b"key", b"payload");
        // Spot check: hex-only and 64 chars (256 bits).
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
