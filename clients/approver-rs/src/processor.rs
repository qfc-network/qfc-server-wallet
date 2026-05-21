//! Per-request approval flow.
//!
//! Given a parsed `ApprovalRequestWire`:
//!   1. Decide (auto-approve / interactive / refuse).
//!   2. Build the canonical preimage via `qfc_quorum::SignedApproval::signing_preimage`.
//!   3. Sign with the configured `ApproverSigner`.
//!   4. POST `SubmitApprovalWire` to `{server}/requests/{request_id}/approvals`.
//!   5. Audit-log the outcome locally.
//!
//! The processor is intentionally state-free: it can be cloned, shared
//! across axum workers, and called concurrently. The reqwest client is
//! reused (it pools connections internally).

use std::path::PathBuf;
use std::sync::Arc;

use qfc_quorum::{ApprovalDecision, SignedApproval};
use qfc_wallet_types::{ApprovalId, RequestId};

use crate::audit::{self, AuditRecord};
use crate::signer_loader::ApproverSigner;
use crate::wire::{ApprovalRequestWire, SubmitApprovalWire};

/// What the operator (or auto-policy) decided to do with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Sign + POST an approval.
    Approve,
    /// Sign + POST a reject.
    Reject,
    /// Drop the request without signing anything. The server-side will
    /// time out per its own quorum-timeout. This is the safe default
    /// when the operator can't / won't decide.
    Refuse,
}

/// How decisions are made.
#[derive(Clone, Debug)]
pub enum DecisionPolicy {
    /// Always approve every request. **Demo / staging only.**
    AutoApprove,
    /// Always reject. Useful when proving the receiver is wired up.
    AutoReject,
    /// Prompt the operator on stdin per request.
    Interactive,
    /// Drop every request. The default — fail-closed.
    Refuse,
}

/// Processor configuration shared across handlers.
#[derive(Clone, Debug)]
pub struct ProcessorConfig {
    /// Base URL of the qfc-server-wallet (e.g. `https://wallet.example`).
    pub server: String,
    /// The registered ULID this client identifies as.
    pub approver_id: String,
    /// Decision policy.
    pub policy: DecisionPolicy,
    /// Where to append local audit records.
    pub audit_path: PathBuf,
}

/// The processor — wraps a signer + an HTTP client + a config.
#[derive(Clone)]
pub struct Processor {
    signer: ApproverSigner,
    http: Arc<reqwest::Client>,
    config: ProcessorConfig,
    /// Override "now". Plumbed only for tests; production passes `None`.
    now_unix_ms_override: Option<i64>,
    /// Override the on-wire `ApproverIdentityWire` echoed back to the
    /// server. Defaults to `External` with the configured `approver_id`;
    /// real deployments will set this to whatever identity variant they
    /// registered.
    identity_override: Option<crate::wire::ApproverIdentityWire>,
}

/// Outcome of processing one webhook.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    /// Final decision.
    pub decision: Decision,
    /// HTTP status the server returned (`None` if we refused locally).
    pub server_status: Option<u16>,
    /// The approval id we minted (empty if refused).
    pub approval_id: String,
}

impl Processor {
    /// Build a new processor.
    #[must_use]
    pub fn new(
        signer: ApproverSigner,
        http: Arc<reqwest::Client>,
        config: ProcessorConfig,
    ) -> Self {
        Self {
            signer,
            http,
            config,
            now_unix_ms_override: None,
            identity_override: None,
        }
    }

    /// Pin the identity payload echoed back to the server. The reference
    /// CLI uses `External { id: approver_id, public_key_hex: derived,
    /// scheme }`; integrators that registered as `Chain` /
    /// `NestedWallet` / `Hardware` should call this to match the
    /// registered identity.
    #[must_use]
    pub fn with_identity(mut self, identity: crate::wire::ApproverIdentityWire) -> Self {
        self.identity_override = Some(identity);
        self
    }

    /// Pin the "now" used in the approval timestamp. Test-only.
    #[must_use]
    #[doc(hidden)]
    pub fn with_now_unix_ms(mut self, now_ms: i64) -> Self {
        self.now_unix_ms_override = Some(now_ms);
        self
    }

    /// Process one incoming webhook body.
    ///
    /// Returns an outcome describing what was done. Local errors (bad
    /// request id, signer failure, network failure) are surfaced as
    /// `Err`; the processor never panics.
    ///
    /// # Errors
    ///
    /// `ProcessorError::*` for any failure mode.
    pub async fn process(
        &self,
        req: &ApprovalRequestWire,
    ) -> Result<ProcessOutcome, ProcessorError> {
        // 1. Decide
        let decision = self.decide(req).await;

        if matches!(decision, Decision::Refuse) {
            let audit_rec = AuditRecord {
                timestamp: AuditRecord::now(),
                event: "rejected",
                request_id: req.request_id.clone(),
                approver_id: self.config.approver_id.clone(),
                message_hash_hex: req.message_hash.clone(),
                decision: "refused".into(),
                signature_hex: None,
                server_status: None,
                note: Some("operator refused".into()),
            };
            audit::append(&self.config.audit_path, &audit_rec)
                .await
                .ok();
            return Ok(ProcessOutcome {
                decision,
                server_status: None,
                approval_id: String::new(),
            });
        }

        // 2. Parse the request id + message hash into typed values so we
        //    can build the canonical preimage via the server-side helper.
        let request_id: RequestId = req
            .request_id
            .parse()
            .map_err(|e: qfc_wallet_types::ParseError| ProcessorError::BadRequest(e.to_string()))?;
        let message_hash = decode_msg_hash(&req.message_hash)?;
        let approval_id = ApprovalId::new();
        let approval_decision = match decision {
            Decision::Approve => ApprovalDecision::Approve,
            Decision::Reject => ApprovalDecision::Reject,
            Decision::Refuse => unreachable!("guarded above"),
        };
        let now_ms = self
            .now_unix_ms_override
            .unwrap_or_else(|| time::OffsetDateTime::now_utc().unix_timestamp() * 1_000);

        // 3. Build canonical preimage + sign
        let preimage = SignedApproval::signing_preimage(
            &approval_id,
            &request_id,
            &message_hash,
            approval_decision,
            now_ms,
        );
        let signature = self
            .signer
            .sign(&preimage)
            .map_err(|e| ProcessorError::Signer(e.to_string()))?;
        let signature_hex = hex::encode(&signature);

        // 4. POST
        let body = SubmitApprovalWire {
            approver_id: self.config.approver_id.clone(),
            approval_id: approval_id.to_string(),
            decision: match decision {
                Decision::Approve => "approve".into(),
                Decision::Reject => "reject".into(),
                Decision::Refuse => unreachable!(),
            },
            signature_hex: signature_hex.clone(),
            timestamp_unix_ms: now_ms,
            message_hash_hex: req.message_hash.clone(),
            identity: self.identity_for_wire(),
        };

        let url = format!(
            "{}/requests/{}/approvals",
            self.config.server.trim_end_matches('/'),
            req.request_id
        );
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProcessorError::Http(e.to_string()))?;
        let status = resp.status().as_u16();

        // 5. Audit
        let audit_rec = AuditRecord {
            timestamp: AuditRecord::now(),
            event: if (200..300).contains(&status) {
                "posted"
            } else {
                "error"
            },
            request_id: req.request_id.clone(),
            approver_id: self.config.approver_id.clone(),
            message_hash_hex: req.message_hash.clone(),
            decision: body.decision.clone(),
            signature_hex: Some(signature_hex),
            server_status: Some(status),
            note: None,
        };
        audit::append(&self.config.audit_path, &audit_rec)
            .await
            .ok();

        Ok(ProcessOutcome {
            decision,
            server_status: Some(status),
            approval_id: approval_id.to_string(),
        })
    }

    async fn decide(&self, req: &ApprovalRequestWire) -> Decision {
        match &self.config.policy {
            DecisionPolicy::AutoApprove => Decision::Approve,
            DecisionPolicy::AutoReject => Decision::Reject,
            DecisionPolicy::Refuse => Decision::Refuse,
            DecisionPolicy::Interactive => {
                let summary = format!(
                    "request_id    = {}\nmessage_hash  = {}\nthreshold     = {} of {}",
                    req.request_id,
                    req.message_hash,
                    req.threshold,
                    req.approver_set.len()
                );
                crate::prompt::prompt_for_decision(&summary).await
            }
        }
    }

    fn identity_for_wire(&self) -> crate::wire::ApproverIdentityWire {
        if let Some(id) = &self.identity_override {
            return id.clone();
        }
        crate::wire::ApproverIdentityWire::External {
            id: self.config.approver_id.clone(),
            public_key_hex: hex::encode(self.signer.public_key()),
            scheme: self.signer.scheme().into(),
        }
    }
}

fn decode_msg_hash(s: &str) -> Result<[u8; 32], ProcessorError> {
    let bytes = hex::decode(s).map_err(|e| ProcessorError::BadRequest(format!("hex: {e}")))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| ProcessorError::BadRequest("message_hash must be 32 bytes".into()))
}

/// Failures the processor can surface to its caller.
#[derive(Debug, thiserror::Error)]
pub enum ProcessorError {
    /// Webhook body was malformed (bad request id, hex, etc).
    #[error("bad request: {0}")]
    BadRequest(String),
    /// The configured signer failed.
    #[error("signer: {0}")]
    Signer(String),
    /// Outbound HTTP to the server failed.
    #[error("http: {0}")]
    Http(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{ApproverIdentityWire, SigningSchemeWire};
    use qfc_wallet_types::{SecretBytes, SigningScheme};

    fn mk_signer() -> ApproverSigner {
        ApproverSigner::new(SecretBytes::from_slice(&[0xAB; 32]), SigningScheme::Ed25519).unwrap()
    }

    fn mk_req() -> ApprovalRequestWire {
        ApprovalRequestWire {
            request_id: RequestId::new().to_string(),
            message_hash: hex::encode([0u8; 32]),
            approver_set: vec![ApproverIdentityWire::External {
                id: "alice".into(),
                public_key_hex: hex::encode([1u8; 32]),
                scheme: SigningSchemeWire::Ed25519,
            }],
            threshold: 1,
        }
    }

    #[tokio::test]
    async fn refuse_policy_does_not_call_http() {
        let signer = mk_signer();
        let http = Arc::new(reqwest::Client::new());
        let dir = tempfile::tempdir().unwrap();
        let cfg = ProcessorConfig {
            server: "http://unused.invalid".into(),
            approver_id: "01H8XYZ".into(),
            policy: DecisionPolicy::Refuse,
            audit_path: dir.path().join("audit.log"),
        };
        let p = Processor::new(signer, http, cfg);
        let req = mk_req();
        let out = p.process(&req).await.unwrap();
        assert_eq!(out.decision, Decision::Refuse);
        assert!(out.server_status.is_none());
        let log = tokio::fs::read_to_string(dir.path().join("audit.log"))
            .await
            .unwrap();
        assert!(log.contains("\"refused\""));
    }

    #[tokio::test]
    async fn approve_signs_with_preimage_helper_and_posts() {
        let mock = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .and(wiremock::matchers::path_regex("/requests/.+/approvals"))
            .respond_with(
                wiremock::ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"recorded": true, "approval_id": "01H"})),
            )
            .expect(1)
            .mount(&mock)
            .await;

        let signer = mk_signer();
        let http = Arc::new(reqwest::Client::new());
        let dir = tempfile::tempdir().unwrap();
        let cfg = ProcessorConfig {
            server: mock.uri(),
            approver_id: "01HABCDEFGHJKMNPQRSTVWXYZ0".into(),
            policy: DecisionPolicy::AutoApprove,
            audit_path: dir.path().join("audit.log"),
        };
        let p = Processor::new(signer, http, cfg);
        let req = mk_req();
        let out = p.process(&req).await.unwrap();
        assert_eq!(out.decision, Decision::Approve);
        assert_eq!(out.server_status, Some(200));
    }
}
