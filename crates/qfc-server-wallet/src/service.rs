//! `WalletService` — the top-level orchestration surface.
//!
//! Mediates between policy, quorum, enclave, share store, and audit log.
//! Crate consumers (HTTP server in M2, integration tests today) talk
//! exclusively to this type.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use qfc_audit::{Actor, AuditEventDraft, AuditKind, AuditSink};
use qfc_enclave::{
    Enclave, EnclaveSignRequest, EnclaveSignResponse, GenerateWalletRequest, SigningContext,
};
use qfc_policy::{Policy, PolicyDecision, SigningPayload, SigningRequest};
use qfc_quorum::{
    ApprovalRequest, ApprovalStore, ApproverRegistry, QuorumApprover, RecordOutcome, SignedApproval,
};
use qfc_sss::{ShareStore, StoredShare};
use qfc_wallet_types::{HashAlg, HdPath, RequestId, ShareId, WalletId};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::observability::{
    record_policy_evaluation, record_quorum_collect, record_sign_duration, record_sign_outcome,
    record_wallet_created, SignResult,
};
use crate::wallet::{WalletConfig, WalletRecord, WalletStatus};

/// Errors raised by the orchestrator.
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The wallet does not exist (or has been revoked).
    #[error("wallet not found: {0}")]
    WalletNotFound(WalletId),

    /// Policy denied the request.
    #[error("policy denied: {0}")]
    PolicyDenied(String),

    /// Policy required quorum but quorum collection failed.
    #[error("quorum failure: {0}")]
    Quorum(#[from] qfc_quorum::QuorumError),

    /// Underlying policy backend failed.
    #[error("policy backend: {0}")]
    Policy(#[from] qfc_policy::PolicyError),

    /// Underlying enclave failed.
    #[error("enclave: {0}")]
    Enclave(#[from] qfc_enclave::EnclaveError),

    /// Underlying share store failed.
    #[error("share store: {0}")]
    Store(#[from] qfc_sss::store::StoreError),

    /// Audit log failed (best-effort; sign may still succeed but the
    /// operator should be alerted).
    #[error("audit: {0}")]
    Audit(#[from] qfc_audit::AuditError),

    /// Could not assemble M shares (e.g. some shares missing).
    #[error("not enough shares available: {0}")]
    InsufficientShares(String),
}

/// Top-level orchestrator. Holds the dependency tree as `Arc`s so it is
/// cheap to clone for parallel request handling.
pub struct WalletService {
    pub(crate) enclave: Arc<dyn Enclave>,
    pub(crate) shares: Arc<dyn ShareStore>,
    pub(crate) policy: Arc<dyn Policy>,
    pub(crate) quorum: Arc<dyn QuorumApprover>,
    pub(crate) audit: Arc<dyn AuditSink>,
    /// Approver / approver-set admin surface (M4).
    pub(crate) approvers: Arc<dyn ApproverRegistry>,
    /// Submitted-approvals store (M4). Backs both the HTTP approval
    /// submission endpoint and the `OrchestratingApprover` collector.
    pub(crate) approval_store: Arc<dyn ApprovalStore>,
    pub(crate) wallets: Arc<RwLock<HashMap<WalletId, WalletRecord>>>,
    pub(crate) quorum_timeout: Duration,
}

impl WalletService {
    /// Build a new `WalletService` from its subsystem dependencies.
    ///
    /// The approver registry + approval store default to in-memory
    /// implementations; production deployments swap with
    /// [`WalletService::with_approver_registry`] /
    /// [`WalletService::with_approval_store`].
    #[must_use]
    pub fn new(
        enclave: Arc<dyn Enclave>,
        shares: Arc<dyn ShareStore>,
        policy: Arc<dyn Policy>,
        quorum: Arc<dyn QuorumApprover>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            enclave,
            shares,
            policy,
            quorum,
            audit,
            approvers: Arc::new(qfc_quorum::MemoryApproverRegistry::new()),
            approval_store: Arc::new(qfc_quorum::MemoryApprovalStore::new()),
            wallets: Arc::new(RwLock::new(HashMap::new())),
            quorum_timeout: Duration::from_secs(120),
        }
    }

    /// Override the approver registry. Useful for swapping to
    /// `PostgresApproverRegistry` in production.
    #[must_use]
    pub fn with_approver_registry(mut self, registry: Arc<dyn ApproverRegistry>) -> Self {
        self.approvers = registry;
        self
    }

    /// Override the approval store. Useful for swapping to
    /// `PostgresApprovalStore` in production.
    #[must_use]
    pub fn with_approval_store(mut self, store: Arc<dyn ApprovalStore>) -> Self {
        self.approval_store = store;
        self
    }

    /// Override the quorum-collection timeout (default: 120s).
    #[must_use]
    pub fn with_quorum_timeout(mut self, timeout: Duration) -> Self {
        self.quorum_timeout = timeout;
        self
    }

    /// Borrow a wallet record by id.
    ///
    /// # Errors
    ///
    /// `ServiceError::WalletNotFound` if no wallet matches.
    #[tracing::instrument(skip_all, fields(wallet_id = %wallet_id))]
    pub async fn get_wallet(&self, wallet_id: WalletId) -> Result<WalletRecord, ServiceError> {
        self.wallets
            .read()
            .await
            .get(&wallet_id)
            .cloned()
            .ok_or(ServiceError::WalletNotFound(wallet_id))
    }

    /// Create a new wallet end-to-end: enclave generates, shares persist,
    /// audit logs `WalletCreated`.
    ///
    /// # Errors
    ///
    /// Propagates from any subsystem.
    #[tracing::instrument(
        skip_all,
        fields(
            scheme = ?config.scheme,
            threshold = config.threshold,
            total = config.total,
            wallet_id = tracing::field::Empty,
        ),
    )]
    pub async fn create_wallet(
        &self,
        config: WalletConfig,
        owner_actor: Actor,
    ) -> Result<WalletRecord, ServiceError> {
        let wallet_id = WalletId::new();
        tracing::Span::current().record("wallet_id", tracing::field::display(wallet_id));
        let gen = self
            .enclave
            .generate_wallet(GenerateWalletRequest {
                wallet_id,
                scheme: config.scheme,
                threshold: config.threshold,
                total: config.total,
                master_hd_path: None,
            })
            .await?;

        // Persist shares.
        let now = current_unix_ms();
        let mut share_indices: Vec<u8> = Vec::with_capacity(gen.shares.len());
        for s in &gen.shares {
            share_indices.push(s.index);
            let stored = StoredShare {
                share_id: ShareId::new(wallet_id, s.index),
                created_at_unix_ms: now,
                share: s.clone(),
            };
            self.shares.put(&stored).await?;
        }

        let record = WalletRecord {
            wallet_id,
            config: config.clone(),
            master_public_key: gen.master_public_key.clone(),
            status: WalletStatus::Active,
            created_at_unix_ms: now,
        };
        self.wallets.write().await.insert(wallet_id, record.clone());

        // Audit.
        self.audit
            .emit(AuditEventDraft {
                actor: owner_actor,
                kind: AuditKind::WalletCreated,
                request_id: None,
                wallet_id: Some(wallet_id),
                details: json!({
                    "scheme": config.scheme,
                    "threshold": config.threshold,
                    "total": config.total,
                    "share_indices": share_indices,
                    "master_public_key_hex": hex_encode(&gen.master_public_key),
                    "policy_id": config.policy_id,
                }),
            })
            .await?;

        record_wallet_created(scheme_label(config.scheme));
        Ok(record)
    }

    /// Sign a message for `wallet_id`. Walks the full flow per RFC §4.2 /
    /// §4.3.
    ///
    /// # Errors
    ///
    /// Propagates from any subsystem; `ServiceError::PolicyDenied` for a
    /// hard deny; `ServiceError::Quorum` for quorum timeouts or rejected
    /// approvals; `ServiceError::WalletNotFound` for unknown wallets.
    #[allow(clippy::too_many_lines)]
    #[tracing::instrument(
        skip_all,
        fields(
            wallet_id = %wallet_id,
            request_id = tracing::field::Empty,
            scheme = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
    )]
    pub async fn sign(
        &self,
        wallet_id: WalletId,
        payload: SigningPayload,
        requester: qfc_policy::Requester,
        hd_path: Option<HdPath>,
        context: SigningContext,
        hash_alg: HashAlg,
    ) -> Result<EnclaveSignResponse, ServiceError> {
        let sign_started = Instant::now();
        let wallet = self.get_wallet(wallet_id).await?;
        if wallet.status == WalletStatus::Revoked {
            // Wallet was found-then-revoked; bump the denied counter so
            // operators can see this distinct failure mode.
            record_sign_outcome(scheme_label(wallet.config.scheme), SignResult::Denied);
            return Err(ServiceError::WalletNotFound(wallet_id));
        }
        let scheme = scheme_label(wallet.config.scheme);
        let request_id = RequestId::new();
        tracing::Span::current().record("request_id", tracing::field::display(request_id));
        tracing::Span::current().record("scheme", scheme);
        let message = canonical_message_bytes(&payload);
        let message_hash = ApprovalRequest::message_hash_for(&message);

        // 1. Audit the request.
        self.audit
            .emit(AuditEventDraft {
                actor: requester_to_actor(&requester),
                kind: AuditKind::SigningRequested,
                request_id: Some(request_id),
                wallet_id: Some(wallet_id),
                details: json!({
                    "message_hash_hex": hex_encode(&message_hash),
                    "hd_path": hd_path.as_ref().map(ToString::to_string),
                }),
            })
            .await?;

        // 2. Policy evaluate.
        let signing_request = SigningRequest {
            request_id,
            wallet_id,
            requester: requester.clone(),
            payload: payload.clone(),
            hd_path: hd_path.clone(),
            received_at_unix_ms: current_unix_ms(),
        };
        let policy_started = Instant::now();
        let decision = self.policy.evaluate(&signing_request).await?;
        record_policy_evaluation(policy_started.elapsed().as_secs_f64());
        self.audit
            .emit(AuditEventDraft {
                actor: Actor::System,
                kind: AuditKind::SigningEvaluated,
                request_id: Some(request_id),
                wallet_id: Some(wallet_id),
                details: json!({ "decision": &decision }),
            })
            .await?;

        match &decision {
            PolicyDecision::Deny { reason, .. } => {
                record_sign_outcome(scheme, SignResult::Denied);
                record_sign_duration(scheme, sign_started.elapsed().as_secs_f64());
                tracing::Span::current().record("outcome", "denied");
                return Err(ServiceError::PolicyDenied(format!("{reason:?}")));
            }
            PolicyDecision::RequireQuorum {
                threshold,
                total: _,
                approver_set,
                ..
            } => {
                // Resolve the approver set from the registry so we can fan
                // out notifications to its members. If the set is unknown,
                // policy still ran — but we can't proceed: emit a system
                // error and surface as InsufficientShares-ish failure.
                let set = self.approvers.get_approver_set(*approver_set).await.ok();
                let identities: Vec<qfc_quorum::ApproverIdentity> = match &set {
                    Some(set) => {
                        let mut ids = Vec::with_capacity(set.members.len());
                        for m in &set.members {
                            let rec = self.approvers.get_approver(*m).await.map_err(|e| {
                                ServiceError::Quorum(qfc_quorum::QuorumError::Transport(format!(
                                    "registry: {e}"
                                )))
                            })?;
                            ids.push(rec.identity);
                        }
                        ids
                    }
                    None => Vec::new(),
                };
                let approval_request = ApprovalRequest {
                    request_id,
                    message_hash,
                    approver_set: identities,
                    threshold: *threshold,
                };
                self.quorum
                    .request_approval(&approval_request)
                    .await
                    .map_err(ServiceError::Quorum)?;
                self.audit
                    .emit(AuditEventDraft {
                        actor: Actor::System,
                        kind: AuditKind::QuorumNotified,
                        request_id: Some(request_id),
                        wallet_id: Some(wallet_id),
                        details: json!({
                            "threshold": threshold,
                            "approver_set": approver_set.to_string(),
                        }),
                    })
                    .await?;

                let quorum_started = Instant::now();
                let collect_timeout = set
                    .as_ref()
                    .and_then(|s| s.quorum_timeout_secs)
                    .map_or(self.quorum_timeout, |s| Duration::from_secs(u64::from(s)));
                let collect_result = self
                    .quorum
                    .collect_approvals(&request_id, *threshold, collect_timeout)
                    .await;
                record_quorum_collect(quorum_started.elapsed().as_secs_f64());
                let approvals = match collect_result {
                    Ok(a) => a,
                    Err(qfc_quorum::QuorumError::Timeout(d)) => {
                        self.audit
                            .emit(AuditEventDraft {
                                actor: Actor::System,
                                kind: AuditKind::QuorumTimedOut,
                                request_id: Some(request_id),
                                wallet_id: Some(wallet_id),
                                details: json!({ "timeout_ms": d.as_millis() }),
                            })
                            .await?;
                        record_sign_outcome(scheme, SignResult::Denied);
                        record_sign_duration(scheme, sign_started.elapsed().as_secs_f64());
                        tracing::Span::current().record("outcome", "quorum_timeout");
                        return Err(ServiceError::Quorum(qfc_quorum::QuorumError::Timeout(d)));
                    }
                    Err(e) => {
                        return Err(ServiceError::Quorum(e));
                    }
                };
                for approval in &approvals {
                    self.audit
                        .emit(AuditEventDraft {
                            actor: Actor::Approver {
                                id: approval.approver.key(),
                            },
                            kind: if matches!(
                                approval.decision,
                                qfc_quorum::ApprovalDecision::Approve
                            ) {
                                AuditKind::QuorumApprovalReceived
                            } else {
                                AuditKind::QuorumApprovalRejected
                            },
                            request_id: Some(request_id),
                            wallet_id: Some(wallet_id),
                            details: json!({ "approval_id": approval.approval_id }),
                        })
                        .await?;
                }
                // Any reject (the collector surfaces the first one) blocks the sign.
                if let Some(reject) = approvals
                    .iter()
                    .find(|a| matches!(a.decision, qfc_quorum::ApprovalDecision::Reject))
                {
                    record_sign_outcome(scheme, SignResult::Denied);
                    record_sign_duration(scheme, sign_started.elapsed().as_secs_f64());
                    tracing::Span::current().record("outcome", "quorum_rejected");
                    return Err(ServiceError::PolicyDenied(format!(
                        "quorum rejected by {}",
                        reject.approver.key(),
                    )));
                }
                // Threshold reached — emit the "we got M signed approvals"
                // audit event so timelines distinguish "request sent" from
                // "request approved".
                self.audit
                    .emit(AuditEventDraft {
                        actor: Actor::System,
                        kind: AuditKind::QuorumThresholdReached,
                        request_id: Some(request_id),
                        wallet_id: Some(wallet_id),
                        details: json!({
                            "threshold": threshold,
                            "collected": approvals.len(),
                        }),
                    })
                    .await?;
                // TODO(M3): pass `approvals` and the `PolicyDecision` into
                // EnclaveSignRequest so the enclave re-verifies the hybrid
                // policy invariants (see retro-m1-m2 §3.4). Today the
                // orchestrator trusts the host count; with the M3 Nitro
                // backend this becomes load-bearing.
            }
            PolicyDecision::Allow { .. } => {}
        }

        // 3. Fetch shares.
        let stored_shares = self.fetch_shares(&wallet, wallet.config.threshold).await?;
        let raw_shares: Vec<qfc_sss::ShamirShare> =
            stored_shares.into_iter().map(|s| s.share).collect();

        // 4. Audit attempt + enclave sign.
        self.audit
            .emit(AuditEventDraft {
                actor: Actor::System,
                kind: AuditKind::SigningAttempted,
                request_id: Some(request_id),
                wallet_id: Some(wallet_id),
                details: json!({}),
            })
            .await?;

        // M3 hybrid scheme additive fields. The orchestrator threads through:
        //   - `policy_decision: None` for M3 skeleton; the in-enclave hybrid
        //     verifier is exercised in unit tests directly. A future PR
        //     introduces a dedicated `PolicyServiceSigner` that wraps
        //     `decision` into a `SignedPolicyDecision` here.
        //   - `approvals: Vec::new()` until M4 wires quorum →
        //     `EnclaveApproval` conversion at this layer. The
        //     `MockEnclave` ignores both; `NitroEnclave` (the boot binary)
        //     enforces them.
        let resp = self
            .enclave
            .sign_in_enclave(EnclaveSignRequest {
                request_id,
                wallet_id,
                shares: raw_shares,
                scheme: wallet.config.scheme,
                hd_path,
                message,
                hash_alg,
                context,
                policy_decision: None,
                approvals: Vec::new(),
            })
            .await;

        match resp {
            Ok(r) => {
                self.audit
                    .emit(AuditEventDraft {
                        actor: Actor::Enclave,
                        kind: AuditKind::SigningSucceeded,
                        request_id: Some(request_id),
                        wallet_id: Some(wallet_id),
                        details: json!({
                            "signature_hash_hex": hex_encode(&sha256_32(&r.signature)),
                        }),
                    })
                    .await?;
                record_sign_outcome(scheme, SignResult::Success);
                record_sign_duration(scheme, sign_started.elapsed().as_secs_f64());
                tracing::Span::current().record("outcome", "success");
                Ok(r)
            }
            Err(e) => {
                self.audit
                    .emit(AuditEventDraft {
                        actor: Actor::Enclave,
                        kind: AuditKind::SigningFailed,
                        request_id: Some(request_id),
                        wallet_id: Some(wallet_id),
                        details: json!({ "error": e.to_string() }),
                    })
                    .await?;
                record_sign_outcome(scheme, SignResult::Failed);
                record_sign_duration(scheme, sign_started.elapsed().as_secs_f64());
                tracing::Span::current().record("outcome", "failed");
                Err(ServiceError::Enclave(e))
            }
        }
    }

    async fn fetch_shares(
        &self,
        wallet: &WalletRecord,
        threshold: u8,
    ) -> Result<Vec<StoredShare>, ServiceError> {
        // List, then fetch the first `threshold` shares (deterministic
        // order: sorted by index).
        let ids = self.shares.list(&wallet.wallet_id).await?;
        if ids.len() < threshold as usize {
            return Err(ServiceError::InsufficientShares(format!(
                "have {} shares, need {}",
                ids.len(),
                threshold
            )));
        }
        let mut out = Vec::with_capacity(threshold as usize);
        for id in ids.iter().take(threshold as usize) {
            out.push(self.shares.get(id).await?);
        }
        Ok(out)
    }

    /// Record a submitted approval. Verifies the embedded signature against
    /// the message hash and request id derived from the in-flight request,
    /// persists into the approval store, and (when the underlying
    /// `QuorumApprover` is an `OrchestratingApprover`) signals the
    /// collector to recheck.
    ///
    /// The caller (typically the `POST /requests/{request_id}/approvals`
    /// handler) is responsible for resolving the approver record from the
    /// registry; this method then runs the *cryptographic* verification
    /// against the registered identity, freshness, and request binding.
    ///
    /// Re-submission of the SAME approval payload is idempotent
    /// (`Inserted` → `AlreadyRecorded`); a different payload from the same
    /// approver for the same request raises `Quorum` /
    /// `ApprovalStoreError::DuplicateApproval`.
    ///
    /// # Errors
    ///
    /// - `ServiceError::Quorum` for verification or duplicate failures.
    pub async fn record_approval(
        &self,
        approval: SignedApproval,
        approver_id: qfc_wallet_types::ApproverId,
        expected_message_hash: [u8; 32],
    ) -> Result<RecordOutcome, ServiceError> {
        // Look up the approver to enforce the registered identity matches
        // the embedded one (defence in depth: the API request may have
        // claimed approver_id X but signed with the key of approver_id Y).
        let rec = self
            .approvers
            .get_approver(approver_id)
            .await
            .map_err(|e| {
                ServiceError::Quorum(qfc_quorum::QuorumError::Transport(format!("registry: {e}")))
            })?;
        if rec.identity != approval.approver {
            return Err(ServiceError::Quorum(
                qfc_quorum::QuorumError::UnknownApprover(approval.approver.key()),
            ));
        }
        if matches!(rec.status, qfc_quorum::ApproverStatus::Revoked) {
            return Err(ServiceError::Quorum(
                qfc_quorum::QuorumError::UnknownApprover(format!(
                    "approver {approver_id} is revoked"
                )),
            ));
        }

        // Verify the signature + freshness + binding.
        approval
            .verify(
                &approval.request_id,
                &expected_message_hash,
                current_unix_ms(),
            )
            .map_err(|e| ServiceError::Quorum(qfc_quorum::QuorumError::InvalidApproval(e)))?;

        let outcome = self
            .approval_store
            .record_approval(&approval, approver_id)
            .await
            .map_err(|e| match e {
                qfc_quorum::ApprovalStoreError::DuplicateApproval(_, _) => ServiceError::Quorum(
                    qfc_quorum::QuorumError::Transport(format!("duplicate approval: {e}")),
                ),
                qfc_quorum::ApprovalStoreError::Io(msg) => {
                    ServiceError::Quorum(qfc_quorum::QuorumError::Transport(msg))
                }
            })?;
        Ok(outcome)
    }

    /// Borrow the underlying approver registry. Used by the HTTP handlers.
    #[must_use]
    pub fn approver_registry(&self) -> &Arc<dyn ApproverRegistry> {
        &self.approvers
    }

    /// Borrow the underlying approval store. Used by the HTTP handlers.
    #[must_use]
    pub fn approval_store(&self) -> &Arc<dyn ApprovalStore> {
        &self.approval_store
    }

    /// Borrow the underlying quorum approver. Used by the HTTP handlers
    /// to call `notify_arrival` on the `OrchestratingApprover`.
    #[must_use]
    pub fn quorum(&self) -> &Arc<dyn QuorumApprover> {
        &self.quorum
    }
}

fn canonical_message_bytes(payload: &SigningPayload) -> Vec<u8> {
    match payload {
        SigningPayload::Raw { bytes } | SigningPayload::PersonalSign { bytes } => bytes.clone(),
        SigningPayload::TypedData { json } => serde_json::to_vec(json).unwrap_or_default(),
        SigningPayload::VmTransaction { raw, .. } => raw.clone(),
    }
}

fn requester_to_actor(req: &qfc_policy::Requester) -> Actor {
    Actor::Requester {
        id: qfc_policy::StaticAllowDenyPolicy::requester_key(req),
    }
}

fn current_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

fn sha256_32(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Stable string label for a [`SigningScheme`](qfc_wallet_types::SigningScheme),
/// used as the `scheme` metric label.
fn scheme_label(scheme: qfc_wallet_types::SigningScheme) -> &'static str {
    use qfc_wallet_types::SigningScheme as S;
    match scheme {
        S::Ed25519 => "ed25519",
        S::Secp256k1 => "secp256k1",
        S::Secp256k1Recoverable => "secp256k1_recoverable",
        S::MlDsa44 => "ml_dsa_44",
        S::MlDsa65 => "ml_dsa_65",
        S::MlDsa87 => "ml_dsa_87",
    }
}
