//! `OrchestratingApprover` — the `QuorumApprover` that `WalletService`
//! actually uses.
//!
//! Composes:
//!
//! - 1..N `ApproverNotifier`s (webhook, hardware, onchain stub, …) for
//!   `request_approval`. Notifiers fan out concurrently; first error
//!   surfaces as a `QuorumError::Transport`.
//! - One `ApprovalStore` (memory or postgres) for `collect_approvals`.
//!   Collection polls the store with backoff; an embedded `Notify`
//!   wakes it up promptly when `notify_arrival` is called by the API
//!   submission handler.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use qfc_wallet_types::RequestId;
use tokio::sync::Notify;

use crate::approval::{ApprovalDecision, ApprovalRequest, SignedApproval};
use crate::approver::{QuorumApprover, QuorumError};
use crate::store::ApprovalStore;

/// Notification-side surface — one impl per channel (webhook/email/etc.).
#[async_trait]
pub trait ApproverNotifier: Send + Sync {
    /// Notify the approvers of a pending request.
    async fn notify(&self, req: &ApprovalRequest) -> Result<(), QuorumError>;

    /// Static label for audit logs.
    fn label(&self) -> &'static str;
}

/// Builder for `OrchestratingApprover`.
pub struct OrchestratingApproverBuilder {
    notifiers: Vec<Arc<dyn ApproverNotifier>>,
    store: Option<Arc<dyn ApprovalStore>>,
    poll_backoff: Duration,
}

impl Default for OrchestratingApproverBuilder {
    fn default() -> Self {
        Self {
            notifiers: Vec::new(),
            store: None,
            poll_backoff: Duration::from_millis(50),
        }
    }
}

impl OrchestratingApproverBuilder {
    /// Empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a notifier. Order is preserved in audit traces.
    #[must_use]
    pub fn with_notifier(mut self, n: Arc<dyn ApproverNotifier>) -> Self {
        self.notifiers.push(n);
        self
    }

    /// Set the approval store (required).
    #[must_use]
    pub fn with_store(mut self, s: Arc<dyn ApprovalStore>) -> Self {
        self.store = Some(s);
        self
    }

    /// Override the poll backoff. Default 50ms.
    #[must_use]
    pub fn with_poll_backoff(mut self, d: Duration) -> Self {
        self.poll_backoff = d;
        self
    }

    /// Finish.
    ///
    /// # Panics
    ///
    /// Panics if no store was supplied.
    #[must_use]
    pub fn build(self) -> OrchestratingApprover {
        OrchestratingApprover {
            notifiers: self.notifiers,
            store: self
                .store
                .expect("OrchestratingApprover requires an ApprovalStore"),
            arrival: Arc::new(Notify::new()),
            poll_backoff: self.poll_backoff,
        }
    }
}

/// The composed approver.
#[derive(Clone)]
pub struct OrchestratingApprover {
    notifiers: Vec<Arc<dyn ApproverNotifier>>,
    store: Arc<dyn ApprovalStore>,
    arrival: Arc<Notify>,
    poll_backoff: Duration,
}

impl OrchestratingApprover {
    /// Start a builder.
    #[must_use]
    pub fn builder() -> OrchestratingApproverBuilder {
        OrchestratingApproverBuilder::new()
    }

    /// Borrow the underlying store. Used by the HTTP handler to record an
    /// approval; once `notify_arrival` is called, `collect_approvals` will
    /// re-check immediately.
    #[must_use]
    pub fn store(&self) -> &Arc<dyn ApprovalStore> {
        &self.store
    }

    /// Wake any pending `collect_approvals`. Call this after a successful
    /// `record_approval` so the collector doesn't have to wait for the
    /// poll-backoff interval.
    pub fn notify_arrival(&self) {
        self.arrival.notify_waiters();
    }

    /// Per-channel notifier labels for audit.
    #[must_use]
    pub fn notifier_labels(&self) -> Vec<&'static str> {
        self.notifiers.iter().map(|n| n.label()).collect()
    }
}

#[async_trait]
impl QuorumApprover for OrchestratingApprover {
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        if self.notifiers.is_empty() {
            // No notifiers configured: accept silently. Useful in tests
            // that pre-stage approvals; for production it should be a
            // misconfiguration but is checked at deploy time, not here.
            return Ok(());
        }
        // Fan out concurrently. If any notifier fails, surface the first
        // error — but only after all others complete so we don't drop
        // pending notifications mid-flight.
        let mut handles = Vec::with_capacity(self.notifiers.len());
        for n in &self.notifiers {
            let n = Arc::clone(n);
            let req = req.clone();
            handles.push(tokio::spawn(async move { n.notify(&req).await }));
        }
        let mut first_err: Option<QuorumError> = None;
        for h in handles {
            match h.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(join_err) => {
                    if first_err.is_none() {
                        first_err = Some(QuorumError::Transport(format!(
                            "notifier task join: {join_err}"
                        )));
                    }
                }
            }
        }
        if let Some(e) = first_err {
            return Err(e);
        }
        Ok(())
    }

    async fn collect_approvals(
        &self,
        request_id: &RequestId,
        threshold: u8,
        timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError> {
        let started = std::time::Instant::now();
        loop {
            // Snapshot the store. The poll is cheap (memory) or one
            // round-trip (postgres) — fine to do per-iteration.
            let approvals = self
                .store
                .list_for_request(*request_id)
                .await
                .map_err(|e| QuorumError::Transport(format!("approval store: {e}")))?;
            // Reject path — surface the first reject so audit captures it.
            if let Some(reject) = approvals
                .iter()
                .find(|a| a.decision == ApprovalDecision::Reject)
            {
                return Ok(vec![reject.clone()]);
            }
            let approves: Vec<SignedApproval> = approvals
                .iter()
                .filter(|a| a.decision == ApprovalDecision::Approve)
                .cloned()
                .collect();
            if approves.len() >= threshold as usize {
                return Ok(approves);
            }
            let remaining = timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(QuorumError::Timeout(timeout));
            }
            // Sleep until either the poll backoff elapses or a new
            // approval arrives (via `notify_arrival`).
            let wait = remaining.min(self.poll_backoff);
            tokio::select! {
                () = tokio::time::sleep(wait) => {}
                () = self.arrival.notified() => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalDecision, ApprovalRequest, SignedApproval};
    use crate::identity::ApproverIdentity;
    use crate::store::MemoryApprovalStore;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use qfc_wallet_types::{ApprovalId, ApproverId, RequestId, SigningScheme};
    use std::sync::atomic::{AtomicU32, Ordering};

    #[derive(Default)]
    struct CountingNotifier {
        calls: AtomicU32,
        fail: bool,
    }

    #[async_trait]
    impl ApproverNotifier for CountingNotifier {
        async fn notify(&self, _req: &ApprovalRequest) -> Result<(), QuorumError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                Err(QuorumError::Transport("nope".into()))
            } else {
                Ok(())
            }
        }
        fn label(&self) -> &'static str {
            "counting"
        }
    }

    fn ed25519_identity(seed: u8) -> (ApproverIdentity, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        (
            ApproverIdentity::External {
                id: format!("approver-{seed}"),
                public_key: pk,
                scheme: SigningScheme::Ed25519,
            },
            sk,
        )
    }

    fn signed(
        identity: &ApproverIdentity,
        sk: &SigningKey,
        request_id: RequestId,
        message_hash: [u8; 32],
        decision: ApprovalDecision,
    ) -> SignedApproval {
        let approval_id = ApprovalId::new();
        let ts = 0i64;
        let pre = SignedApproval::signing_preimage(
            &approval_id,
            &request_id,
            &message_hash,
            decision,
            ts,
        );
        let sig = sk.sign(&pre).to_bytes().to_vec();
        SignedApproval {
            approval_id,
            approver: identity.clone(),
            request_id,
            message_hash,
            decision,
            timestamp_unix_ms: ts,
            signature: sig,
        }
    }

    #[tokio::test]
    async fn notifies_all_channels() {
        let n1 = Arc::new(CountingNotifier::default());
        let n2 = Arc::new(CountingNotifier::default());
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder()
            .with_notifier(n1.clone())
            .with_notifier(n2.clone())
            .with_store(store)
            .build();
        let req = ApprovalRequest {
            request_id: RequestId::new(),
            message_hash: [0u8; 32],
            approver_set: vec![],
            threshold: 1,
        };
        orch.request_approval(&req).await.unwrap();
        assert_eq!(n1.calls.load(Ordering::SeqCst), 1);
        assert_eq!(n2.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn collect_returns_when_threshold_reached() {
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder()
            .with_store(store.clone())
            .build();
        let request_id = RequestId::new();
        let (id_a, sk_a) = ed25519_identity(1);
        let (id_b, sk_b) = ed25519_identity(2);

        // Pre-submit two approvals.
        store
            .record_approval(
                &signed(
                    &id_a,
                    &sk_a,
                    request_id,
                    [0u8; 32],
                    ApprovalDecision::Approve,
                ),
                ApproverId::new(),
            )
            .await
            .unwrap();
        store
            .record_approval(
                &signed(
                    &id_b,
                    &sk_b,
                    request_id,
                    [0u8; 32],
                    ApprovalDecision::Approve,
                ),
                ApproverId::new(),
            )
            .await
            .unwrap();
        let result = orch
            .collect_approvals(&request_id, 2, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(result.len(), 2);
    }

    #[tokio::test]
    async fn collect_surfaces_reject() {
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder()
            .with_store(store.clone())
            .build();
        let request_id = RequestId::new();
        let (id_a, sk_a) = ed25519_identity(3);
        store
            .record_approval(
                &signed(
                    &id_a,
                    &sk_a,
                    request_id,
                    [0u8; 32],
                    ApprovalDecision::Reject,
                ),
                ApproverId::new(),
            )
            .await
            .unwrap();
        let result = orch
            .collect_approvals(&request_id, 3, Duration::from_millis(50))
            .await
            .unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].decision, ApprovalDecision::Reject);
    }

    #[tokio::test]
    async fn collect_times_out_without_threshold() {
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder().with_store(store).build();
        let request_id = RequestId::new();
        let err = orch
            .collect_approvals(&request_id, 2, Duration::from_millis(40))
            .await;
        assert!(matches!(err, Err(QuorumError::Timeout(_))));
    }

    #[tokio::test]
    async fn notify_arrival_wakes_collector() {
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder()
            .with_store(store.clone())
            .with_poll_backoff(Duration::from_secs(60)) // long poll backoff to prove the wake
            .build();
        let request_id = RequestId::new();
        let orch2 = orch.clone();
        let store2 = store.clone();
        let (id_a, sk_a) = ed25519_identity(5);
        let approver_id = ApproverId::new();
        let collect = tokio::spawn(async move {
            orch2
                .collect_approvals(&request_id, 1, Duration::from_secs(2))
                .await
        });
        // Give the collector a chance to start its sleep.
        tokio::time::sleep(Duration::from_millis(50)).await;
        store2
            .record_approval(
                &signed(
                    &id_a,
                    &sk_a,
                    request_id,
                    [0u8; 32],
                    ApprovalDecision::Approve,
                ),
                approver_id,
            )
            .await
            .unwrap();
        orch.notify_arrival();
        let r = collect.await.unwrap().unwrap();
        assert_eq!(r.len(), 1);
    }

    #[tokio::test]
    async fn notifier_failure_surfaces() {
        let n_ok = Arc::new(CountingNotifier::default());
        let n_bad = Arc::new(CountingNotifier {
            calls: AtomicU32::new(0),
            fail: true,
        });
        let store = Arc::new(MemoryApprovalStore::new());
        let orch = OrchestratingApprover::builder()
            .with_notifier(n_ok)
            .with_notifier(n_bad)
            .with_store(store)
            .build();
        let req = ApprovalRequest {
            request_id: RequestId::new(),
            message_hash: [0u8; 32],
            approver_set: vec![],
            threshold: 1,
        };
        let err = orch.request_approval(&req).await;
        assert!(matches!(err, Err(QuorumError::Transport(_))));
    }
}
