//! `OnChainQfcEventApprover` — STUB.
//!
//! Real chain submission is gated on `qfc-core` integration (see retro-m1-m2
//! §3.6 / RFC §1.4). For M4 we emit an `OnChainEvent` into an in-memory
//! `tokio::sync::broadcast` channel so other crates can subscribe and
//! exercise the dispatch path without a chain dependency.
//!
//! The whole module is feature-gated under `qfc-chain` which is *off* by
//! default. Code in this file compiles unconditionally so the trait shape
//! is visible to consumers; only the `feature = "qfc-chain"` block has
//! wiring to a live chain (currently empty — placeholder for M5+).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use qfc_wallet_types::RequestId;
use tokio::sync::broadcast;

use crate::approval::{ApprovalRequest, SignedApproval};
use crate::approver::{QuorumApprover, QuorumError};
use crate::approvers::orchestrating::ApproverNotifier;

/// In-memory event emitted by the stub on-chain approver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnChainEvent {
    /// Request being announced.
    pub request_id: RequestId,
    /// Bound message hash.
    pub message_hash: [u8; 32],
}

/// Stub on-chain approver. Holds a `broadcast::Sender<OnChainEvent>`;
/// every notification is fanned out to all subscribers.
#[derive(Clone)]
pub struct OnChainQfcEventApprover {
    tx: Arc<broadcast::Sender<OnChainEvent>>,
}

impl OnChainQfcEventApprover {
    /// Build a new stub with the given channel capacity. Use 64 or so for
    /// production-shape testing.
    #[must_use]
    pub fn new(channel_capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(channel_capacity);
        Self { tx: Arc::new(tx) }
    }

    /// Subscribe to the in-memory event channel. Returns a `Receiver` that
    /// will get every `OnChainEvent` from `request_approval` going forward.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<OnChainEvent> {
        self.tx.subscribe()
    }
}

#[async_trait]
impl QuorumApprover for OnChainQfcEventApprover {
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        emit(&self.tx, req);
        Ok(())
    }

    async fn collect_approvals(
        &self,
        _request_id: &RequestId,
        _threshold: u8,
        _timeout: Duration,
    ) -> Result<Vec<SignedApproval>, QuorumError> {
        Err(QuorumError::Transport(
            "OnChainQfcEventApprover is notify-only (stub); collection is M4+ with qfc-core".into(),
        ))
    }
}

#[async_trait]
impl ApproverNotifier for OnChainQfcEventApprover {
    async fn notify(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        emit(&self.tx, req);
        Ok(())
    }

    fn label(&self) -> &'static str {
        "onchain_stub"
    }
}

fn emit(tx: &broadcast::Sender<OnChainEvent>, req: &ApprovalRequest) {
    // Send is fallible only if there are zero subscribers — we treat that
    // as "no one is listening yet" and drop the event silently. In M5+
    // this dispatches a real chain tx and the error path is meaningful.
    let _ = tx.send(OnChainEvent {
        request_id: req.request_id,
        message_hash: req.message_hash,
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ApproverIdentity;
    use qfc_wallet_types::{RequestId, SigningScheme};

    #[tokio::test]
    async fn subscribers_receive_emitted_event() {
        let approver = OnChainQfcEventApprover::new(8);
        let mut rx = approver.subscribe();
        let request_id = RequestId::new();
        let req = ApprovalRequest {
            request_id,
            message_hash: [9u8; 32],
            approver_set: vec![ApproverIdentity::External {
                id: "alice".into(),
                public_key: vec![0u8; 32],
                scheme: SigningScheme::Ed25519,
            }],
            threshold: 1,
        };
        approver.request_approval(&req).await.unwrap();
        let ev = rx.recv().await.unwrap();
        assert_eq!(ev.request_id, request_id);
        assert_eq!(ev.message_hash, [9u8; 32]);
    }

    #[tokio::test]
    async fn no_subscribers_does_not_error() {
        let approver = OnChainQfcEventApprover::new(8);
        let req = ApprovalRequest {
            request_id: RequestId::new(),
            message_hash: [0u8; 32],
            approver_set: vec![],
            threshold: 1,
        };
        approver.request_approval(&req).await.unwrap();
    }
}
