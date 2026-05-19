//! `MockQuorumApprover` — in-memory quorum backend for tests.
//!
//! Tests pre-populate approvals via `submit(...)`. `collect_approvals`
//! polls the in-memory store with backoff until threshold is reached or
//! `timeout` elapses.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use qfc_wallet_types::RequestId;
use tokio::sync::RwLock;
use tokio::time::sleep;

use crate::approval::{ApprovalDecision, ApprovalRequest, SignedApproval};
use crate::approver::{QuorumApprover, QuorumError};

/// In-memory quorum approver. Cheap to clone via `Arc` for test fan-out.
#[derive(Clone, Default)]
pub struct MockQuorumApprover {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    /// `request_id` → collected approvals so far.
    submitted: RwLock<HashMap<RequestId, Vec<SignedApproval>>>,
    /// `request_id` → notification count (lets tests assert `request_approval` was called).
    notified: RwLock<HashMap<RequestId, u32>>,
}

impl MockQuorumApprover {
    /// Construct an empty mock.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inject an approval into the store. Used by tests acting as the
    /// approver-side client.
    pub async fn submit(&self, approval: SignedApproval) {
        let mut guard = self.inner.submitted.write().await;
        guard.entry(approval.request_id).or_default().push(approval);
    }

    /// Count notifications received for a given request (test introspection).
    pub async fn notification_count(&self, request_id: &RequestId) -> u32 {
        *self
            .inner
            .notified
            .read()
            .await
            .get(request_id)
            .unwrap_or(&0)
    }
}

#[async_trait]
impl QuorumApprover for MockQuorumApprover {
    async fn request_approval(&self, req: &ApprovalRequest) -> Result<(), QuorumError> {
        let mut guard = self.inner.notified.write().await;
        *guard.entry(req.request_id).or_default() += 1;
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
            {
                let guard = self.inner.submitted.read().await;
                if let Some(list) = guard.get(request_id) {
                    // Reject path — surface the first reject so callers can audit.
                    if let Some(reject) =
                        list.iter().find(|a| a.decision == ApprovalDecision::Reject)
                    {
                        return Ok(vec![reject.clone()]);
                    }
                    let approvals: Vec<SignedApproval> = list
                        .iter()
                        .filter(|a| a.decision == ApprovalDecision::Approve)
                        .cloned()
                        .collect();
                    if approvals.len() >= threshold as usize {
                        return Ok(approvals);
                    }
                }
            }
            if started.elapsed() >= timeout {
                return Err(QuorumError::Timeout(timeout));
            }
            // Short backoff. In a real impl this would be a watch / signal.
            sleep(Duration::from_millis(10)).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ApprovalDecision, ApprovalRequest, SignedApproval};
    use crate::identity::ApproverIdentity;
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};
    use qfc_wallet_types::{ApprovalId, RequestId, SigningScheme};

    fn ed25519_approver(seed: u8) -> (ApproverIdentity, SigningKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = sk.verifying_key().to_bytes().to_vec();
        let id = ApproverIdentity::External {
            id: format!("approver-{seed}"),
            public_key: pk,
            scheme: SigningScheme::Ed25519,
        };
        (id, sk)
    }

    fn signed_approval(
        approver: &ApproverIdentity,
        sk: &SigningKey,
        request_id: RequestId,
        message_hash: [u8; 32],
        decision: ApprovalDecision,
        timestamp_unix_ms: i64,
    ) -> SignedApproval {
        let approval_id = ApprovalId::new();
        let preimage = SignedApproval::signing_preimage(
            &approval_id,
            &request_id,
            &message_hash,
            decision,
            timestamp_unix_ms,
        );
        let sig = sk.sign(&preimage).to_bytes().to_vec();
        SignedApproval {
            approval_id,
            approver: approver.clone(),
            request_id,
            message_hash,
            decision,
            timestamp_unix_ms,
            signature: sig,
        }
    }

    #[tokio::test]
    async fn collects_when_threshold_reached() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [0xABu8; 32];
        let (id_a, sk_a) = ed25519_approver(1);
        let (id_b, sk_b) = ed25519_approver(2);

        let req = ApprovalRequest {
            request_id,
            message_hash: msg_hash,
            approver_set: vec![id_a.clone(), id_b.clone()],
            threshold: 2,
        };
        q.request_approval(&req).await.unwrap();
        assert_eq!(q.notification_count(&request_id).await, 1);

        let now = now_ms();
        q.submit(signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            now,
        ))
        .await;
        q.submit(signed_approval(
            &id_b,
            &sk_b,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            now,
        ))
        .await;

        let collected = q
            .collect_approvals(&request_id, 2, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(collected.len(), 2);
    }

    #[tokio::test]
    async fn surfaces_first_reject() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [1u8; 32];
        let (id_a, sk_a) = ed25519_approver(3);
        q.submit(signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Reject,
            now_ms(),
        ))
        .await;
        let collected = q
            .collect_approvals(&request_id, 3, Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].decision, ApprovalDecision::Reject);
    }

    #[tokio::test]
    async fn times_out_when_threshold_not_reached() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let err = q
            .collect_approvals(&request_id, 1, Duration::from_millis(50))
            .await;
        assert!(matches!(err, Err(QuorumError::Timeout(_))));
    }

    #[tokio::test]
    async fn verify_approval_round_trip() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [9u8; 32];
        let (id_a, sk_a) = ed25519_approver(4);
        let approval = signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            now_ms(),
        );
        q.verify_approval(&approval, &id_a, &msg_hash, now_ms())
            .expect("approval verifies");
    }

    #[tokio::test]
    async fn verify_approval_rejects_wrong_message() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [9u8; 32];
        let (id_a, sk_a) = ed25519_approver(5);
        let approval = signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            now_ms(),
        );
        let other_hash = [0xFFu8; 32];
        let err = q.verify_approval(&approval, &id_a, &other_hash, now_ms());
        assert!(matches!(err, Err(QuorumError::InvalidApproval(_))));
    }

    #[tokio::test]
    async fn verify_approval_rejects_stale() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [9u8; 32];
        let (id_a, sk_a) = ed25519_approver(6);
        let signed_at = now_ms() - (crate::approval::MAX_APPROVAL_AGE_SECS + 10) * 1000;
        let approval = signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            signed_at,
        );
        let err = q.verify_approval(&approval, &id_a, &msg_hash, now_ms());
        assert!(matches!(err, Err(QuorumError::InvalidApproval(_))));
    }

    #[tokio::test]
    async fn verify_approval_rejects_mismatched_identity() {
        let q = MockQuorumApprover::new();
        let request_id = RequestId::new();
        let msg_hash = [9u8; 32];
        let (id_a, sk_a) = ed25519_approver(7);
        let (id_b, _sk_b) = ed25519_approver(8);
        let approval = signed_approval(
            &id_a,
            &sk_a,
            request_id,
            msg_hash,
            ApprovalDecision::Approve,
            now_ms(),
        );
        // Try to claim id_b — should bounce.
        let err = q.verify_approval(&approval, &id_b, &msg_hash, now_ms());
        assert!(matches!(err, Err(QuorumError::UnknownApprover(_))));
    }

    fn now_ms() -> i64 {
        let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
        i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
    }
}
