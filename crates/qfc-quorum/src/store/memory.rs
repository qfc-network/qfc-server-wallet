//! In-memory `ApprovalStore` for tests/dev.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use qfc_wallet_types::{ApprovalId, ApproverId, RequestId};
use tokio::sync::RwLock;

use crate::approval::SignedApproval;
use crate::store::{ApprovalStore, RecordOutcome, StoreError};

type ApprovalKey = (RequestId, ApproverId);
type ApprovalEntry = (ApprovalId, SignedApproval);
type ApprovalIndex = HashMap<RequestId, Vec<(ApproverId, ApprovalId)>>;

/// In-memory approval store. Cheap to clone.
#[derive(Clone, Default)]
pub struct MemoryApprovalStore {
    inner: Arc<RwLock<HashMap<ApprovalKey, ApprovalEntry>>>,
    by_request: Arc<RwLock<ApprovalIndex>>,
}

impl MemoryApprovalStore {
    /// Empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ApprovalStore for MemoryApprovalStore {
    async fn record_approval(
        &self,
        approval: &SignedApproval,
        approver_id: ApproverId,
    ) -> Result<RecordOutcome, StoreError> {
        let key = (approval.request_id, approver_id);
        let mut guard = self.inner.write().await;
        if let Some((prev_id, _)) = guard.get(&key) {
            return if *prev_id == approval.approval_id {
                Ok(RecordOutcome::AlreadyRecorded)
            } else {
                Err(StoreError::DuplicateApproval(
                    approver_id,
                    approval.request_id,
                ))
            };
        }
        guard.insert(key, (approval.approval_id, approval.clone()));
        drop(guard);
        let mut idx = self.by_request.write().await;
        idx.entry(approval.request_id)
            .or_default()
            .push((approver_id, approval.approval_id));
        Ok(RecordOutcome::Inserted)
    }

    async fn list_for_request(
        &self,
        request_id: RequestId,
    ) -> Result<Vec<SignedApproval>, StoreError> {
        let idx = self.by_request.read().await;
        let inner = self.inner.read().await;
        let Some(list) = idx.get(&request_id) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::with_capacity(list.len());
        for (approver_id, _) in list {
            if let Some((_, app)) = inner.get(&(request_id, *approver_id)) {
                out.push(app.clone());
            }
        }
        Ok(out)
    }
}
