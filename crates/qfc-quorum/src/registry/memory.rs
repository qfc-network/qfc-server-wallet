//! In-memory `ApproverRegistry`. Backed by `tokio::sync::RwLock<HashMap>`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use qfc_wallet_types::{ApproverId, ApproverSetId, OwnerId, WalletId};
use tokio::sync::RwLock;

use crate::identity::ApproverIdentity;
use crate::registry::types::{
    validate_set_shape, ApproverCreate, ApproverRecord, ApproverRegistry, ApproverSet,
    ApproverSetCreate, ApproverStatus, RegistryError, MAX_NESTING_DEPTH,
};

/// In-memory registry. Cheap to clone.
#[derive(Clone, Default)]
pub struct MemoryApproverRegistry {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    approvers: RwLock<HashMap<ApproverId, ApproverRecord>>,
    sets: RwLock<HashMap<ApproverSetId, ApproverSet>>,
}

impl MemoryApproverRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl ApproverRegistry for MemoryApproverRegistry {
    async fn add_approver(&self, create: ApproverCreate) -> Result<ApproverRecord, RegistryError> {
        let approver_id = ApproverId::new();
        let scheme = create.identity.scheme();
        let record = ApproverRecord {
            approver_id,
            identity: create.identity,
            scheme,
            label: create.label,
            owner_id: create.owner_id,
            webhook_url: create.webhook_url,
            status: ApproverStatus::Active,
            added_at_unix_ms: now_unix_ms(),
        };
        self.inner
            .approvers
            .write()
            .await
            .insert(approver_id, record.clone());
        Ok(record)
    }

    async fn revoke_approver(&self, id: ApproverId) -> Result<(), RegistryError> {
        let mut guard = self.inner.approvers.write().await;
        let rec = guard
            .get_mut(&id)
            .ok_or(RegistryError::ApproverNotFound(id))?;
        rec.status = ApproverStatus::Revoked;
        Ok(())
    }

    async fn get_approver(&self, id: ApproverId) -> Result<ApproverRecord, RegistryError> {
        self.inner
            .approvers
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or(RegistryError::ApproverNotFound(id))
    }

    async fn list_approvers_by_owner(
        &self,
        owner: &OwnerId,
        include_revoked: bool,
    ) -> Result<Vec<ApproverRecord>, RegistryError> {
        let guard = self.inner.approvers.read().await;
        let mut out: Vec<ApproverRecord> = guard
            .values()
            .filter(|r| &r.owner_id == owner)
            .filter(|r| include_revoked || r.status == ApproverStatus::Active)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.added_at_unix_ms.cmp(&b.added_at_unix_ms));
        Ok(out)
    }

    async fn create_approver_set(
        &self,
        create: ApproverSetCreate,
    ) -> Result<ApproverSet, RegistryError> {
        validate_set_shape(&create)?;

        // Resolve members + reject unknown/revoked.
        let approvers_guard = self.inner.approvers.read().await;
        let mut nested_wallets: Vec<WalletId> = Vec::new();
        for m in &create.members {
            let rec = approvers_guard
                .get(m)
                .ok_or(RegistryError::UnknownMember(*m))?;
            if rec.status != ApproverStatus::Active {
                return Err(RegistryError::RevokedMember(*m));
            }
            if let ApproverIdentity::NestedWallet { wallet_id, .. } = &rec.identity {
                nested_wallets.push(*wallet_id);
            }
        }
        drop(approvers_guard);

        // Cycle detection over the nested-wallet membership graph.
        //
        // The graph is: wallet W → approver-sets that reference W's policy →
        // member approvers → if any is `NestedWallet(W')`, edge to W'.
        // We don't model "which wallet is being created" because at
        // create-set time the set hasn't been attached to a wallet yet —
        // what we *can* detect is whether the listed nested wallets form a
        // cycle through *existing* sets. Recursion depth is also capped.
        let sets_guard = self.inner.sets.read().await;
        for w in &nested_wallets {
            walk_nested(*w, &sets_guard, &approvers_for_walk(&self.inner).await, 0)?;
        }
        drop(sets_guard);

        let id = ApproverSetId::new();
        let set = ApproverSet {
            id,
            name: create.name,
            owner_id: create.owner_id,
            members: create.members,
            threshold: create.threshold,
            total: create.total,
            quorum_timeout_secs: create.quorum_timeout_secs,
            created_at_unix_ms: now_unix_ms(),
        };
        self.inner.sets.write().await.insert(id, set.clone());
        Ok(set)
    }

    async fn get_approver_set(&self, id: ApproverSetId) -> Result<ApproverSet, RegistryError> {
        self.inner
            .sets
            .read()
            .await
            .get(&id)
            .cloned()
            .ok_or(RegistryError::ApproverSetNotFound(id))
    }

    async fn list_approver_sets(&self, owner: &OwnerId) -> Result<Vec<ApproverSet>, RegistryError> {
        let guard = self.inner.sets.read().await;
        let mut out: Vec<ApproverSet> = guard
            .values()
            .filter(|s| &s.owner_id == owner)
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_at_unix_ms.cmp(&b.created_at_unix_ms));
        Ok(out)
    }
}

/// Take a read lock and clone the approver map. Used by the cycle-detection
/// walker to avoid juggling lock lifetimes.
async fn approvers_for_walk(inner: &Inner) -> HashMap<ApproverId, ApproverRecord> {
    inner.approvers.read().await.clone()
}

/// Walk the nested-wallet graph starting at `wallet`. The graph is
/// `wallet → approver-set whose members include NestedWallet(wallet) → that
/// set's nested-wallet members → …`. Returns `NestingCycle` if we revisit a
/// wallet, `NestingTooDeep` if depth would exceed `MAX_NESTING_DEPTH`.
///
/// The walker is iterative-ish over recursion via an explicit stack +
/// visited-set; the implementation is a small DFS.
fn walk_nested(
    start: WalletId,
    sets: &HashMap<ApproverSetId, ApproverSet>,
    approvers: &HashMap<ApproverId, ApproverRecord>,
    depth: u8,
) -> Result<(), RegistryError> {
    let mut visited: HashSet<WalletId> = HashSet::new();
    let mut stack: Vec<(WalletId, u8)> = vec![(start, depth)];
    while let Some((w, d)) = stack.pop() {
        if d > MAX_NESTING_DEPTH {
            return Err(RegistryError::NestingTooDeep(MAX_NESTING_DEPTH));
        }
        if !visited.insert(w) {
            return Err(RegistryError::NestingCycle(w));
        }
        // For every set that contains a NestedWallet(w) member, descend.
        for set in sets.values() {
            for member in &set.members {
                let Some(rec) = approvers.get(member) else {
                    continue;
                };
                if let ApproverIdentity::NestedWallet { wallet_id, .. } = &rec.identity {
                    if *wallet_id == w {
                        // This set "points at" w. Push every *other* nested-wallet
                        // member as a continuation.
                        for other in &set.members {
                            let Some(orec) = approvers.get(other) else {
                                continue;
                            };
                            if let ApproverIdentity::NestedWallet { wallet_id: ow, .. } =
                                &orec.identity
                            {
                                if *ow != w {
                                    stack.push((*ow, d + 1));
                                }
                            }
                        }
                        // Don't break; multiple sets may reference w.
                    }
                }
            }
        }
    }
    Ok(())
}

fn now_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}
