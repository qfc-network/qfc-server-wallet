//! `MockShareStore` — in-memory share store for tests and ephemeral dev.
//!
//! Holds `StoredShare`s in a `tokio::sync::RwLock<HashMap<ShareId, StoredShare>>`.
//! Trivially fast; no persistence; no encryption. Never deploy this.

use std::collections::HashMap;

use async_trait::async_trait;
use qfc_wallet_types::{ShareId, WalletId};
use tokio::sync::RwLock;

use crate::store::{ShareStore, StoreError, StoredShare};

/// In-memory share store. Cheap to clone via `Arc`.
#[derive(Default)]
pub struct MockShareStore {
    inner: RwLock<HashMap<ShareId, StoredShare>>,
}

impl MockShareStore {
    /// Create an empty mock store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Synchronous read of the current share count (useful in tests).
    pub async fn len(&self) -> usize {
        self.inner.read().await.len()
    }

    /// Whether the store holds any shares.
    pub async fn is_empty(&self) -> bool {
        self.inner.read().await.is_empty()
    }
}

#[async_trait]
impl ShareStore for MockShareStore {
    async fn put(&self, share: &StoredShare) -> Result<(), StoreError> {
        let mut guard = self.inner.write().await;
        guard.insert(share.share_id, share.clone());
        Ok(())
    }

    async fn get(&self, share_id: &ShareId) -> Result<StoredShare, StoreError> {
        let guard = self.inner.read().await;
        guard
            .get(share_id)
            .cloned()
            .ok_or(StoreError::NotFound(*share_id))
    }

    async fn delete(&self, share_id: &ShareId) -> Result<(), StoreError> {
        let mut guard = self.inner.write().await;
        guard.remove(share_id);
        Ok(())
    }

    async fn list(&self, wallet_id: &WalletId) -> Result<Vec<ShareId>, StoreError> {
        let guard = self.inner.read().await;
        let mut ids: Vec<ShareId> = guard
            .keys()
            .filter(|id| id.wallet_id == *wallet_id)
            .copied()
            .collect();
        ids.sort_by_key(|id| id.index);
        Ok(ids)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{shamir::ShamirParams, split_secret};
    use qfc_wallet_types::WalletId;

    fn sample_stored_shares(wallet: WalletId, threshold: u8, total: u8) -> Vec<StoredShare> {
        let secret = b"qfc-mock-store-secret-bytes-32!!"; // 32 bytes
        let shares = split_secret(secret, ShamirParams { threshold, total }).unwrap();
        shares
            .into_iter()
            .map(|s| StoredShare::now(ShareId::new(wallet, s.index), s))
            .collect()
    }

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let store = MockShareStore::new();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        for s in &shares {
            store.put(s).await.unwrap();
        }
        let got = store.get(&shares[1].share_id).await.unwrap();
        assert_eq!(got, shares[1]);
    }

    #[tokio::test]
    async fn get_missing_returns_not_found() {
        let store = MockShareStore::new();
        let wallet = WalletId::new();
        let missing = ShareId::new(wallet, 42);
        let err = store.get(&missing).await;
        assert!(matches!(err, Err(StoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn delete_then_get_returns_not_found() {
        let store = MockShareStore::new();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();
        store.delete(&shares[0].share_id).await.unwrap();
        assert!(matches!(
            store.get(&shares[0].share_id).await,
            Err(StoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn delete_missing_is_ok() {
        let store = MockShareStore::new();
        let wallet = WalletId::new();
        // Deleting something that does not exist is a no-op.
        store
            .delete(&ShareId::new(wallet, 9))
            .await
            .expect("delete is idempotent");
    }

    #[tokio::test]
    async fn list_returns_sorted_for_wallet() {
        let store = MockShareStore::new();
        let wallet_a = WalletId::new();
        let wallet_b = WalletId::new();
        let shares_a = sample_stored_shares(wallet_a, 2, 3);
        let shares_b = sample_stored_shares(wallet_b, 3, 5);
        for s in &shares_a {
            store.put(s).await.unwrap();
        }
        for s in &shares_b {
            store.put(s).await.unwrap();
        }
        let ids = store.list(&wallet_a).await.unwrap();
        assert_eq!(ids.len(), 3);
        assert_eq!(ids[0].index, 1);
        assert_eq!(ids[1].index, 2);
        assert_eq!(ids[2].index, 3);
        let ids_b = store.list(&wallet_b).await.unwrap();
        assert_eq!(ids_b.len(), 5);
    }

    #[tokio::test]
    async fn list_for_unknown_wallet_is_empty() {
        let store = MockShareStore::new();
        let lonely = WalletId::new();
        assert!(store.list(&lonely).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn put_is_idempotent_on_share_id() {
        let store = MockShareStore::new();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();
        // Same share_id, different timestamp — should overwrite, not error.
        let later = StoredShare {
            share_id: shares[0].share_id,
            created_at_unix_ms: shares[0].created_at_unix_ms + 1_000,
            share: shares[0].share.clone(),
        };
        store.put(&later).await.unwrap();
        let got = store.get(&shares[0].share_id).await.unwrap();
        assert_eq!(got.created_at_unix_ms, shares[0].created_at_unix_ms + 1_000);
        assert_eq!(store.len().await, 1);
    }
}
