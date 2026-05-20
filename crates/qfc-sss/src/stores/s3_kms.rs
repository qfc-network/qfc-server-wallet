//! `S3KmsShareStore` — share storage in AWS S3 + KMS envelope encryption.
//!
//! See `docs/server-wallet-rfc.md` §2.2 (M3 scope), §4.1 (wallet creation),
//! and §4.2 step "KMS-decrypts(wrapped_dek)".
//!
//! ## What this is
//!
//! - Each share lives at `s3://<bucket>/<wallet_id>/<index>`.
//! - The on-disk shape is `{ wrapped_dek, nonce, ciphertext, integrity_mac }`.
//! - `wrapped_dek` is the per-share data-encryption key wrapped by a KMS
//!   key whose **decrypt** policy is gated on the calling enclave's PCR0
//!   matching the expected EIF measurement. This is what makes "the share
//!   leaves S3 in the clear only for the right enclave" a property.
//!
//! ## M3 skeleton: mock-backed by default
//!
//! Real `aws-sdk-s3` + `aws-sdk-kms` lock the crate behind the `aws`
//! feature (off by default). The default build uses `MockS3Client` +
//! `MockKmsClient`, both in-memory, and lets tests assert the
//! attestation-conditional decrypt predicate (a closure the test plugs
//! into the mock KMS).
//!
//! ## Trait surface
//!
//! - `S3Like`: minimal put / get / delete / list against a key-value store.
//! - `KmsClient`: encrypt-DEK / decrypt-DEK with an attestation document
//!   carried alongside the request (mock implementation enforces the
//!   predicate; real AWS does it via the KMS condition policy).
//!
//! ## Why traits and not direct `aws-sdk-*` calls
//!
//! Two reasons:
//! 1. Build hygiene — `aws-sdk-*` pulls in a large dependency tree. The
//!    `aws` feature keeps non-AWS dev builds light.
//! 2. Test surface — the trait abstraction lets us prove the *attestation
//!    predicate* fails closed without spinning up real KMS.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use qfc_wallet_types::{ShareId, WalletId};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::store::{ShareStore, StoreError, StoredShare};

/// Minimal "S3-like" key-value store. Real impl lives behind `feature = "aws"`.
#[async_trait]
pub trait S3Like: Send + Sync {
    /// Put `body` at `key`.
    ///
    /// # Errors
    ///
    /// `StoreError::Io` on backend failure.
    async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<(), StoreError>;

    /// Get `body` at `key`.
    ///
    /// # Errors
    ///
    /// `StoreError::NotFound` if the key does not exist, `StoreError::Io`
    /// otherwise.
    async fn get_object(&self, key: &str) -> Result<Vec<u8>, StoreError>;

    /// Delete `key`. Idempotent.
    ///
    /// # Errors
    ///
    /// `StoreError::Io` on backend failure.
    async fn delete_object(&self, key: &str) -> Result<(), StoreError>;

    /// List keys with the given prefix.
    ///
    /// # Errors
    ///
    /// `StoreError::Io` on backend failure.
    async fn list_objects(&self, prefix: &str) -> Result<Vec<String>, StoreError>;
}

/// Minimal KMS client. Real impl lives behind `feature = "aws"`.
#[async_trait]
pub trait KmsClient: Send + Sync {
    /// Generate a fresh data-encryption key + return its plaintext + the
    /// wrapped (encrypted-by-KMS) ciphertext.
    ///
    /// # Errors
    ///
    /// `StoreError::Crypto` if generation failed.
    async fn generate_data_key(&self) -> Result<DataKeyMaterial, StoreError>;

    /// Decrypt a wrapped DEK back to plaintext. The `attestation` document
    /// is shown to the KMS condition policy.
    ///
    /// # Errors
    ///
    /// `StoreError::Crypto` if KMS refuses to decrypt (attestation
    /// constraint violation, wrong key arn, etc.).
    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        attestation: &[u8],
    ) -> Result<Vec<u8>, StoreError>;
}

/// The two-part DEK material returned by KMS `GenerateDataKey`.
#[derive(Clone, Debug)]
pub struct DataKeyMaterial {
    /// Plaintext DEK — encrypts the share locally.
    pub plaintext: [u8; 32],
    /// Wrapped DEK — stored alongside the ciphertext on S3.
    pub wrapped: Vec<u8>,
}

/// The on-disk envelope shape persisted to S3.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct S3Envelope {
    /// Wrapped DEK bytes (returned by KMS `GenerateDataKey`).
    #[serde(with = "serde_bytes")]
    pub wrapped_dek: Vec<u8>,
    /// XChaCha20-Poly1305 24-byte nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext over the `StoredShare`'s canonical serialization.
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// PCR constraint at the time of write — informational; the real
    /// enforcement happens at KMS-decrypt time.
    pub pcr_label: String,
}

/// `S3KmsShareStore` — per RFC §2.2 M3 backend.
pub struct S3KmsShareStore<S, K>
where
    S: S3Like + 'static,
    K: KmsClient + 'static,
{
    s3: Arc<S>,
    kms: Arc<K>,
    bucket_prefix: String,
    attestation: Vec<u8>,
    pcr_label: String,
}

impl<S, K> S3KmsShareStore<S, K>
where
    S: S3Like + 'static,
    K: KmsClient + 'static,
{
    /// Build a fresh `S3KmsShareStore`. `attestation` is the bytes shown to
    /// KMS for the attestation-conditional decrypt policy.
    #[must_use]
    pub fn new(
        s3: Arc<S>,
        kms: Arc<K>,
        bucket_prefix: impl Into<String>,
        attestation: Vec<u8>,
        pcr_label: impl Into<String>,
    ) -> Self {
        Self {
            s3,
            kms,
            bucket_prefix: bucket_prefix.into(),
            attestation,
            pcr_label: pcr_label.into(),
        }
    }

    fn object_key(&self, share_id: &ShareId) -> String {
        if self.bucket_prefix.is_empty() {
            format!("{}/{}", share_id.wallet_id, share_id.index)
        } else {
            format!(
                "{}/{}/{}",
                self.bucket_prefix.trim_end_matches('/'),
                share_id.wallet_id,
                share_id.index
            )
        }
    }

    fn wallet_prefix(&self, wallet_id: &WalletId) -> String {
        if self.bucket_prefix.is_empty() {
            format!("{wallet_id}/")
        } else {
            format!(
                "{}/{}/",
                self.bucket_prefix.trim_end_matches('/'),
                wallet_id
            )
        }
    }
}

#[async_trait]
impl<S, K> ShareStore for S3KmsShareStore<S, K>
where
    S: S3Like + 'static,
    K: KmsClient + 'static,
{
    async fn put(&self, share: &StoredShare) -> Result<(), StoreError> {
        let dek_material = self.kms.generate_data_key().await?;
        let cipher = XChaCha20Poly1305::new((&dek_material.plaintext).into());
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let plaintext = serde_json::to_vec(share)
            .map_err(|e| StoreError::Serde(format!("serialize share: {e}")))?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_slice())
            .map_err(|_| StoreError::Crypto("AEAD encrypt failed"))?;
        let envelope = S3Envelope {
            wrapped_dek: dek_material.wrapped,
            nonce: nonce_bytes,
            ciphertext,
            pcr_label: self.pcr_label.clone(),
        };
        let body = serde_json::to_vec(&envelope)
            .map_err(|e| StoreError::Serde(format!("serialize envelope: {e}")))?;
        let key_str = self.object_key(&share.share_id);
        self.s3.put_object(&key_str, body).await
    }

    async fn get(&self, share_id: &ShareId) -> Result<StoredShare, StoreError> {
        let body = self.s3.get_object(&self.object_key(share_id)).await?;
        let envelope: S3Envelope = serde_json::from_slice(&body)
            .map_err(|e| StoreError::Serde(format!("parse envelope: {e}")))?;
        // KMS-decrypts the wrapped DEK; this is where the attestation
        // predicate is enforced.
        let dek_plaintext = self
            .kms
            .decrypt_data_key(&envelope.wrapped_dek, &self.attestation)
            .await?;
        if dek_plaintext.len() != 32 {
            return Err(StoreError::Crypto("DEK length != 32"));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&dek_plaintext);
        let cipher = XChaCha20Poly1305::new((&key_arr).into());
        let nonce = XNonce::from(envelope.nonce);
        let plaintext = cipher
            .decrypt(&nonce, envelope.ciphertext.as_slice())
            .map_err(|_| StoreError::Crypto("AEAD decrypt failed"))?;
        let stored: StoredShare = serde_json::from_slice(&plaintext)
            .map_err(|e| StoreError::Serde(format!("parse share: {e}")))?;
        Ok(stored)
    }

    async fn delete(&self, share_id: &ShareId) -> Result<(), StoreError> {
        self.s3.delete_object(&self.object_key(share_id)).await
    }

    async fn list(&self, wallet_id: &WalletId) -> Result<Vec<ShareId>, StoreError> {
        let keys = self.s3.list_objects(&self.wallet_prefix(wallet_id)).await?;
        let mut out: Vec<ShareId> = keys
            .iter()
            .filter_map(|k| {
                // <prefix>/<wallet_id>/<index>
                let last = k.rsplit('/').next()?;
                let idx: u8 = last.parse().ok()?;
                Some(ShareId::new(*wallet_id, idx))
            })
            .collect();
        out.sort_unstable_by_key(|s| s.index);
        Ok(out)
    }
}

// ----------------------------------------------------------------------
// Mock backends — used by tests + dev-without-AWS.
// ----------------------------------------------------------------------

/// In-memory `S3Like` for tests.
#[derive(Default)]
pub struct MockS3Client {
    inner: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MockS3Client {
    /// Fresh empty mock store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot the in-memory contents (for tests).
    pub async fn snapshot(&self) -> HashMap<String, Vec<u8>> {
        self.inner.read().await.clone()
    }

    /// Drop all keys.
    pub async fn clear(&self) {
        self.inner.write().await.clear();
    }
}

#[async_trait]
impl S3Like for MockS3Client {
    async fn put_object(&self, key: &str, body: Vec<u8>) -> Result<(), StoreError> {
        self.inner.write().await.insert(key.to_string(), body);
        Ok(())
    }

    async fn get_object(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        self.inner
            .read()
            .await
            .get(key)
            .cloned()
            .ok_or(StoreError::NotFound(ShareId::new(
                WalletId::from_ulid(ulid::Ulid::nil()),
                0,
            )))
    }

    async fn delete_object(&self, key: &str) -> Result<(), StoreError> {
        self.inner.write().await.remove(key);
        Ok(())
    }

    async fn list_objects(&self, prefix: &str) -> Result<Vec<String>, StoreError> {
        Ok(self
            .inner
            .read()
            .await
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect())
    }
}

/// Closure type for the attestation predicate.
pub type AttestationPredicate = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// In-memory KMS that enforces an attestation predicate at decrypt time.
///
/// Construct via `MockKmsClient::new()` for the default "accept any non-empty
/// attestation"; tests that want a strict PCR-match predicate plug their
/// own via `with_attestation_predicate(...)`.
pub struct MockKmsClient {
    /// Maps `wrapped` (random 32 B identifier) -> plaintext DEK.
    inner: Arc<RwLock<HashMap<Vec<u8>, [u8; 32]>>>,
    /// Attestation predicate: returns `true` if the request is allowed to
    /// decrypt. Default: any non-empty attestation.
    predicate: AttestationPredicate,
}

impl MockKmsClient {
    /// Fresh mock KMS that accepts any non-empty attestation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            predicate: Arc::new(|att: &[u8]| !att.is_empty()),
        }
    }

    /// Override the attestation predicate.
    #[must_use]
    pub fn with_attestation_predicate(mut self, predicate: AttestationPredicate) -> Self {
        self.predicate = predicate;
        self
    }
}

impl Default for MockKmsClient {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl KmsClient for MockKmsClient {
    async fn generate_data_key(&self) -> Result<DataKeyMaterial, StoreError> {
        let mut plaintext = [0u8; 32];
        OsRng.fill_bytes(&mut plaintext);
        let mut wrapped = vec![0u8; 32];
        OsRng.fill_bytes(&mut wrapped);
        self.inner.write().await.insert(wrapped.clone(), plaintext);
        Ok(DataKeyMaterial { plaintext, wrapped })
    }

    async fn decrypt_data_key(
        &self,
        wrapped: &[u8],
        attestation: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        if !(self.predicate)(attestation) {
            return Err(StoreError::Crypto(
                "KMS decrypt refused: attestation predicate failed",
            ));
        }
        let inner = self.inner.read().await;
        inner
            .get(wrapped)
            .map(|p| p.to_vec())
            .ok_or(StoreError::Crypto("KMS: unknown wrapped DEK"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shamir::ShamirParams;

    fn sample_share(wallet: WalletId, index: u8) -> StoredShare {
        // Generate a real share rather than hand-crafting one — the
        // ShamirShare internal blob layout is private to the shamir mod.
        let secret = vec![0x42u8; 32];
        let shares = crate::shamir::split_secret(
            &secret,
            ShamirParams {
                threshold: 2,
                total: 3,
            },
        )
        .unwrap();
        // Index is 1..=3; pick the matching one (1-indexed).
        let chosen = shares
            .into_iter()
            .find(|s| s.index == index.max(1))
            .expect("share at index");
        StoredShare::now(ShareId::new(wallet, chosen.index), chosen)
    }

    fn make_store() -> S3KmsShareStore<MockS3Client, MockKmsClient> {
        S3KmsShareStore::new(
            Arc::new(MockS3Client::new()),
            Arc::new(MockKmsClient::new()),
            "qfc-test",
            b"attestation-blob".to_vec(),
            "pcr-mock-sentinel",
        )
    }

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let store = make_store();
        let w = WalletId::new();
        let s = sample_share(w, 3);
        store.put(&s).await.unwrap();
        let got = store.get(&s.share_id).await.unwrap();
        assert_eq!(got.share_id, s.share_id);
        assert_eq!(got.share, s.share);
    }

    #[tokio::test]
    async fn delete_then_get_returns_error() {
        let store = make_store();
        let w = WalletId::new();
        let s = sample_share(w, 2);
        store.put(&s).await.unwrap();
        store.delete(&s.share_id).await.unwrap();
        let err = store.get(&s.share_id).await;
        assert!(matches!(err, Err(StoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn list_returns_sorted_indices() {
        let store = make_store();
        let w = WalletId::new();
        for idx in [3u8, 1, 2] {
            store.put(&sample_share(w, idx)).await.unwrap();
        }
        let ids = store.list(&w).await.unwrap();
        assert_eq!(ids.iter().map(|s| s.index).collect::<Vec<_>>(), vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn on_storage_bytes_are_ciphertext() {
        // Put a share, then directly fetch the raw S3 body and assert the
        // raw share bytes never appear in plaintext.
        let s3 = Arc::new(MockS3Client::new());
        let kms = Arc::new(MockKmsClient::new());
        let store = S3KmsShareStore::new(
            s3.clone(),
            kms,
            "p",
            b"att".to_vec(),
            "pcr".to_string(),
        );
        let w = WalletId::new();
        let share = sample_share(w, 1);
        let raw_share_bytes = serde_json::to_vec(&share).unwrap();
        store.put(&share).await.unwrap();
        let snapshot = s3.snapshot().await;
        for (_, body) in snapshot {
            // The raw share bytes should not appear as a window of `body`.
            assert!(
                !body.windows(raw_share_bytes.len()).any(|w| w == raw_share_bytes),
                "raw share bytes leaked into S3 body"
            );
        }
    }

    #[tokio::test]
    async fn attestation_predicate_failure_blocks_decrypt() {
        // A predicate that refuses anything but `b"good"` — `put` works
        // (no decrypt yet) but `get` will fail.
        let predicate: AttestationPredicate = Arc::new(|att: &[u8]| att == b"good");
        let kms = Arc::new(MockKmsClient::new().with_attestation_predicate(predicate));
        let s3 = Arc::new(MockS3Client::new());
        let store = S3KmsShareStore::new(
            s3,
            kms,
            "p",
            b"WRONG-att".to_vec(),
            "pcr".to_string(),
        );
        let w = WalletId::new();
        let s = sample_share(w, 1);
        store.put(&s).await.unwrap();
        let err = store.get(&s.share_id).await;
        assert!(matches!(err, Err(StoreError::Crypto(_))));
    }

    #[tokio::test]
    async fn attestation_predicate_pass_unlocks_decrypt() {
        let predicate: AttestationPredicate = Arc::new(|att: &[u8]| att == b"good");
        let kms = Arc::new(MockKmsClient::new().with_attestation_predicate(predicate));
        let s3 = Arc::new(MockS3Client::new());
        let store = S3KmsShareStore::new(s3, kms, "p", b"good".to_vec(), "pcr".to_string());
        let w = WalletId::new();
        let s = sample_share(w, 1);
        store.put(&s).await.unwrap();
        let got = store.get(&s.share_id).await.unwrap();
        assert_eq!(got.share, s.share);
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails_decrypt() {
        let s3 = Arc::new(MockS3Client::new());
        let kms = Arc::new(MockKmsClient::new());
        let store = S3KmsShareStore::new(
            s3.clone(),
            kms,
            "",
            b"att".to_vec(),
            "pcr".to_string(),
        );
        let w = WalletId::new();
        let s = sample_share(w, 1);
        store.put(&s).await.unwrap();
        // Flip a byte in the stored envelope ciphertext.
        let key = format!("{}/{}", w, 1);
        let mut body = s3.snapshot().await.get(&key).cloned().unwrap();
        let mut envelope: S3Envelope = serde_json::from_slice(&body).unwrap();
        envelope.ciphertext[0] ^= 0xFF;
        body = serde_json::to_vec(&envelope).unwrap();
        s3.put_object(&key, body).await.unwrap();
        let err = store.get(&s.share_id).await;
        assert!(matches!(err, Err(StoreError::Crypto(_))));
    }

    #[tokio::test]
    async fn put_is_idempotent_on_share_id() {
        let store = make_store();
        let w = WalletId::new();
        let s = sample_share(w, 2);
        store.put(&s).await.unwrap();
        store.put(&s).await.unwrap();
        // List still shows exactly one share for this wallet.
        let ids = store.list(&w).await.unwrap();
        assert_eq!(ids.len(), 1);
    }
}
