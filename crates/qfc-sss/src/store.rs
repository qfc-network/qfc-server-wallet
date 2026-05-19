//! The `ShareStore` trait and the on-the-wire `StoredShare` envelope.
//!
//! See `docs/server-wallet-rfc.md` §2.2 and §3.2.
//!
//! ## What lives where
//!
//! - **`ShareStore`** is the put/get/delete/list surface that the orchestrator
//!   uses without caring about whether the backend is in-memory, on-disk
//!   (with at-rest encryption), or KMS-wrapped in S3.
//! - **`StoredShare`** is the envelope. It carries the `ShamirShare` plus a
//!   creation timestamp and re-binds the share's identity (`ShareId`,
//!   `WalletId`) so the store can index without unpacking the share.
//! - **At-rest encryption is a store-level concern**, not part of the
//!   `StoredShare` envelope. `MockShareStore` stores in cleartext (it lives
//!   in process memory only); `LocalFsShareStore` AEAD-encrypts on write.
//!   When `S3KmsShareStore` lands in M3 it will add envelope encryption /
//!   wrapped-DEK metadata as a separate type so the trait surface stays clean.

use async_trait::async_trait;
use qfc_wallet_types::{ShareId, WalletId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ShamirShare;

/// Errors raised by `ShareStore` implementations.
#[derive(Debug, Error)]
pub enum StoreError {
    /// No share is registered under the requested ID.
    #[error("share not found: {0}")]
    NotFound(ShareId),

    /// The on-disk / on-wire representation could not be parsed.
    #[error("share serialization error: {0}")]
    Serde(String),

    /// I/O failure (disk, network, etc.).
    #[error("share store I/O error: {0}")]
    Io(String),

    /// At-rest encryption / decryption failed.
    #[error("share store crypto error: {0}")]
    Crypto(&'static str),

    /// Caller-supplied configuration is invalid.
    #[error("share store configuration error: {0}")]
    Config(&'static str),
}

/// The envelope that crosses the `ShareStore` trait boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredShare {
    /// Composite (`wallet_id`, `index`) lookup key.
    pub share_id: ShareId,
    /// Unix-millisecond timestamp at which this share was first persisted.
    /// Set by `put()`; the store is permitted to refresh on subsequent writes.
    pub created_at_unix_ms: i64,
    /// The actual share material.
    pub share: ShamirShare,
}

impl StoredShare {
    /// Convenience constructor that stamps `created_at` from the current
    /// wall-clock time.
    #[must_use]
    pub fn now(share_id: ShareId, share: ShamirShare) -> Self {
        Self {
            share_id,
            created_at_unix_ms: current_unix_ms(),
            share,
        }
    }

    /// Borrow the owning wallet identifier (convenience over `share_id.wallet_id`).
    #[must_use]
    pub fn wallet_id(&self) -> WalletId {
        self.share_id.wallet_id
    }
}

fn current_unix_ms() -> i64 {
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    // Floor to milliseconds; clamp into i64. Negative values are impossible in
    // practice (we are past 1970-01-01) but the clamp is defensive.
    i64::try_from(now / 1_000_000).unwrap_or(i64::MAX)
}

/// The put/get/delete/list interface that every share-storage backend
/// implements.
#[async_trait]
pub trait ShareStore: Send + Sync {
    /// Persist `share`. Idempotent on `share.share_id` — re-putting the same
    /// `ShareId` overwrites the prior value (the on-disk timestamp is
    /// refreshed). Implementations MUST make the write durable before
    /// returning `Ok(())`.
    ///
    /// # Errors
    ///
    /// `StoreError::Io`, `StoreError::Crypto`, or `StoreError::Serde` per
    /// the implementation.
    async fn put(&self, share: &StoredShare) -> Result<(), StoreError>;

    /// Retrieve a previously-stored share.
    ///
    /// # Errors
    ///
    /// - `StoreError::NotFound` if no share is registered under `share_id`.
    /// - `StoreError::Io` / `StoreError::Crypto` / `StoreError::Serde` for
    ///   underlying failures.
    async fn get(&self, share_id: &ShareId) -> Result<StoredShare, StoreError>;

    /// Delete a share. Returns `Ok(())` whether or not the share existed —
    /// the post-condition is "no share with this ID is retrievable via `get`".
    ///
    /// # Errors
    ///
    /// `StoreError::Io` for underlying failures.
    async fn delete(&self, share_id: &ShareId) -> Result<(), StoreError>;

    /// Enumerate all shares belonging to `wallet_id`. The returned vector is
    /// sorted by `share_id.index` ascending.
    ///
    /// # Errors
    ///
    /// `StoreError::Io` for underlying failures.
    async fn list(&self, wallet_id: &WalletId) -> Result<Vec<ShareId>, StoreError>;
}
