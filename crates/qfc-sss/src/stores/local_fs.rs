//! `LocalFsShareStore` — encrypted-at-rest filesystem share store.
//!
//! Layout under `root`:
//! ```text
//! root/
//!   01J<wallet-ulid>/
//!     1.bin
//!     2.bin
//!     ...
//! ```
//!
//! Each `<index>.bin` file is the AEAD-encrypted JSON serialization of the
//! `StoredShare`, with the following on-disk format:
//!
//! ```text
//! magic   : 8 bytes — b"QFCSS\x00\x01\x00"
//! nonce   : 24 bytes — XChaCha20-Poly1305 nonce, fresh per write
//! ciphertext + tag : variable — the AEAD output
//! ```
//!
//! The cipher is XChaCha20-Poly1305 (extended-nonce variant). 32-byte key
//! is supplied at construction. The store does NOT derive the key from a
//! passphrase or load it from a file — that is an operator-startup
//! concern. If you need passphrase-based key wrapping, layer an `age`
//! file or a KDF (argon2 / scrypt) above this store.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use qfc_wallet_types::{ShareId, WalletId};
use rand::RngCore;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use zeroize::Zeroizing;

use crate::store::{ShareStore, StoreError, StoredShare};

const FILE_MAGIC: &[u8; 8] = b"QFCSS\x00\x01\x00";
const NONCE_BYTES: usize = 24;

/// Filesystem-backed encrypted share store.
pub struct LocalFsShareStore {
    root: PathBuf,
    /// 32-byte AEAD key. Held in `Zeroizing` so it's wiped on drop.
    key: Zeroizing<[u8; 32]>,
}

impl LocalFsShareStore {
    /// Create a new store rooted at `root` with the given 32-byte key.
    ///
    /// `root` must exist OR be creatable by this process (the constructor
    /// does NOT create it — that is a deploy-time decision).
    ///
    /// # Errors
    ///
    /// `StoreError::Config` if `root` is empty.
    pub fn new(root: impl Into<PathBuf>, key: [u8; 32]) -> Result<Self, StoreError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(StoreError::Config("root path must not be empty"));
        }
        Ok(Self {
            root,
            key: Zeroizing::new(key),
        })
    }

    /// Generate a fresh random 32-byte key. Convenient for tests; production
    /// callers should source the key from a hardened path (KMS, age, etc.).
    #[must_use]
    pub fn random_key() -> [u8; 32] {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    }

    fn wallet_dir(&self, wallet_id: &WalletId) -> PathBuf {
        self.root.join(wallet_id.to_string())
    }

    fn share_path(&self, share_id: &ShareId) -> PathBuf {
        self.wallet_dir(&share_id.wallet_id)
            .join(format!("{}.bin", share_id.index))
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(self.key.as_ref().into())
    }

    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, StoreError> {
        let cipher = self.cipher();
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from(nonce_bytes);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| StoreError::Crypto("aead encrypt"))?;
        let mut out = Vec::with_capacity(FILE_MAGIC.len() + NONCE_BYTES + ct.len());
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    fn open_envelope(raw: &[u8]) -> Result<(XNonce, &[u8]), StoreError> {
        if raw.len() < FILE_MAGIC.len() + NONCE_BYTES {
            return Err(StoreError::Crypto("share file truncated"));
        }
        if &raw[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(StoreError::Crypto("share file magic mismatch"));
        }
        let nonce_start = FILE_MAGIC.len();
        let body_start = nonce_start + NONCE_BYTES;
        let mut nonce_bytes = [0u8; NONCE_BYTES];
        nonce_bytes.copy_from_slice(&raw[nonce_start..body_start]);
        Ok((XNonce::from(nonce_bytes), &raw[body_start..]))
    }

    fn open(&self, raw: &[u8]) -> Result<Vec<u8>, StoreError> {
        let (nonce, body) = Self::open_envelope(raw)?;
        let cipher = self.cipher();
        cipher
            .decrypt(&nonce, body)
            .map_err(|_| StoreError::Crypto("aead decrypt"))
    }
}

#[async_trait]
impl ShareStore for LocalFsShareStore {
    async fn put(&self, share: &StoredShare) -> Result<(), StoreError> {
        let path = self.share_path(&share.share_id);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let serialized = serde_json::to_vec(share).map_err(|e| StoreError::Serde(e.to_string()))?;
        let sealed = self.seal(&serialized)?;

        // Atomic write: write to a tempfile in the same dir, then rename.
        let tmp = path.with_extension("bin.tmp");
        {
            let mut f = fs::File::create(&tmp)
                .await
                .map_err(|e| StoreError::Io(e.to_string()))?;
            f.write_all(&sealed)
                .await
                .map_err(|e| StoreError::Io(e.to_string()))?;
            f.flush().await.map_err(|e| StoreError::Io(e.to_string()))?;
            f.sync_all()
                .await
                .map_err(|e| StoreError::Io(e.to_string()))?;
        }
        fs::rename(&tmp, &path)
            .await
            .map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, share_id: &ShareId) -> Result<StoredShare, StoreError> {
        let path = self.share_path(share_id);
        let raw = match fs::read(&path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(StoreError::NotFound(*share_id));
            }
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let plaintext = self.open(&raw)?;
        let share: StoredShare =
            serde_json::from_slice(&plaintext).map_err(|e| StoreError::Serde(e.to_string()))?;
        // Defensive: ensure on-disk share_id matches the requested ID. Catches
        // accidental file copies / cross-wallet collisions.
        if share.share_id != *share_id {
            return Err(StoreError::Crypto("share_id mismatch in decrypted blob"));
        }
        Ok(share)
    }

    async fn delete(&self, share_id: &ShareId) -> Result<(), StoreError> {
        let path = self.share_path(share_id);
        match fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e.to_string())),
        }
    }

    async fn list(&self, wallet_id: &WalletId) -> Result<Vec<ShareId>, StoreError> {
        let dir = self.wallet_dir(wallet_id);
        let mut entries = match fs::read_dir(&dir).await {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let mut indices: HashSet<u8> = HashSet::new();
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| StoreError::Io(e.to_string()))?
        {
            if let Some(idx) = parse_share_filename(entry.path().as_path()) {
                indices.insert(idx);
            }
        }
        let mut ids: Vec<ShareId> = indices
            .into_iter()
            .map(|i| ShareId::new(*wallet_id, i))
            .collect();
        ids.sort_by_key(|id| id.index);
        Ok(ids)
    }
}

fn parse_share_filename(path: &Path) -> Option<u8> {
    let file = path.file_name()?.to_str()?;
    let stem = file.strip_suffix(".bin")?;
    stem.parse::<u8>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{shamir::ShamirParams, split_secret};
    use qfc_wallet_types::WalletId;
    use tempfile::TempDir;

    fn store_with_temp() -> (LocalFsShareStore, TempDir, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let key = LocalFsShareStore::random_key();
        let store = LocalFsShareStore::new(dir.path(), key).unwrap();
        (store, dir, key)
    }

    fn sample_stored_shares(wallet: WalletId, threshold: u8, total: u8) -> Vec<StoredShare> {
        let secret = b"qfc-localfs-store-secret-32-byte"; // 32 bytes
        let shares = split_secret(secret, ShamirParams { threshold, total }).unwrap();
        shares
            .into_iter()
            .map(|s| StoredShare::now(ShareId::new(wallet, s.index), s))
            .collect()
    }

    #[tokio::test]
    async fn put_then_get_round_trip() {
        let (store, _tmp, _key) = store_with_temp();
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
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let err = store.get(&ShareId::new(wallet, 7)).await;
        assert!(matches!(err, Err(StoreError::NotFound(_))));
    }

    #[tokio::test]
    async fn delete_removes_file_and_subsequent_get_is_not_found() {
        let (store, _tmp, _key) = store_with_temp();
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
    async fn delete_missing_is_idempotent() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        store
            .delete(&ShareId::new(wallet, 99))
            .await
            .expect("delete-missing must succeed");
    }

    #[tokio::test]
    async fn list_returns_sorted_indices() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 3, 5);
        for s in shares.iter().rev() {
            store.put(s).await.unwrap();
        }
        let ids = store.list(&wallet).await.unwrap();
        let indices: Vec<u8> = ids.iter().map(|i| i.index).collect();
        assert_eq!(indices, vec![1, 2, 3, 4, 5]);
    }

    #[tokio::test]
    async fn list_for_unknown_wallet_is_empty() {
        let (store, _tmp, _key) = store_with_temp();
        let lonely = WalletId::new();
        assert!(store.list(&lonely).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn put_overwrites_existing_share() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();
        let updated = StoredShare {
            share_id: shares[0].share_id,
            created_at_unix_ms: shares[0].created_at_unix_ms + 60_000,
            share: shares[0].share.clone(),
        };
        store.put(&updated).await.unwrap();
        let got = store.get(&shares[0].share_id).await.unwrap();
        assert_eq!(got, updated);
    }

    #[tokio::test]
    async fn wrong_key_fails_to_decrypt() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = LocalFsShareStore::random_key();
        let store_a = LocalFsShareStore::new(dir.path(), key_a).unwrap();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store_a.put(&shares[0]).await.unwrap();

        // Different key, same path.
        let mut wrong = LocalFsShareStore::random_key();
        // Guarantee distinct keys (random_key may collide in 2^-256 cases).
        if wrong == key_a {
            wrong[0] ^= 0x55;
        }
        let store_b = LocalFsShareStore::new(dir.path(), wrong).unwrap();
        let err = store_b.get(&shares[0].share_id).await;
        assert!(matches!(err, Err(StoreError::Crypto(_))));
    }

    #[tokio::test]
    async fn corrupted_file_fails_to_decrypt() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();

        // Flip a byte deep in the ciphertext.
        let path = store.share_path(&shares[0].share_id);
        let mut bytes = std::fs::read(&path).unwrap();
        let idx = FILE_MAGIC.len() + NONCE_BYTES + 4; // somewhere inside ciphertext
        bytes[idx] ^= 0xFF;
        std::fs::write(&path, &bytes).unwrap();

        let err = store.get(&shares[0].share_id).await;
        assert!(matches!(err, Err(StoreError::Crypto(_))));
    }

    #[tokio::test]
    async fn truncated_file_is_rejected() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();
        let path = store.share_path(&shares[0].share_id);
        std::fs::write(&path, [1u8; 4]).unwrap();
        let err = store.get(&shares[0].share_id).await;
        assert!(matches!(err, Err(StoreError::Crypto(_))));
    }

    #[tokio::test]
    async fn list_ignores_non_share_files() {
        let (store, tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        for s in &shares {
            store.put(s).await.unwrap();
        }
        // Drop unrelated junk in the wallet directory.
        let wallet_dir = tmp.path().join(wallet.to_string());
        std::fs::write(wallet_dir.join("README.txt"), b"not a share").unwrap();
        std::fs::write(wallet_dir.join("garbage.bin"), b"not numeric").unwrap();
        let ids = store.list(&wallet).await.unwrap();
        assert_eq!(ids.len(), 3);
    }

    #[tokio::test]
    async fn empty_root_path_rejected() {
        let err = LocalFsShareStore::new("", [0u8; 32]);
        assert!(matches!(err, Err(StoreError::Config(_))));
    }

    /// Integration check: round-trip a share, then verify the on-disk bytes
    /// are *not* the cleartext (i.e. confirm the file is actually encrypted).
    #[tokio::test]
    async fn on_disk_bytes_are_ciphertext() {
        let (store, _tmp, _key) = store_with_temp();
        let wallet = WalletId::new();
        let shares = sample_stored_shares(wallet, 2, 3);
        store.put(&shares[0]).await.unwrap();
        let path = store.share_path(&shares[0].share_id);
        let on_disk = std::fs::read(&path).unwrap();
        // The serialized JSON would contain "share_id" etc. Confirm absence.
        assert!(!on_disk.windows(8).any(|w| w == b"share_id"));
        // And confirm the magic header is present.
        assert_eq!(&on_disk[..FILE_MAGIC.len()], FILE_MAGIC);
    }
}
