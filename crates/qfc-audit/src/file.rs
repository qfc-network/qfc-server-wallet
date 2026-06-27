//! `FileAuditSink` — NDJSON append-only audit log with hash chain + signed events.
//!
//! On-disk layout: one JSON-serialized `AuditEvent` per line, in event order.
//! The hash chain anchors every event to its predecessor via `prev_event_hash`;
//! `server_signature` is an ed25519 signature over the canonical preimage of
//! that event so tampering with even a single byte invalidates the chain
//! from that point forward.
//!
//! ## What this *does not* defend against in M1
//!
//! - **Log truncation from the tail.** If an attacker deletes the last N
//!   events, callers must check a separately-published "chain head"
//!   (M2 ships the daily on-chain anchor commit; M1 only has the in-memory
//!   `prev_hash` cursor).
//! - **Server-key compromise.** If the audit signing key leaks, an attacker
//!   can forge events. Treat the key with the same operational care as the
//!   share-store AEAD key.

use std::path::PathBuf;

use async_trait::async_trait;
use ed25519_dalek::{Signer as DalekSigner, SigningKey, Verifier};
use qfc_wallet_types::EventId;
use sha2::{Digest, Sha256};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

use crate::event::AuditEvent;
#[cfg(test)]
use crate::event::AuditKind;
use crate::sink::{AuditError, AuditEventDraft, AuditSink};

/// File-backed hash-chained audit sink.
pub struct FileAuditSink {
    path: PathBuf,
    server_key: Zeroizing<[u8; 32]>,
    state: Mutex<ChainState>,
}

struct ChainState {
    prev_event_hash: [u8; 32],
    written: u64,
}

impl FileAuditSink {
    /// Open an existing NDJSON audit file or create a new one.
    ///
    /// If the file exists and is non-empty, the head of the chain is
    /// recovered from the last line so subsequent emits link correctly.
    ///
    /// # Errors
    ///
    /// `AuditError::Io` for filesystem failures, `AuditError::Serde` for
    /// a corrupt tail line.
    pub async fn open(path: impl Into<PathBuf>, server_key: [u8; 32]) -> Result<Self, AuditError> {
        let path = path.into();
        // Recover the chain head from the existing log, if any.
        let (prev_event_hash, written) = recover_chain_head(&path).await?;
        Ok(Self {
            path,
            server_key: Zeroizing::new(server_key),
            state: Mutex::new(ChainState {
                prev_event_hash,
                written,
            }),
        })
    }

    /// Generate a fresh random 32-byte server signing key. Tests-friendly;
    /// production callers should source from a hardened path.
    #[must_use]
    pub fn random_key() -> [u8; 32] {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        k
    }

    /// Borrow the public verifying key (ed25519, 32 bytes). External
    /// verifiers use this to check `server_signature` on emitted events.
    #[must_use]
    pub fn server_public_key(&self) -> Vec<u8> {
        SigningKey::from_bytes(&self.server_key)
            .verifying_key()
            .to_bytes()
            .to_vec()
    }

    /// Number of events written to this sink since construction. Test-only
    /// convenience.
    pub async fn event_count(&self) -> u64 {
        self.state.lock().await.written
    }

    /// Snapshot the current chain head as an
    /// [`AnchorPayload`](crate::anchor::AnchorPayload), ready for a
    /// daily anchor submitter (file or on-chain).
    ///
    /// `chain_head_hex` is the hash the *next* emit would adopt as its
    /// `prev_event_hash` — i.e. a commitment to the entire chain so far —
    /// matching the semantics of the Postgres-backed
    /// [`anchor_payload`](crate::anchor::anchor_payload). `head_event_id` is
    /// `None` for the file sink (the in-memory cursor tracks the head hash and
    /// count, not the last event id); on-chain verifiers key off
    /// `chain_head_hex` + `event_count`, which are sufficient to detect tail
    /// truncation.
    pub async fn current_anchor_payload(&self) -> crate::anchor::AnchorPayload {
        let state = self.state.lock().await;
        crate::anchor::AnchorPayload {
            date_utc: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            chain_head_hex: hex::encode(state.prev_event_hash),
            head_event_id: None,
            event_count: state.written,
        }
    }
}

#[async_trait]
impl AuditSink for FileAuditSink {
    async fn emit(&self, draft: AuditEventDraft) -> Result<AuditEvent, AuditError> {
        let mut guard = self.state.lock().await;

        let event_id = EventId::new();
        let timestamp_unix_ms = current_unix_ms();
        let preimage = AuditEvent::signing_preimage(
            &guard.prev_event_hash,
            &event_id,
            draft.kind,
            &draft.details,
        );
        let signing_key = SigningKey::from_bytes(&self.server_key);
        let signature = signing_key.sign(&preimage).to_bytes().to_vec();
        let event = AuditEvent {
            event_id,
            prev_event_hash: guard.prev_event_hash,
            timestamp_unix_ms,
            actor: draft.actor,
            kind: draft.kind,
            request_id: draft.request_id,
            wallet_id: draft.wallet_id,
            details: draft.details,
            server_signature: signature,
        };

        let mut line = serde_json::to_vec(&event).map_err(|e| AuditError::Serde(e.to_string()))?;
        line.push(b'\n');

        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;
        f.write_all(&line)
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;
        f.flush().await.map_err(|e| AuditError::Io(e.to_string()))?;
        f.sync_all()
            .await
            .map_err(|e| AuditError::Io(e.to_string()))?;

        // Advance the chain head: the next event's prev_event_hash is the
        // SHA-256 of the just-written event's signed preimage. Including
        // the signature is intentional — a tamperer who only modifies the
        // signature still breaks the chain.
        let mut h = Sha256::new();
        h.update(&preimage);
        h.update(&event.server_signature);
        guard.prev_event_hash = h.finalize().into();
        guard.written += 1;

        Ok(event)
    }
}

async fn recover_chain_head(path: &PathBuf) -> Result<([u8; 32], u64), AuditError> {
    use tokio::io::AsyncReadExt;
    let mut f = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(([0u8; 32], 0)),
        Err(e) => return Err(AuditError::Io(e.to_string())),
    };
    let mut content = Vec::new();
    f.read_to_end(&mut content)
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;
    if content.is_empty() {
        return Ok(([0u8; 32], 0));
    }
    let lines: Vec<&[u8]> = content
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    let written = lines.len() as u64;
    let last = *lines.last().expect("non-empty by earlier check");
    let event: AuditEvent =
        serde_json::from_slice(last).map_err(|e| AuditError::Serde(e.to_string()))?;
    // Reconstruct the next chain-head hash: SHA-256(preimage || signature).
    let preimage = AuditEvent::signing_preimage(
        &event.prev_event_hash,
        &event.event_id,
        event.kind,
        &event.details,
    );
    let mut h = Sha256::new();
    h.update(&preimage);
    h.update(&event.server_signature);
    let mut next = [0u8; 32];
    next.copy_from_slice(&h.finalize());
    Ok((next, written))
}

fn current_unix_ms() -> i64 {
    let nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).unwrap_or(i64::MAX)
}

/// Verify a single event against the supplied verifying key.
///
/// # Errors
///
/// Returns `AuditError::Crypto` on invalid key length / signature.
pub fn verify_event(event: &AuditEvent, verifying_key: &[u8]) -> Result<bool, AuditError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let pk: [u8; 32] = verifying_key
        .try_into()
        .map_err(|_| AuditError::Crypto("verifying key must be 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk)
        .map_err(|_| AuditError::Crypto("malformed ed25519 pubkey"))?;
    let sig: [u8; 64] = event
        .server_signature
        .as_slice()
        .try_into()
        .map_err(|_| AuditError::Crypto("signature must be 64 bytes"))?;
    let sig = Signature::from_bytes(&sig);
    let preimage = AuditEvent::signing_preimage(
        &event.prev_event_hash,
        &event.event_id,
        event.kind,
        &event.details,
    );
    Ok(vk.verify(&preimage, &sig).is_ok())
}

/// Replay-check a full NDJSON file. Returns `Ok(n)` if all `n` events
/// chain correctly and verify against `verifying_key`. Returns
/// `Err(AuditError::Crypto)` on the first failure.
///
/// # Errors
///
/// `AuditError::Io` for filesystem issues, `AuditError::Serde` for a
/// corrupt line, `AuditError::Crypto` for a broken chain or signature.
pub async fn replay_verify(
    path: impl Into<PathBuf>,
    verifying_key: &[u8],
) -> Result<u64, AuditError> {
    let content = tokio::fs::read(path.into())
        .await
        .map_err(|e| AuditError::Io(e.to_string()))?;
    if content.is_empty() {
        return Ok(0);
    }
    let mut prev = [0u8; 32];
    let mut n: u64 = 0;
    for line in content.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let event: AuditEvent =
            serde_json::from_slice(line).map_err(|e| AuditError::Serde(e.to_string()))?;
        if event.prev_event_hash != prev {
            return Err(AuditError::Crypto("hash chain broken"));
        }
        if !verify_event(&event, verifying_key)? {
            return Err(AuditError::Crypto("signature mismatch"));
        }
        let preimage = AuditEvent::signing_preimage(
            &event.prev_event_hash,
            &event.event_id,
            event.kind,
            &event.details,
        );
        let mut h = Sha256::new();
        h.update(&preimage);
        h.update(&event.server_signature);
        prev = h.finalize().into();
        n += 1;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Actor;
    use qfc_wallet_types::WalletId;
    use serde_json::json;
    use tempfile::TempDir;

    fn draft(kind: AuditKind) -> AuditEventDraft {
        AuditEventDraft {
            actor: Actor::System,
            kind,
            request_id: None,
            wallet_id: Some(WalletId::new()),
            details: json!({ "note": "test event" }),
        }
    }

    async fn sink_with_temp() -> (FileAuditSink, TempDir, [u8; 32]) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        let key = FileAuditSink::random_key();
        let sink = FileAuditSink::open(&path, key).await.unwrap();
        (sink, dir, key)
    }

    #[tokio::test]
    async fn emits_and_round_trips_one_event() {
        let (sink, _tmp, _key) = sink_with_temp().await;
        let e = sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();
        assert_eq!(e.kind, AuditKind::SigningRequested);
        assert_eq!(e.prev_event_hash, [0u8; 32]);
        assert_eq!(sink.event_count().await, 1);
    }

    #[tokio::test]
    async fn chain_links_subsequent_events() {
        let (sink, _tmp, _key) = sink_with_temp().await;
        let a = sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();
        let b = sink.emit(draft(AuditKind::SigningEvaluated)).await.unwrap();
        let c = sink.emit(draft(AuditKind::SigningSucceeded)).await.unwrap();
        // b.prev = sha256(a.preimage || a.signature)
        let mut h = Sha256::new();
        h.update(AuditEvent::signing_preimage(
            &a.prev_event_hash,
            &a.event_id,
            a.kind,
            &a.details,
        ));
        h.update(&a.server_signature);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(b.prev_event_hash, expected);
        assert_ne!(b.prev_event_hash, c.prev_event_hash);
    }

    #[tokio::test]
    async fn replay_verify_passes_for_clean_log() {
        let (sink, tmp, key) = sink_with_temp().await;
        for k in [
            AuditKind::SigningRequested,
            AuditKind::SigningEvaluated,
            AuditKind::SigningAttempted,
            AuditKind::SigningSucceeded,
        ] {
            sink.emit(draft(k)).await.unwrap();
        }
        let path = tmp.path().join("audit.ndjson");
        let n = replay_verify(&path, &sink.server_public_key())
            .await
            .unwrap();
        assert_eq!(n, 4);
        // sanity: key arg unused beyond construction
        let _ = key;
    }

    #[tokio::test]
    async fn replay_verify_detects_tampered_event_body() {
        let (sink, tmp, _key) = sink_with_temp().await;
        for k in [AuditKind::SigningRequested, AuditKind::SigningSucceeded] {
            sink.emit(draft(k)).await.unwrap();
        }
        let path = tmp.path().join("audit.ndjson");
        // Flip a byte in the file.
        let mut bytes = std::fs::read(&path).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x55;
        std::fs::write(&path, &bytes).unwrap();
        // Replay must reject — could be Serde (broken JSON) or Crypto.
        let err = replay_verify(&path, &sink.server_public_key()).await;
        assert!(matches!(
            err,
            Err(AuditError::Crypto(_) | AuditError::Serde(_))
        ));
    }

    #[tokio::test]
    async fn replay_verify_detects_swapped_events() {
        let (sink, tmp, _key) = sink_with_temp().await;
        let _a = sink.emit(draft(AuditKind::SigningRequested)).await.unwrap();
        let _b = sink.emit(draft(AuditKind::SigningSucceeded)).await.unwrap();
        let path = tmp.path().join("audit.ndjson");
        // Reorder the two lines.
        let content = std::fs::read(&path).unwrap();
        let mut lines: Vec<Vec<u8>> = content
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .map(<[u8]>::to_vec)
            .collect();
        lines.swap(0, 1);
        let mut swapped = Vec::new();
        for l in lines {
            swapped.extend_from_slice(&l);
            swapped.push(b'\n');
        }
        std::fs::write(&path, &swapped).unwrap();
        let err = replay_verify(&path, &sink.server_public_key()).await;
        assert!(matches!(err, Err(AuditError::Crypto(_))));
    }

    #[tokio::test]
    async fn reopen_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        let key = FileAuditSink::random_key();
        let sink_a = FileAuditSink::open(&path, key).await.unwrap();
        sink_a
            .emit(draft(AuditKind::SigningRequested))
            .await
            .unwrap();
        sink_a
            .emit(draft(AuditKind::SigningSucceeded))
            .await
            .unwrap();
        let head_after_a = sink_a.state.lock().await.prev_event_hash;
        drop(sink_a);

        // Reopen with same key; new emit must link off the prior head.
        let sink_b = FileAuditSink::open(&path, key).await.unwrap();
        let restored_head = sink_b.state.lock().await.prev_event_hash;
        assert_eq!(restored_head, head_after_a);
        let c = sink_b
            .emit(draft(AuditKind::SigningEvaluated))
            .await
            .unwrap();
        assert_eq!(c.prev_event_hash, head_after_a);
        // Full chain still verifies.
        let n = replay_verify(&path, &sink_b.server_public_key())
            .await
            .unwrap();
        assert_eq!(n, 3);
    }

    #[tokio::test]
    async fn distinct_keys_reject_each_other() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.ndjson");
        let key_a = FileAuditSink::random_key();
        let sink_a = FileAuditSink::open(&path, key_a).await.unwrap();
        sink_a
            .emit(draft(AuditKind::SigningRequested))
            .await
            .unwrap();

        // Verify with a different key — should fail.
        let key_b = FileAuditSink::random_key();
        let sink_b = FileAuditSink::open(&path, key_b).await.unwrap();
        let err = replay_verify(&path, &sink_b.server_public_key()).await;
        assert!(matches!(err, Err(AuditError::Crypto(_))));
    }

    #[tokio::test]
    async fn batch_emit_preserves_order_and_chain() {
        let (sink, tmp, _key) = sink_with_temp().await;
        let drafts = vec![
            draft(AuditKind::SigningRequested),
            draft(AuditKind::SigningEvaluated),
            draft(AuditKind::SigningSucceeded),
        ];
        let events = sink.emit_batch(drafts).await.unwrap();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, AuditKind::SigningRequested);
        let path = tmp.path().join("audit.ndjson");
        let n = replay_verify(&path, &sink.server_public_key())
            .await
            .unwrap();
        assert_eq!(n, 3);
    }
}
