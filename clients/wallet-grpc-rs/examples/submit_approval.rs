//! Sign and submit an approval for a known request_id, using a fixed
//! ed25519 dev seed.
//!
//! **DEV ONLY.** The signing key here is the deterministic seed
//! `[1u8; 32]` — fine for staging / demos, never for production. In
//! production the signing key comes from `qfc-approver`'s key file
//! (`--secret-file`) or an HSM.
//!
//! Usage:
//!
//! ```sh
//! export QFC_SERVER=http://127.0.0.1:9090
//! export QFC_API_KEY=dev-key-1
//! export QFC_REQUEST_ID=01HABCDEFGHJKMNPQRSTVWXYZ0
//! export QFC_APPROVER_ID=01HJKLMNOPQRSTUVWXYZ123456
//! export QFC_MESSAGE_HASH_HEX=<64 hex chars matching the server's request hash>
//! cargo run --example submit_approval
//! ```

#![allow(clippy::result_large_err)] // SdkError embeds tonic::Status; see lib.rs

use std::env;

use ed25519_dalek::{Signer, SigningKey};
use qfc_wallet_grpc::{
    approver_identity, ApprovalDecision, ApproverClient, ApproverIdentity, SdkError, SigningScheme,
    SubmitApprovalParams,
};

// Pinned dev signing seed. The matching public key is deterministic.
const DEV_SEED: [u8; 32] = [1u8; 32];

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, SdkError> {
    if s.len() % 2 != 0 {
        return Err(SdkError::BadInput("odd hex length".into()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    for chunk in s.as_bytes().chunks(2) {
        let s = std::str::from_utf8(chunk)
            .map_err(|e| SdkError::BadInput(format!("non-utf8 hex: {e}")))?;
        out.push(
            u8::from_str_radix(s, 16).map_err(|e| SdkError::BadInput(format!("bad hex: {e}")))?,
        );
    }
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<(), SdkError> {
    let endpoint = env::var("QFC_SERVER").unwrap_or_else(|_| "http://127.0.0.1:9090".to_string());
    let api_key = env::var("QFC_API_KEY").unwrap_or_else(|_| "dev-key-1".to_string());
    let request_id = env::var("QFC_REQUEST_ID").expect("QFC_REQUEST_ID required");
    let approver_id = env::var("QFC_APPROVER_ID")
        .expect("QFC_APPROVER_ID required (register via /approvers first)");
    let message_hash_hex =
        env::var("QFC_MESSAGE_HASH_HEX").expect("QFC_MESSAGE_HASH_HEX required (64 hex chars)");
    let approval_id =
        env::var("QFC_APPROVAL_ID").expect("QFC_APPROVAL_ID required (caller-allocated ULID)");

    let message_hash = hex_decode(&message_hash_hex)?;
    if message_hash.len() != 32 {
        return Err(SdkError::BadInput("message_hash must be 32 bytes".into()));
    }

    let sk = SigningKey::from_bytes(&DEV_SEED);
    let pubkey = sk.verifying_key().to_bytes();
    println!(
        "dev signing pubkey (register an `external` approver with this key first):\n  {}",
        hex_encode(&pubkey)
    );

    let identity = ApproverIdentity {
        identity: Some(approver_identity::Identity::External(
            approver_identity::External {
                id: "dev-approver".into(),
                public_key: pubkey.to_vec(),
                scheme: SigningScheme::Ed25519 as i32,
            },
        )),
    };

    let ts = current_unix_ms();
    let preimage = build_signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        ApprovalDecision::Approve,
        ts,
    );
    let signature = sk.sign(&preimage).to_bytes().to_vec();

    let mut client = ApproverClient::connect(endpoint)
        .api_key(api_key)
        .approver()
        .await?;

    let (recorded, ack_id) = client
        .submit_approval(SubmitApprovalParams {
            request_id,
            approver_id,
            approval_id,
            decision: ApprovalDecision::Approve,
            signature,
            timestamp_unix_ms: ts,
            message_hash,
            identity,
        })
        .await?;
    println!("approval_id: {ack_id}");
    println!("recorded:    {recorded}");
    Ok(())
}

fn current_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    i64::try_from(dur.as_millis()).unwrap_or(i64::MAX)
}

/// Mirror of `qfc_quorum::SignedApproval::signing_preimage`. Any change
/// to the upstream layout must be mirrored here. The on-the-wire bytes
/// are the same the server's verifier will check, so any drift is
/// caught loudly by signature verification failure.
fn build_signing_preimage(
    approval_id: &str,
    request_id: &str,
    message_hash: &[u8],
    decision: ApprovalDecision,
    ts: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(26 + 26 + 32 + 1 + 8);
    buf.extend_from_slice(approval_id.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(request_id.as_bytes());
    buf.push(b'|');
    buf.extend_from_slice(message_hash);
    buf.push(b'|');
    buf.push(match decision {
        ApprovalDecision::Approve => 0x01,
        ApprovalDecision::Reject => 0x00,
        // Unspecified: only present as the proto's zero-variant default.
        // The server rejects it; we emit a sentinel that won't match.
        _ => 0xff,
    });
    buf.push(b'|');
    buf.extend_from_slice(&ts.to_be_bytes());
    buf
}
