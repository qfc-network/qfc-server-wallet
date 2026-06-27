//! End-to-end `ChainAnchor` test against a fake JSON-RPC node (wiremock).
//!
//! No live chain required: we stand up an HTTP mock that answers the four
//! RPC methods the anchor uses, capture the `eth_sendRawTransaction` payload,
//! and assert the broadcast raw transaction (a) recovers to the operator
//! address and (b) carries the expected anchor calldata.

use std::sync::{Arc, Mutex};

use qfc_audit::{AnchorPayload, ChainAnchor, DEFAULT_ANCHOR_GAS_LIMIT};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// A responder that routes by JSON-RPC `method` and records the raw tx it was
/// asked to broadcast. A plain `std::sync::Mutex` (not tokio's) because
/// `Respond::respond` is a synchronous callback.
struct RpcResponder {
    captured_raw_tx: Arc<Mutex<Option<String>>>,
}

impl Respond for RpcResponder {
    fn respond(&self, req: &Request) -> ResponseTemplate {
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        let rpc_method = body.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let result = match rpc_method {
            // chainId 9000 (qfc testnet)
            "eth_chainId" => serde_json::json!("0x2328"),
            "eth_getTransactionCount" => serde_json::json!("0x7"),
            "eth_gasPrice" => serde_json::json!("0x3b9aca00"), // 1 gwei
            "eth_sendRawTransaction" => {
                let raw = body
                    .get("params")
                    .and_then(|p| p.get(0))
                    .and_then(|p| p.as_str())
                    .unwrap()
                    .to_string();
                // Record what we were asked to broadcast.
                self.captured_raw_tx.lock().unwrap().replace(raw);
                // Echo a plausible 32-byte tx hash.
                serde_json::json!(
                    "0xabc0000000000000000000000000000000000000000000000000000000000abc"
                )
            }
            other => panic!("unexpected rpc method: {other}"),
        };
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": result,
        }))
    }
}

#[tokio::test]
async fn submit_broadcasts_recoverable_tx_with_anchor_calldata() {
    let server = MockServer::start().await;
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .respond_with(RpcResponder {
            captured_raw_tx: captured.clone(),
        })
        .mount(&server)
        .await;

    // Fixed operator key → deterministic operator address.
    let key = [0x11u8; 32];
    let anchor = ChainAnchor::new(
        server.uri(),
        &key,
        None, // to defaults to operator self-address
        None, // chain_id auto-queried (mock returns 9000)
        DEFAULT_ANCHOR_GAS_LIMIT,
        None, // gas_price auto-queried
    )
    .unwrap();

    let payload = AnchorPayload {
        date_utc: "2026-06-27".into(),
        chain_head_hex: hex::encode([0xcdu8; 32]),
        head_event_id: None,
        event_count: 42,
    };

    let tx_hash = anchor.submit(payload.clone()).await.unwrap();
    assert!(tx_hash.starts_with("0x"));

    // Decode the captured raw tx and assert structure.
    let raw_hex = captured
        .lock()
        .unwrap()
        .clone()
        .expect("a tx was broadcast");
    let raw = hex::decode(raw_hex.strip_prefix("0x").unwrap()).unwrap();

    // Recover the sender from the legacy EIP-155 signed tx and check it
    // equals the operator address.
    let recovered = recover_sender(&raw, 9000);
    assert_eq!(
        recovered,
        anchor.operator_address(),
        "broadcast tx must be signed by the operator key"
    );

    // The calldata (RLP `data` field) must carry our anchor commitment.
    let data = extract_legacy_data_field(&raw);
    assert_eq!(&data[..20], b"qfc-audit-anchor-v1\0");
    assert_eq!(&data[20..52], &[0xcdu8; 32]);
    assert_eq!(&data[52..60], &42u64.to_be_bytes());
    assert_eq!(&data[60..], b"2026-06-27");
}

// --- minimal RLP-decode + ecrecover helpers, test-only ----------------------

/// Decode one RLP item at `pos`, returning `(payload_bytes, next_pos, is_list)`.
fn rlp_item(buf: &[u8], pos: usize) -> (&[u8], usize, bool) {
    let b = buf[pos];
    if b < 0x80 {
        (&buf[pos..pos + 1], pos + 1, false)
    } else if b < 0xb8 {
        let len = (b - 0x80) as usize;
        (&buf[pos + 1..pos + 1 + len], pos + 1 + len, false)
    } else if b < 0xc0 {
        let ll = (b - 0xb7) as usize;
        let len = be_usize(&buf[pos + 1..pos + 1 + ll]);
        let start = pos + 1 + ll;
        (&buf[start..start + len], start + len, false)
    } else if b < 0xf8 {
        let len = (b - 0xc0) as usize;
        (&buf[pos + 1..pos + 1 + len], pos + 1 + len, true)
    } else {
        let ll = (b - 0xf7) as usize;
        let len = be_usize(&buf[pos + 1..pos + 1 + ll]);
        let start = pos + 1 + ll;
        (&buf[start..start + len], start + len, true)
    }
}

fn be_usize(b: &[u8]) -> usize {
    b.iter().fold(0usize, |acc, &x| (acc << 8) | x as usize)
}

/// Split a legacy tx list into its 9 field payloads.
fn legacy_fields(raw: &[u8]) -> Vec<Vec<u8>> {
    let (list_payload, _, is_list) = rlp_item(raw, 0);
    assert!(is_list, "tx must be an RLP list");
    let mut fields = Vec::new();
    let mut p = 0;
    while p < list_payload.len() {
        let (item, next, _) = rlp_item(list_payload, p);
        fields.push(item.to_vec());
        p = next;
    }
    assert_eq!(fields.len(), 9, "legacy tx has 9 fields");
    fields
}

fn extract_legacy_data_field(raw: &[u8]) -> Vec<u8> {
    legacy_fields(raw)[5].clone()
}

/// Recover the 20-byte sender address from a signed legacy EIP-155 tx.
fn recover_sender(raw: &[u8], chain_id: u64) -> [u8; 20] {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    use sha3::{Digest, Keccak256};

    let fields = legacy_fields(raw);
    let v = be_usize(&fields[6]) as u64;
    let r = &fields[7];
    let s = &fields[8];

    // Re-derive the signing hash: rlp([nonce,gasPrice,gas,to,value,data,chainId,0,0]).
    let mut sign_fields = Vec::new();
    for f in fields.iter().take(6) {
        rlp_encode_string_or_scalar(f, &mut sign_fields);
    }
    rlp_encode_scalar_u64(chain_id, &mut sign_fields);
    rlp_encode_scalar_u64(0, &mut sign_fields);
    rlp_encode_scalar_u64(0, &mut sign_fields);
    let mut unsigned = Vec::new();
    rlp_encode_list(&sign_fields, &mut unsigned);
    let sighash = Keccak256::digest(&unsigned);

    let recid_byte = (v - 35 - chain_id * 2) as u8;
    let recid = RecoveryId::from_byte(recid_byte).unwrap();
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&left_pad32(r));
    sig_bytes[32..].copy_from_slice(&left_pad32(s));
    let sig = Signature::from_bytes((&sig_bytes).into()).unwrap();
    let vk = VerifyingKey::recover_from_prehash(&sighash, &sig, recid).unwrap();
    let point = vk.to_encoded_point(false);
    let hash = Keccak256::digest(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

fn left_pad32(b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    out
}

// Re-encode helpers mirroring the producer side (string for the field bytes
// as already-stripped scalars / fixed-width; the decoded field payloads are
// the canonical inner bytes, so we re-wrap with a string header).
fn rlp_encode_string_or_scalar(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let be = bytes.len().to_be_bytes();
        let first = be.iter().position(|&x| x != 0).unwrap();
        let lb = &be[first..];
        out.push(0xb7 + lb.len() as u8);
        out.extend_from_slice(lb);
        out.extend_from_slice(bytes);
    }
}

fn rlp_encode_scalar_u64(v: u64, out: &mut Vec<u8>) {
    let be = v.to_be_bytes();
    let start = be.iter().position(|&x| x != 0).unwrap_or(be.len());
    rlp_encode_string_or_scalar(&be[start..], out);
}

fn rlp_encode_list(payload: &[u8], out: &mut Vec<u8>) {
    if payload.len() <= 55 {
        out.push(0xc0 + payload.len() as u8);
    } else {
        let be = payload.len().to_be_bytes();
        let first = be.iter().position(|&x| x != 0).unwrap();
        let lb = &be[first..];
        out.push(0xf7 + lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.extend_from_slice(payload);
}
