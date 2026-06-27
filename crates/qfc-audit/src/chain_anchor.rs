//! On-chain audit anchor submitter — the real chain-side of RFC §2.6.
//!
//! [`LocalFileAnchor`](crate::anchor::LocalFileAnchor) was the deferred stub:
//! it wrote each daily [`AnchorPayload`] to a
//! local JSONL file because publishing it on-chain was "blocked on `qfc-core`
//! integration". This module closes that gap **without** taking a `qfc-core`
//! workspace dependency.
//!
//! qfc-core exposes transaction submission through its EVM-compatible JSON-RPC
//! (`eth_sendRawTransaction`) — the same surface `qfc-cli` and the SDKs use.
//! So [`ChainAnchor`] speaks plain Ethereum JSON-RPC: it builds a legacy
//! EIP-155 transaction that carries the anchor commitment in its `data` field,
//! signs it with a secp256k1 operator key, and broadcasts the raw bytes. The
//! transaction is a zero-value self-send; the only payload is the calldata.
//!
//! Everything here is built from crates already in the workspace tree
//! (`k256`, `sha3`, `reqwest`) — no `alloy`/`ethers`, no FFI, matching the
//! RFC §1.5 pure-Rust posture. RLP is hand-rolled (~40 lines) and pinned
//! against the canonical EIP-155 test vector in the unit tests.
//!
//! ## Calldata layout
//!
//! ```text
//! b"qfc-audit-anchor-v1\0" ‖ chain_head[32] ‖ event_count_be[8] ‖ date_utc(ascii)
//! ```
//!
//! A verifier reads the transaction `input`, splits off the 20-byte domain
//! tag, and recovers `(chain_head, event_count, date)` — then checks it
//! against the audit log's own head. The on-chain copy makes silent
//! truncation by a chain operator detectable.

use sha3::{Digest, Keccak256};

use crate::anchor::AnchorPayload;
use crate::sink::AuditError;

/// Domain-separation prefix for anchor calldata. 20 bytes incl. the NUL.
const ANCHOR_CALLDATA_TAG: &[u8] = b"qfc-audit-anchor-v1\0";

/// Default gas limit for an anchor self-send. 21000 base + calldata; the
/// payload is ~70 bytes so this is generous headroom.
pub const DEFAULT_ANCHOR_GAS_LIMIT: u64 = 100_000;

// ---------------------------------------------------------------------------
// Minimal hand-rolled RLP (encode-only). Validated against the EIP-155 vector.
// ---------------------------------------------------------------------------

/// Encode an RLP length prefix: `short_base` is `0x80` for byte strings,
/// `0xc0` for lists.
fn rlp_len_prefix(len: usize, short_base: u8, out: &mut Vec<u8>) {
    if len <= 55 {
        out.push(short_base + u8::try_from(len).expect("len <= 55 fits in u8"));
    } else {
        let be = len.to_be_bytes();
        let first = be.iter().position(|&b| b != 0).unwrap_or(be.len() - 1);
        let lb = &be[first..];
        out.push(
            short_base + 55 + u8::try_from(lb.len()).expect("length-of-length <= 8 fits in u8"),
        );
        out.extend_from_slice(lb);
    }
}

/// Encode a byte string (no leading-zero stripping — used for fixed-width
/// fields like the 20-byte `to` address and the `data` blob).
fn rlp_string(bytes: &[u8], out: &mut Vec<u8>) {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        out.push(bytes[0]);
    } else {
        rlp_len_prefix(bytes.len(), 0x80, out);
        out.extend_from_slice(bytes);
    }
}

/// Encode a big-endian integer as an RLP scalar: strip leading zero bytes,
/// then string-encode. `0` becomes the empty string `0x80`.
fn rlp_scalar(bytes_be: &[u8], out: &mut Vec<u8>) {
    let start = bytes_be
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(bytes_be.len());
    rlp_string(&bytes_be[start..], out);
}

fn rlp_u64(v: u64, out: &mut Vec<u8>) {
    rlp_scalar(&v.to_be_bytes(), out);
}

fn rlp_u128(v: u128, out: &mut Vec<u8>) {
    rlp_scalar(&v.to_be_bytes(), out);
}

/// Wrap an already-encoded field payload in an RLP list header.
fn rlp_list(payload: &[u8], out: &mut Vec<u8>) {
    rlp_len_prefix(payload.len(), 0xc0, out);
    out.extend_from_slice(payload);
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(bytes);
    h.finalize().into()
}

/// A signed legacy transaction, ready for `eth_sendRawTransaction`.
struct SignedLegacyTx {
    /// `0x`-prefixed hex of the RLP-encoded signed transaction.
    raw_hex: String,
    /// `0x`-prefixed keccak256 of the signed bytes (the transaction hash).
    tx_hash_hex: String,
}

/// Build + sign a legacy EIP-155 transaction.
///
/// Field order follows the spec: `[nonce, gasPrice, gasLimit, to, value,
/// data, chainId, 0, 0]` for the signing hash, then `[…, v, r, s]` for the
/// broadcast envelope.
#[allow(clippy::too_many_arguments)] // mirrors the 9-field EIP-155 tx shape
fn sign_legacy_tx(
    signing_key: &k256::ecdsa::SigningKey,
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Result<SignedLegacyTx, AuditError> {
    // Common prefix fields shared by the signing-hash list and the final list.
    let mut prefix = Vec::with_capacity(128);
    rlp_u64(nonce, &mut prefix);
    rlp_u128(gas_price, &mut prefix);
    rlp_u64(gas_limit, &mut prefix);
    rlp_string(to, &mut prefix);
    rlp_u128(value, &mut prefix);
    rlp_string(data, &mut prefix);

    // Signing payload: prefix ‖ chainId ‖ 0 ‖ 0  (EIP-155).
    let mut sign_fields = prefix.clone();
    rlp_u64(chain_id, &mut sign_fields);
    rlp_u64(0, &mut sign_fields);
    rlp_u64(0, &mut sign_fields);
    let mut unsigned = Vec::with_capacity(sign_fields.len() + 4);
    rlp_list(&sign_fields, &mut unsigned);
    let sighash = keccak256(&unsigned);

    let (sig, recid) = signing_key
        .sign_prehash_recoverable(&sighash)
        .map_err(|_| AuditError::Crypto("anchor tx signing failed"))?;
    let r = sig.r().to_bytes();
    let s = sig.s().to_bytes();
    // EIP-155: v = recovery_id + 35 + chain_id * 2.
    let v = u64::from(recid.to_byte()) + 35 + chain_id * 2;

    // Broadcast payload: prefix ‖ v ‖ r ‖ s.
    let mut signed_fields = prefix;
    rlp_u64(v, &mut signed_fields);
    rlp_scalar(&r, &mut signed_fields);
    rlp_scalar(&s, &mut signed_fields);
    let mut signed = Vec::with_capacity(signed_fields.len() + 4);
    rlp_list(&signed_fields, &mut signed);

    Ok(SignedLegacyTx {
        raw_hex: format!("0x{}", hex::encode(&signed)),
        tx_hash_hex: format!("0x{}", hex::encode(keccak256(&signed))),
    })
}

/// Derive the 20-byte EVM address for a secp256k1 signing key.
fn evm_address(signing_key: &k256::ecdsa::SigningKey) -> [u8; 20] {
    let vk = signing_key.verifying_key();
    let point = vk.to_encoded_point(false); // 0x04 ‖ X ‖ Y, 65 bytes
    let hash = keccak256(&point.as_bytes()[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    addr
}

/// Build the anchor calldata: domain tag ‖ `chain_head` ‖ `event_count` ‖ date.
fn anchor_calldata(payload: &AnchorPayload) -> Result<Vec<u8>, AuditError> {
    let head = hex::decode(&payload.chain_head_hex)
        .map_err(|e| AuditError::Serde(format!("anchor chain_head_hex not hex: {e}")))?;
    if head.len() != 32 {
        return Err(AuditError::Serde(format!(
            "anchor chain_head_hex must be 32 bytes, got {}",
            head.len()
        )));
    }
    let mut data = Vec::with_capacity(ANCHOR_CALLDATA_TAG.len() + 32 + 8 + payload.date_utc.len());
    data.extend_from_slice(ANCHOR_CALLDATA_TAG);
    data.extend_from_slice(&head);
    data.extend_from_slice(&payload.event_count.to_be_bytes());
    data.extend_from_slice(payload.date_utc.as_bytes());
    Ok(data)
}

// ---------------------------------------------------------------------------
// JSON-RPC client (reqwest, no extra deps).
// ---------------------------------------------------------------------------

/// Minimal Ethereum JSON-RPC client — just the four methods the anchor needs.
#[derive(Clone, Debug)]
struct EvmRpc {
    http: reqwest::Client,
    url: String,
}

impl EvmRpc {
    fn new(url: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            url,
        }
    }

    async fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, AuditError> {
        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        });
        let resp = self
            .http
            .post(&self.url)
            .json(&body)
            .send()
            .await
            .map_err(|e| AuditError::Io(format!("rpc {method} send: {e}")))?;
        let value: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| AuditError::Io(format!("rpc {method} decode: {e}")))?;
        if let Some(err) = value.get("error") {
            if !err.is_null() {
                return Err(AuditError::Io(format!("rpc {method} error: {err}")));
            }
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| AuditError::Io(format!("rpc {method}: missing result")))
    }

    /// Parse a `0x`-prefixed hex quantity into a `u128`.
    fn parse_quantity(method: &str, v: &serde_json::Value) -> Result<u128, AuditError> {
        let s = v
            .as_str()
            .ok_or_else(|| AuditError::Io(format!("rpc {method}: result not a string")))?;
        let hex = s.strip_prefix("0x").unwrap_or(s);
        u128::from_str_radix(hex, 16)
            .map_err(|e| AuditError::Io(format!("rpc {method}: bad quantity {s:?}: {e}")))
    }

    async fn chain_id(&self) -> Result<u64, AuditError> {
        let v = self.call("eth_chainId", serde_json::json!([])).await?;
        let q = Self::parse_quantity("eth_chainId", &v)?;
        u64::try_from(q).map_err(|_| AuditError::Io("eth_chainId overflows u64".into()))
    }

    async fn transaction_count(&self, address: &[u8; 20]) -> Result<u64, AuditError> {
        let addr = format!("0x{}", hex::encode(address));
        let v = self
            .call(
                "eth_getTransactionCount",
                serde_json::json!([addr, "pending"]),
            )
            .await?;
        let q = Self::parse_quantity("eth_getTransactionCount", &v)?;
        u64::try_from(q).map_err(|_| AuditError::Io("nonce overflows u64".into()))
    }

    async fn gas_price(&self) -> Result<u128, AuditError> {
        let v = self.call("eth_gasPrice", serde_json::json!([])).await?;
        Self::parse_quantity("eth_gasPrice", &v)
    }

    async fn send_raw_transaction(&self, raw_hex: &str) -> Result<String, AuditError> {
        let v = self
            .call("eth_sendRawTransaction", serde_json::json!([raw_hex]))
            .await?;
        v.as_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| AuditError::Io("eth_sendRawTransaction: result not a tx hash".into()))
    }
}

// ---------------------------------------------------------------------------
// ChainAnchor
// ---------------------------------------------------------------------------

/// On-chain anchor submitter. Drop-in replacement for
/// [`LocalFileAnchor`](crate::anchor::LocalFileAnchor) — same
/// `submit(AnchorPayload)` shape, so it wires straight into
/// [`daily_anchor_commit_job_with_reader`](crate::anchor::daily_anchor_commit_job_with_reader).
#[derive(Clone)]
pub struct ChainAnchor {
    rpc: EvmRpc,
    signing_key: k256::ecdsa::SigningKey,
    operator_address: [u8; 20],
    /// Anchor commitments are sent here. Defaults to the operator's own
    /// address (a zero-value self-send) when not overridden.
    to: [u8; 20],
    /// If `Some`, skip the `eth_chainId` round-trip and use this directly.
    chain_id: Option<u64>,
    gas_limit: u64,
    /// If `Some`, skip `eth_gasPrice` and use this directly (wei).
    gas_price: Option<u128>,
}

impl std::fmt::Debug for ChainAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the signing key.
        f.debug_struct("ChainAnchor")
            .field("url", &self.rpc.url)
            .field(
                "operator",
                &format!("0x{}", hex::encode(self.operator_address)),
            )
            .field("to", &format!("0x{}", hex::encode(self.to)))
            .field("chain_id", &self.chain_id)
            .field("gas_limit", &self.gas_limit)
            .field("gas_price", &self.gas_price)
            .finish_non_exhaustive() // signing_key deliberately omitted
    }
}

impl ChainAnchor {
    /// Construct from a JSON-RPC URL and a 32-byte secp256k1 operator key.
    ///
    /// `to` defaults to the operator's own address when `None`. `chain_id`
    /// and `gas_price` are auto-queried from the node when `None`.
    ///
    /// # Errors
    ///
    /// [`AuditError::Crypto`] if `operator_key` is not a valid secp256k1
    /// scalar.
    pub fn new(
        rpc_url: impl Into<String>,
        operator_key: &[u8; 32],
        to: Option<[u8; 20]>,
        chain_id: Option<u64>,
        gas_limit: u64,
        gas_price: Option<u128>,
    ) -> Result<Self, AuditError> {
        let signing_key = k256::ecdsa::SigningKey::from_bytes(operator_key.into())
            .map_err(|_| AuditError::Crypto("anchor operator key invalid"))?;
        let operator_address = evm_address(&signing_key);
        Ok(Self {
            rpc: EvmRpc::new(rpc_url.into()),
            signing_key,
            operator_address,
            to: to.unwrap_or(operator_address),
            chain_id,
            gas_limit,
            gas_price,
        })
    }

    /// The operator's 20-byte EVM address (the funded sender).
    #[must_use]
    pub fn operator_address(&self) -> [u8; 20] {
        self.operator_address
    }

    /// `0x`-prefixed hex of [`operator_address`](Self::operator_address).
    #[must_use]
    pub fn operator_address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.operator_address))
    }

    /// Submit one anchor payload on-chain. Returns the `0x`-prefixed
    /// transaction hash the node accepted.
    ///
    /// # Errors
    ///
    /// [`AuditError::Io`] on any RPC failure, [`AuditError::Serde`] on a
    /// malformed payload, [`AuditError::Crypto`] on a signing failure.
    pub async fn submit(&self, payload: AnchorPayload) -> Result<String, AuditError> {
        let chain_id = match self.chain_id {
            Some(c) => c,
            None => self.rpc.chain_id().await?,
        };
        let nonce = self.rpc.transaction_count(&self.operator_address).await?;
        let gas_price = match self.gas_price {
            Some(g) => g,
            None => self.rpc.gas_price().await?,
        };
        let data = anchor_calldata(&payload)?;
        let tx = sign_legacy_tx(
            &self.signing_key,
            nonce,
            gas_price,
            self.gas_limit,
            &self.to,
            0,
            &data,
            chain_id,
        )?;
        let accepted = self.rpc.send_raw_transaction(&tx.raw_hex).await?;
        tracing::info!(
            tx_hash = %accepted,
            local_tx_hash = %tx.tx_hash_hex,
            date = %payload.date_utc,
            chain_head = %payload.chain_head_hex,
            event_count = payload.event_count,
            "audit anchor committed on-chain"
        );
        Ok(accepted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical EIP-155 worked example (spec, Vitalik's appendix):
    /// nonce 9, gasPrice 20 gwei, gas 21000, to 0x3535…35, value 1 ETH,
    /// empty data, chainId 1, key 0x46…46. The expected raw tx is fixed.
    #[test]
    fn eip155_reference_vector() {
        let key = [0x46u8; 32];
        let sk = k256::ecdsa::SigningKey::from_bytes((&key).into()).unwrap();
        let to_bytes = hex::decode("3535353535353535353535353535353535353535").unwrap();
        let mut to = [0u8; 20];
        to.copy_from_slice(&to_bytes);
        let tx = sign_legacy_tx(
            &sk,
            9,
            20_000_000_000,
            21_000,
            &to,
            1_000_000_000_000_000_000,
            &[],
            1,
        )
        .unwrap();
        assert_eq!(
            tx.raw_hex,
            "0xf86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
        );
    }

    #[test]
    fn evm_address_matches_known_key() {
        // Private key 0x4646...46 → well-known address 0x9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f.
        let key = [0x46u8; 32];
        let sk = k256::ecdsa::SigningKey::from_bytes((&key).into()).unwrap();
        let addr = evm_address(&sk);
        assert_eq!(
            hex::encode(addr),
            "9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f"
        );
    }

    #[test]
    fn rlp_scalar_zero_is_0x80() {
        let mut out = Vec::new();
        rlp_u64(0, &mut out);
        assert_eq!(out, vec![0x80]);
    }

    #[test]
    fn rlp_scalar_single_low_byte_is_bare() {
        let mut out = Vec::new();
        rlp_u64(0x0f, &mut out);
        assert_eq!(out, vec![0x0f]);
    }

    #[test]
    fn calldata_roundtrips() {
        let payload = AnchorPayload {
            date_utc: "2026-06-27".into(),
            chain_head_hex: hex::encode([0xabu8; 32]),
            head_event_id: None,
            event_count: 0x0102_0304_0506_0708,
        };
        let data = anchor_calldata(&payload).unwrap();
        assert_eq!(&data[..20], ANCHOR_CALLDATA_TAG);
        assert_eq!(&data[20..52], &[0xabu8; 32]);
        assert_eq!(&data[52..60], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&data[60..], b"2026-06-27");
    }

    #[test]
    fn calldata_rejects_bad_head() {
        let payload = AnchorPayload {
            date_utc: "2026-06-27".into(),
            chain_head_hex: "not-hex".into(),
            head_event_id: None,
            event_count: 1,
        };
        assert!(anchor_calldata(&payload).is_err());
    }
}
