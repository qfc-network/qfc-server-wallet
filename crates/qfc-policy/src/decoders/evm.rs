//! Structural decoder for EVM transaction envelopes.
//!
//! Handles the four envelope shapes currently deployed on mainnet:
//!
//! | Type | Source                | Fields                                                                                                                                                       |
//! |------|-----------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|
//! | 0    | Legacy / EIP-155      | `[nonce, gas_price, gas_limit, to, value, data, v, r, s]`                                                                                                    |
//! | 1    | EIP-2930              | `[chain_id, nonce, gas_price, gas_limit, to, value, data, access_list, y_parity, r, s]`                                                                      |
//! | 2    | EIP-1559              | `[chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, y_parity, r, s]`                                      |
//! | 3    | EIP-4844              | `[chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list, max_fee_per_blob_gas, blob_versioned_hashes, y_parity, r, s]` |
//!
//! The decoder is **structural only**: it does not recover the signer, it
//! does not validate KZG commitments for blobs, and it does not enforce
//! gas / fee semantics. Those are caller / consensus concerns. The policy
//! engine just needs `to`, `value`, `method_selector`, `chain_id`,
//! `gas_limit`, and (for 4844) the `blob_versioned_hashes` list.

use alloy_rlp::{Header, PayloadView};
use primitive_types::U256;

use crate::request::VmType;
use crate::vm::{DecodedTx, VmDecoder};

/// Discriminant for the four supported EVM transaction envelopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvmTxType {
    /// Pre-typed-envelope transaction (legacy or EIP-155).
    Legacy,
    /// EIP-2930 access-list transaction (type byte `0x01`).
    Eip2930,
    /// EIP-1559 dynamic-fee transaction (type byte `0x02`).
    Eip1559,
    /// EIP-4844 blob transaction (type byte `0x03`).
    Eip4844,
}

/// A single `(address, storage_keys[])` tuple from an EIP-2930 access list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessListItem {
    /// The contract address this entry pre-warms.
    pub address: [u8; 20],
    /// Storage slots being pre-warmed under `address`.
    pub storage_keys: Vec<[u8; 32]>,
}

/// Fully-decoded EVM transaction envelope.
///
/// Fields that are not present in a given transaction type are `None` /
/// empty:
///
/// - `gas_price` is `Some` for legacy + EIP-2930, `None` for 1559 + 4844.
/// - `max_fee_per_gas` / `max_priority_fee_per_gas` are `Some` for 1559 + 4844 only.
/// - `access_list` is empty for legacy.
/// - `blob_versioned_hashes` is non-empty only for EIP-4844.
/// - `chain_id` is `None` for pre-EIP-155 legacy txs (v == 27 or 28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedEvmTx {
    /// Which envelope shape this was.
    pub tx_type: EvmTxType,
    /// EIP-155 chain id (for legacy) or the explicit `chain_id` RLP field.
    pub chain_id: Option<u64>,
    /// Sender-account nonce.
    pub nonce: u64,
    /// Recipient address. `None` for contract-creation transactions
    /// (legacy `to == 0x80` empty string).
    pub to: Option<[u8; 20]>,
    /// Wei value transferred.
    pub value: U256,
    /// Gas limit set by the sender.
    pub gas_limit: u64,
    /// EIP-1559 / 4844 ceiling fee. `None` for legacy + 2930.
    pub max_fee_per_gas: Option<U256>,
    /// EIP-1559 / 4844 priority tip. `None` for legacy + 2930.
    pub max_priority_fee_per_gas: Option<U256>,
    /// Legacy / 2930 fixed gas price. `None` for 1559 + 4844.
    pub gas_price: Option<U256>,
    /// Calldata payload.
    pub data: Vec<u8>,
    /// First 4 bytes of `data` if at least 4 bytes are present.
    pub method_selector: Option<[u8; 4]>,
    /// EIP-2930+ access list. Always empty for legacy.
    pub access_list: Vec<AccessListItem>,
    /// EIP-4844 blob commitments. Always empty outside type-3.
    pub blob_versioned_hashes: Vec<[u8; 32]>,
}

/// Errors that `decode_evm_tx` can return. The decoder never panics on
/// arbitrary input — all malformed payloads surface here.
#[derive(Debug, thiserror::Error)]
pub enum EvmDecodeError {
    /// Input slice was empty.
    #[error("empty payload")]
    Empty,
    /// First byte was a reserved EIP-2718 type byte we don't recognize
    /// (typed envelopes use `0x01..=0x7f`).
    #[error("unknown transaction type 0x{0:02x}")]
    UnknownType(u8),
    /// `alloy-rlp` rejected the payload (truncated, non-canonical, wrong
    /// shape, etc.).
    #[error("rlp decoding failed: {0}")]
    Rlp(String),
    /// A fixed-width field (address, hash, u64-as-bytes) had the wrong
    /// length after RLP-stripping.
    #[error("invalid field length for {field}: expected {expected}, got {got}")]
    InvalidLength {
        /// Human-readable field name.
        field: &'static str,
        /// Maximum / required byte length after RLP-stripping.
        expected: usize,
        /// Actual length received.
        got: usize,
    },
}

impl From<alloy_rlp::Error> for EvmDecodeError {
    fn from(err: alloy_rlp::Error) -> Self {
        Self::Rlp(format!("{err:?}"))
    }
}

/// Zero-sized unit struct that implements [`VmDecoder`] for EVM payloads.
///
/// Constructed with `EvmDecoder` — there is no state to carry. The policy
/// evaluator (P3) holds one of these per VM kind.
#[derive(Clone, Copy, Debug, Default)]
pub struct EvmDecoder;

impl VmDecoder for EvmDecoder {
    fn decode(&self, vm: VmType, raw: &[u8]) -> Option<DecodedTx> {
        if vm != VmType::Evm {
            return None;
        }
        let decoded = decode_evm_tx(raw).ok()?;
        Some(DecodedTx::from(decoded))
    }
}

/// Decode an EVM transaction envelope.
///
/// Supports all four shapes documented at the module level. The leading
/// byte selects the parser:
///
/// - `0x00..=0x7f` (other than `0x01`/`0x02`/`0x03`) is reserved by
///   EIP-2718 and returns [`EvmDecodeError::UnknownType`].
/// - `0x01`, `0x02`, `0x03` strip the type byte and parse the inner RLP
///   list as typed envelopes.
/// - `0x80..=0xff` is the legacy RLP-list prefix and is parsed as a
///   pre-typed transaction.
///
/// # Errors
///
/// Returns [`EvmDecodeError`] on empty input, unknown type bytes,
/// truncated / malformed RLP, or out-of-range fixed-width fields.
pub fn decode_evm_tx(raw: &[u8]) -> Result<DecodedEvmTx, EvmDecodeError> {
    let first = *raw.first().ok_or(EvmDecodeError::Empty)?;
    match first {
        0x01 => decode_eip2930(&raw[1..]),
        0x02 => decode_eip1559(&raw[1..]),
        0x03 => decode_eip4844(&raw[1..]),
        // EIP-2718 reserves 0x00..=0x7f for typed envelopes; everything in
        // that range that we don't recognize is an unknown type. RLP list
        // prefixes (legacy txs) live in 0xC0..=0xFF, and short-string RLP
        // single-byte values would be 0x80..=0xBF, but no legitimate legacy
        // tx starts below 0xC0 since the envelope is always a list.
        0x00..=0x7f => Err(EvmDecodeError::UnknownType(first)),
        _ => decode_legacy(raw),
    }
}

// ---------------------------------------------------------------------------
// Type-specific decoders
// ---------------------------------------------------------------------------

fn decode_legacy(raw: &[u8]) -> Result<DecodedEvmTx, EvmDecodeError> {
    let items = decode_list(raw, 9)?;
    let nonce = decode_u64(items[0], "nonce")?;
    let gas_price = decode_u256(items[1], "gas_price")?;
    let gas_limit = decode_u64(items[2], "gas_limit")?;
    let to = decode_optional_address(items[3])?;
    let value = decode_u256(items[4], "value")?;
    let data = decode_bytes(items[5])?;
    let v = decode_u64(items[6], "v")?;
    // r, s are not used by the policy engine — decode-and-drop so that
    // length checks still catch malformed envelopes.
    let _ = decode_bytes(items[7])?;
    let _ = decode_bytes(items[8])?;

    // EIP-155: chain_id = (v - 35) / 2 when v >= 35; otherwise pre-155
    // (v in {27, 28}) which carries no chain id.
    let chain_id = if v >= 35 { Some((v - 35) / 2) } else { None };
    let method_selector = first_four(&data);

    Ok(DecodedEvmTx {
        tx_type: EvmTxType::Legacy,
        chain_id,
        nonce,
        to,
        value,
        gas_limit,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        gas_price: Some(gas_price),
        data,
        method_selector,
        access_list: Vec::new(),
        blob_versioned_hashes: Vec::new(),
    })
}

fn decode_eip2930(raw: &[u8]) -> Result<DecodedEvmTx, EvmDecodeError> {
    let items = decode_list(raw, 11)?;
    let chain_id = decode_u64(items[0], "chain_id")?;
    let nonce = decode_u64(items[1], "nonce")?;
    let gas_price = decode_u256(items[2], "gas_price")?;
    let gas_limit = decode_u64(items[3], "gas_limit")?;
    let to = decode_optional_address(items[4])?;
    let value = decode_u256(items[5], "value")?;
    let data = decode_bytes(items[6])?;
    let access_list = decode_access_list(items[7])?;
    let _ = decode_u64(items[8], "y_parity")?;
    let _ = decode_bytes(items[9])?;
    let _ = decode_bytes(items[10])?;

    let method_selector = first_four(&data);
    Ok(DecodedEvmTx {
        tx_type: EvmTxType::Eip2930,
        chain_id: Some(chain_id),
        nonce,
        to,
        value,
        gas_limit,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
        gas_price: Some(gas_price),
        data,
        method_selector,
        access_list,
        blob_versioned_hashes: Vec::new(),
    })
}

fn decode_eip1559(raw: &[u8]) -> Result<DecodedEvmTx, EvmDecodeError> {
    let items = decode_list(raw, 12)?;
    let chain_id = decode_u64(items[0], "chain_id")?;
    let nonce = decode_u64(items[1], "nonce")?;
    let max_priority_fee_per_gas = decode_u256(items[2], "max_priority_fee_per_gas")?;
    let max_fee_per_gas = decode_u256(items[3], "max_fee_per_gas")?;
    let gas_limit = decode_u64(items[4], "gas_limit")?;
    let to = decode_optional_address(items[5])?;
    let value = decode_u256(items[6], "value")?;
    let data = decode_bytes(items[7])?;
    let access_list = decode_access_list(items[8])?;
    let _ = decode_u64(items[9], "y_parity")?;
    let _ = decode_bytes(items[10])?;
    let _ = decode_bytes(items[11])?;

    let method_selector = first_four(&data);
    Ok(DecodedEvmTx {
        tx_type: EvmTxType::Eip1559,
        chain_id: Some(chain_id),
        nonce,
        to,
        value,
        gas_limit,
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        gas_price: None,
        data,
        method_selector,
        access_list,
        blob_versioned_hashes: Vec::new(),
    })
}

fn decode_eip4844(raw: &[u8]) -> Result<DecodedEvmTx, EvmDecodeError> {
    // 14 fields: chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
    // gas_limit, to, value, data, access_list, max_fee_per_blob_gas,
    // blob_versioned_hashes, y_parity, r, s.
    let items = decode_list(raw, 14)?;
    let chain_id = decode_u64(items[0], "chain_id")?;
    let nonce = decode_u64(items[1], "nonce")?;
    let max_priority_fee_per_gas = decode_u256(items[2], "max_priority_fee_per_gas")?;
    let max_fee_per_gas = decode_u256(items[3], "max_fee_per_gas")?;
    let gas_limit = decode_u64(items[4], "gas_limit")?;
    // EIP-4844 blob txs MUST have a non-empty `to` (no contract creation).
    // We still accept `to == empty` and surface it as `None` so the policy
    // engine sees a uniform shape; the consensus client rejects the tx
    // before it ever reaches us.
    let to = decode_optional_address(items[5])?;
    let value = decode_u256(items[6], "value")?;
    let data = decode_bytes(items[7])?;
    let access_list = decode_access_list(items[8])?;
    let _ = decode_u256(items[9], "max_fee_per_blob_gas")?;
    let blob_versioned_hashes = decode_hash_list(items[10])?;
    let _ = decode_u64(items[11], "y_parity")?;
    let _ = decode_bytes(items[12])?;
    let _ = decode_bytes(items[13])?;

    let method_selector = first_four(&data);
    Ok(DecodedEvmTx {
        tx_type: EvmTxType::Eip4844,
        chain_id: Some(chain_id),
        nonce,
        to,
        value,
        gas_limit,
        max_fee_per_gas: Some(max_fee_per_gas),
        max_priority_fee_per_gas: Some(max_priority_fee_per_gas),
        gas_price: None,
        data,
        method_selector,
        access_list,
        blob_versioned_hashes,
    })
}

// ---------------------------------------------------------------------------
// Field-level helpers
// ---------------------------------------------------------------------------

/// Decode an RLP list header and split the payload into exactly `expected`
/// item slices. Each returned slice is the *raw* (header-included) encoding
/// of one item; the per-field decoders strip headers themselves so they can
/// recurse into lists where needed.
fn decode_list(raw: &[u8], expected: usize) -> Result<Vec<&[u8]>, EvmDecodeError> {
    let mut buf = raw;
    let view = Header::decode_raw(&mut buf)?;
    if !buf.is_empty() {
        return Err(EvmDecodeError::Rlp("trailing bytes after envelope".into()));
    }
    match view {
        PayloadView::List(items) => {
            if items.len() != expected {
                return Err(EvmDecodeError::InvalidLength {
                    field: "envelope",
                    expected,
                    got: items.len(),
                });
            }
            Ok(items)
        }
        PayloadView::String(_) => Err(EvmDecodeError::Rlp("expected list at top level".into())),
    }
}

/// Strip the RLP header from an item that should be a byte string.
fn decode_bytes(item: &[u8]) -> Result<Vec<u8>, EvmDecodeError> {
    let mut cur = item;
    let bytes = Header::decode_bytes(&mut cur, false)?;
    if !cur.is_empty() {
        return Err(EvmDecodeError::Rlp(
            "trailing bytes after string item".into(),
        ));
    }
    Ok(bytes.to_vec())
}

/// Decode a u64 from an RLP byte string. Empty string == 0. Rejects
/// leading-zero non-canonical encodings (RLP rule) and > 8 byte payloads.
fn decode_u64(item: &[u8], field: &'static str) -> Result<u64, EvmDecodeError> {
    let bytes = decode_bytes(item)?;
    if bytes.len() > 8 {
        return Err(EvmDecodeError::InvalidLength {
            field,
            expected: 8,
            got: bytes.len(),
        });
    }
    if bytes.first() == Some(&0) {
        return Err(EvmDecodeError::Rlp(format!(
            "non-canonical leading zero in {field}"
        )));
    }
    let mut buf = [0u8; 8];
    buf[8 - bytes.len()..].copy_from_slice(&bytes);
    Ok(u64::from_be_bytes(buf))
}

/// Decode a `U256` from an RLP byte string. Empty string == 0. Rejects
/// payloads > 32 bytes and non-canonical leading zeros.
fn decode_u256(item: &[u8], field: &'static str) -> Result<U256, EvmDecodeError> {
    let bytes = decode_bytes(item)?;
    if bytes.len() > 32 {
        return Err(EvmDecodeError::InvalidLength {
            field,
            expected: 32,
            got: bytes.len(),
        });
    }
    if bytes.first() == Some(&0) {
        return Err(EvmDecodeError::Rlp(format!(
            "non-canonical leading zero in {field}"
        )));
    }
    Ok(U256::from_big_endian(&bytes))
}

/// `to` is either a 20-byte address or an empty string (contract creation).
fn decode_optional_address(item: &[u8]) -> Result<Option<[u8; 20]>, EvmDecodeError> {
    let bytes = decode_bytes(item)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() != 20 {
        return Err(EvmDecodeError::InvalidLength {
            field: "to",
            expected: 20,
            got: bytes.len(),
        });
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

/// `access_list` item is a list of `[address, storage_keys[]]` tuples.
fn decode_access_list(item: &[u8]) -> Result<Vec<AccessListItem>, EvmDecodeError> {
    let mut buf = item;
    let view = Header::decode_raw(&mut buf)?;
    if !buf.is_empty() {
        return Err(EvmDecodeError::Rlp(
            "trailing bytes after access_list".into(),
        ));
    }
    let entries = match view {
        PayloadView::List(items) => items,
        PayloadView::String(_) => {
            return Err(EvmDecodeError::Rlp(
                "expected access_list to be a list".into(),
            ))
        }
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let mut e = entry;
        let entry_view = Header::decode_raw(&mut e)?;
        if !e.is_empty() {
            return Err(EvmDecodeError::Rlp(
                "trailing bytes inside access_list entry".into(),
            ));
        }
        let entry_items = match entry_view {
            PayloadView::List(v) => v,
            PayloadView::String(_) => {
                return Err(EvmDecodeError::Rlp(
                    "access_list entry must be a list".into(),
                ))
            }
        };
        if entry_items.len() != 2 {
            return Err(EvmDecodeError::InvalidLength {
                field: "access_list_entry",
                expected: 2,
                got: entry_items.len(),
            });
        }
        let addr_bytes = decode_bytes(entry_items[0])?;
        if addr_bytes.len() != 20 {
            return Err(EvmDecodeError::InvalidLength {
                field: "access_list_address",
                expected: 20,
                got: addr_bytes.len(),
            });
        }
        let mut address = [0u8; 20];
        address.copy_from_slice(&addr_bytes);

        let storage_keys = decode_hash_list(entry_items[1])?;
        out.push(AccessListItem {
            address,
            storage_keys,
        });
    }
    Ok(out)
}

/// Decode an RLP list of 32-byte hashes (storage keys, blob hashes).
fn decode_hash_list(item: &[u8]) -> Result<Vec<[u8; 32]>, EvmDecodeError> {
    let mut buf = item;
    let view = Header::decode_raw(&mut buf)?;
    if !buf.is_empty() {
        return Err(EvmDecodeError::Rlp("trailing bytes after hash list".into()));
    }
    let entries = match view {
        PayloadView::List(items) => items,
        PayloadView::String(_) => {
            return Err(EvmDecodeError::Rlp(
                "expected hash list to be a list".into(),
            ))
        }
    };
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let bytes = decode_bytes(entry)?;
        if bytes.len() != 32 {
            return Err(EvmDecodeError::InvalidLength {
                field: "hash",
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut h = [0u8; 32];
        h.copy_from_slice(&bytes);
        out.push(h);
    }
    Ok(out)
}

fn first_four(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() < 4 {
        return None;
    }
    let mut out = [0u8; 4];
    out.copy_from_slice(&data[..4]);
    Some(out)
}

// ---------------------------------------------------------------------------
// Shim into the (P3) `VmDecoder` neutral shape
// ---------------------------------------------------------------------------

impl From<DecodedEvmTx> for DecodedTx {
    fn from(tx: DecodedEvmTx) -> Self {
        Self {
            // Pre-EIP-155 legacy transactions don't carry a chain id; the
            // policy engine treats a missing chain id as "unknown" — fall
            // through to 0 (a sentinel; chain-id rules on real chains
            // never use 0 anyway).
            chain_id: tx.chain_id.unwrap_or(0),
            to: tx.to.map(|a| a.to_vec()),
            value: Some(tx.value),
            gas_limit: Some(tx.gas_limit),
            method_selector: tx.method_selector,
            raw_args: if tx.data.len() > 4 {
                Some(tx.data[4..].to_vec())
            } else {
                None
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests — keep the file self-contained where possible; golden vectors
// live in `tests/evm_golden.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_errors() {
        let err = decode_evm_tx(&[]).unwrap_err();
        assert!(matches!(err, EvmDecodeError::Empty));
    }

    #[test]
    fn unknown_type_byte_errors() {
        let err = decode_evm_tx(&[0x05, 0xc0]).unwrap_err();
        assert!(matches!(err, EvmDecodeError::UnknownType(0x05)));
    }

    #[test]
    fn legacy_minimal_roundtrip() {
        // hand-rolled: nonce=0, gp=1, gas=21000, to=20-byte 0x11..., value=0,
        // data=empty, v=27, r=s=empty. Encoded with online RLP tools, verified
        // by re-decoding here.
        let mut payload = Vec::new();
        // 9 fields. We construct via a small encoder.
        payload.extend(rlp_encode_u64(0)); // nonce
        payload.extend(rlp_encode_u64(1)); // gas_price
        payload.extend(rlp_encode_u64(21_000)); // gas
        payload.extend(rlp_encode_bytes(&[0x11; 20])); // to
        payload.extend(rlp_encode_u64(0)); // value
        payload.extend(rlp_encode_bytes(&[])); // data
        payload.extend(rlp_encode_u64(27)); // v (pre-155)
        payload.extend(rlp_encode_bytes(&[])); // r
        payload.extend(rlp_encode_bytes(&[])); // s
        let mut envelope = rlp_list_prefix(payload.len());
        envelope.extend(payload);

        let tx = decode_evm_tx(&envelope).expect("decode ok");
        assert_eq!(tx.tx_type, EvmTxType::Legacy);
        assert_eq!(tx.chain_id, None); // pre-EIP-155
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_limit, 21_000);
        assert_eq!(tx.to, Some([0x11; 20]));
        assert_eq!(tx.value, U256::zero());
        assert!(tx.data.is_empty());
        assert!(tx.method_selector.is_none());
        assert!(tx.access_list.is_empty());
        assert!(tx.blob_versioned_hashes.is_empty());
    }

    #[test]
    fn legacy_eip155_chain_id_extracted() {
        // v = 37 → chain_id = (37 - 35) / 2 = 1 (mainnet)
        let mut payload = Vec::new();
        payload.extend(rlp_encode_u64(0));
        payload.extend(rlp_encode_u64(1));
        payload.extend(rlp_encode_u64(21_000));
        payload.extend(rlp_encode_bytes(&[0x11; 20]));
        payload.extend(rlp_encode_u64(0));
        payload.extend(rlp_encode_bytes(&[]));
        payload.extend(rlp_encode_u64(37));
        payload.extend(rlp_encode_bytes(&[]));
        payload.extend(rlp_encode_bytes(&[]));
        let mut envelope = rlp_list_prefix(payload.len());
        envelope.extend(payload);

        let tx = decode_evm_tx(&envelope).expect("decode ok");
        assert_eq!(tx.chain_id, Some(1));
    }

    #[test]
    fn contract_creation_to_none() {
        let mut payload = Vec::new();
        payload.extend(rlp_encode_u64(0));
        payload.extend(rlp_encode_u64(1));
        payload.extend(rlp_encode_u64(100_000));
        payload.extend(rlp_encode_bytes(&[])); // to == empty
        payload.extend(rlp_encode_u64(0));
        payload.extend(rlp_encode_bytes(&[0x60, 0x80, 0x60, 0x40, 0x52])); // PUSH1 0x80...
        payload.extend(rlp_encode_u64(27));
        payload.extend(rlp_encode_bytes(&[]));
        payload.extend(rlp_encode_bytes(&[]));
        let mut envelope = rlp_list_prefix(payload.len());
        envelope.extend(payload);

        let tx = decode_evm_tx(&envelope).expect("decode ok");
        assert_eq!(tx.to, None);
        assert_eq!(tx.method_selector, Some([0x60, 0x80, 0x60, 0x40]));
    }

    #[test]
    fn truncated_envelope_errors() {
        let mut envelope = rlp_list_prefix(50);
        // …no body bytes — alloy-rlp should reject as too short
        envelope.push(0x01);
        let err = decode_evm_tx(&envelope).unwrap_err();
        assert!(matches!(err, EvmDecodeError::Rlp(_)));
    }

    #[test]
    fn wrong_field_count_errors() {
        // legacy envelope with only 8 fields
        let mut payload = Vec::new();
        for _ in 0..8 {
            payload.extend(rlp_encode_bytes(&[]));
        }
        let mut envelope = rlp_list_prefix(payload.len());
        envelope.extend(payload);
        let err = decode_evm_tx(&envelope).unwrap_err();
        match err {
            EvmDecodeError::InvalidLength {
                field,
                expected,
                got,
            } => {
                assert_eq!(field, "envelope");
                assert_eq!(expected, 9);
                assert_eq!(got, 8);
            }
            other => panic!("expected InvalidLength, got {other:?}"),
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        for seed in 0u64..256 {
            // deterministic pseudo-random spray
            let mut state = seed;
            let mut bytes = Vec::with_capacity(64);
            for _ in 0..64 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                bytes.push((state >> 33) as u8);
            }
            // must return Ok or Err, never panic
            let _ = decode_evm_tx(&bytes);
        }
    }

    // -- tiny hand-rolled RLP encoders for the legacy fixtures above --------

    fn rlp_encode_u64(v: u64) -> Vec<u8> {
        if v == 0 {
            return vec![0x80];
        }
        let be = v.to_be_bytes();
        let trimmed: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
        rlp_encode_bytes(&trimmed)
    }

    fn rlp_encode_bytes(b: &[u8]) -> Vec<u8> {
        if b.len() == 1 && b[0] < 0x80 {
            return vec![b[0]];
        }
        if b.len() <= 55 {
            let mut out = Vec::with_capacity(b.len() + 1);
            out.push(0x80 + b.len() as u8);
            out.extend_from_slice(b);
            return out;
        }
        let len_be = b.len().to_be_bytes();
        let trimmed: Vec<u8> = len_be.iter().copied().skip_while(|x| *x == 0).collect();
        let mut out = Vec::with_capacity(1 + trimmed.len() + b.len());
        out.push(0xb7 + trimmed.len() as u8);
        out.extend_from_slice(&trimmed);
        out.extend_from_slice(b);
        out
    }

    fn rlp_list_prefix(payload_len: usize) -> Vec<u8> {
        if payload_len <= 55 {
            return vec![0xc0 + payload_len as u8];
        }
        let len_be = payload_len.to_be_bytes();
        let trimmed: Vec<u8> = len_be.iter().copied().skip_while(|x| *x == 0).collect();
        let mut out = Vec::with_capacity(1 + trimmed.len());
        out.push(0xf7 + trimmed.len() as u8);
        out.extend_from_slice(&trimmed);
        out
    }
}
