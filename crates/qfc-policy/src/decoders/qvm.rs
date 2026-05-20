//! QVM minimal transaction decoder (M5).
//!
//! See RFC §9.6 / §10 decision #5 / option (b). The QVM decoder is
//! **envelope-only** — it parses the borsh-encoded transaction envelope and
//! exposes:
//!
//! - `tx_type` (the `TransactionType` discriminant from `qfc-core`)
//! - `chain_id` (`u64`)
//! - `to` (recipient address — variable-width raw bytes)
//! - `value` (the transferred amount, as a `U256`-compatible big-endian
//!   little-endian byte buffer — see below)
//! - `gas_limit` (`u64`)
//!
//! `data` is **opaque** for QVM: the QVM tx ABI in `qfc-core` does not
//! today carry a first-class `QvmCall` shape, so method-level / argument-
//! level policy is deferred to M6 (when `qfc-core` adds a `QvmCall`
//! variant). See `docs/m5-decisions.md` D41 for the borsh-schema
//! provenance.
//!
//! ## Wire format
//!
//! We do **not** depend on `qfc-core` as a workspace crate (RFC retro
//! §3.6 / the task brief). Instead this module re-declares a minimal
//! `QvmTxEnvelope` (private) that mirrors the shape `qfc-core` writes via
//! borsh today. The mapping:
//!
//! ```text
//! enum TransactionType {           // u8 discriminant via borsh
//!   0 = Transfer,
//!   1 = ContractCreate,
//!   2 = ContractCall,
//!   …                              // any future discriminant is treated
//!                                  // as "unknown but parsable" so older
//!                                  // decoders survive new tx variants.
//! }
//! struct Transaction {
//!   tx_type: TransactionType,
//!   chain_id: u64,
//!   to: Vec<u8>,                   // borsh `Vec<u8>` = u32 length prefix + bytes
//!   value: Vec<u8>,                // big-int encoded little-endian; opaque width
//!   gas_limit: u64,
//!   data: Vec<u8>,                 // opaque — skipped by the decoder
//! }
//! ```
//!
//! The decoder also tolerates trailing bytes after `data` so envelopes
//! that grow new fields in `qfc-core` still parse for the four
//! load-bearing fields we read today (forward-compat).

use borsh::BorshDeserialize;
use primitive_types::U256;

use crate::request::VmType;
use crate::vm::{DecodedTx, VmDecoder};

/// Discriminant for the `qfc-core` `TransactionType` enum. Mirrors the
/// borsh wire-level u8 the upstream crate emits today; unknown values
/// surface as [`QvmTxType::Other`] so policy continues to see envelope
/// fields even when the upstream tx-type set grows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QvmTxType {
    /// Plain value transfer.
    Transfer,
    /// Contract creation (envelope-level only — `data` is opaque).
    ContractCreate,
    /// Contract call (envelope-level only — `data` is opaque).
    ContractCall,
    /// Any other (forward-compat — discriminant value preserved).
    Other(u8),
}

impl QvmTxType {
    fn from_discriminant(d: u8) -> Self {
        match d {
            0 => Self::Transfer,
            1 => Self::ContractCreate,
            2 => Self::ContractCall,
            other => Self::Other(other),
        }
    }
}

/// Envelope-level fields a QVM minimal decoder lifts out of a borsh-
/// encoded `qfc-core` transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedQvmTx {
    /// Transaction type discriminant.
    pub tx_type: QvmTxType,
    /// Chain identifier.
    pub chain_id: u64,
    /// Recipient address — raw bytes (variable width across address
    /// formats; `qfc-core` uses 32-byte qfc addresses today, but the
    /// decoder is width-agnostic).
    pub to: Vec<u8>,
    /// Transfer / call value. Interpreted as little-endian, zero-padded
    /// to fit a `U256`. Values larger than 32 bytes saturate at
    /// `U256::MAX` so the policy engine sees a deterministic ceiling
    /// rather than rejecting outright.
    pub value: U256,
    /// Caller-supplied gas / compute-unit cap.
    pub gas_limit: u64,
}

/// Borsh deserializer for the envelope. Private — callers go through
/// [`decode_qvm_tx`].
///
/// Hand-rolled rather than `#[derive(BorshDeserialize)]` so we can:
/// 1. Map `tx_type` through [`QvmTxType::from_discriminant`] instead of
///    requiring an exhaustive Rust enum.
/// 2. Skip `data` cheaply (borsh `Vec<u8>` = `u32 len || bytes`).
/// 3. Tolerate trailing bytes — borsh derive errors on un-consumed input,
///    which would lock us to the exact upstream schema version.
#[derive(Debug)]
struct QvmTxEnvelope {
    tx_type_disc: u8,
    chain_id: u64,
    to: Vec<u8>,
    value: Vec<u8>,
    gas_limit: u64,
}

impl QvmTxEnvelope {
    fn from_slice(mut buf: &[u8]) -> Result<Self, QvmDecodeError> {
        // Borsh layout: tx_type (1 byte) || chain_id (u64 LE) || to
        // (u32-prefixed bytes) || value (u32-prefixed bytes) || gas_limit
        // (u64 LE) || data (u32-prefixed bytes; ignored).
        let tx_type_disc =
            u8::deserialize_reader(&mut buf).map_err(|e| QvmDecodeError::Borsh(e.to_string()))?;
        let chain_id =
            u64::deserialize_reader(&mut buf).map_err(|e| QvmDecodeError::Borsh(e.to_string()))?;
        let to = Vec::<u8>::deserialize_reader(&mut buf)
            .map_err(|e| QvmDecodeError::Borsh(e.to_string()))?;
        let value = Vec::<u8>::deserialize_reader(&mut buf)
            .map_err(|e| QvmDecodeError::Borsh(e.to_string()))?;
        let gas_limit =
            u64::deserialize_reader(&mut buf).map_err(|e| QvmDecodeError::Borsh(e.to_string()))?;
        // `data` is parsed-and-dropped so the decoder enforces the envelope
        // shape but doesn't materialize the opaque payload. Skipping the
        // call entirely (and tolerating any trailing bytes) preserves
        // forward-compat with future envelope extensions.
        if !buf.is_empty() {
            let _ = Vec::<u8>::deserialize_reader(&mut buf).ok();
        }
        Ok(Self {
            tx_type_disc,
            chain_id,
            to,
            value,
            gas_limit,
        })
    }
}

/// Errors raised by [`decode_qvm_tx`]. Malformed input never panics; all
/// failure modes surface here.
#[derive(Debug, thiserror::Error)]
pub enum QvmDecodeError {
    /// Empty payload.
    #[error("empty payload")]
    Empty,
    /// borsh rejected the payload.
    #[error("borsh decoding failed: {0}")]
    Borsh(String),
}

/// Decode a QVM transaction envelope from borsh-encoded bytes.
///
/// Returns a [`DecodedQvmTx`] with the four envelope-level fields the
/// policy engine reads. `data` is intentionally **not** present on the
/// output — the QVM tx ABI in `qfc-core` does not today carry method-
/// level shape for policy to enforce. See RFC §9.6.
///
/// # Errors
///
/// Returns [`QvmDecodeError::Empty`] on empty input and
/// [`QvmDecodeError::Borsh`] for any borsh-level parse failure.
pub fn decode_qvm_tx(raw: &[u8]) -> Result<DecodedQvmTx, QvmDecodeError> {
    if raw.is_empty() {
        return Err(QvmDecodeError::Empty);
    }
    let env = QvmTxEnvelope::from_slice(raw)?;
    let value = value_bytes_to_u256(&env.value);
    Ok(DecodedQvmTx {
        tx_type: QvmTxType::from_discriminant(env.tx_type_disc),
        chain_id: env.chain_id,
        to: env.to,
        value,
        gas_limit: env.gas_limit,
    })
}

/// Best-effort little-endian decode of an arbitrary-width value blob.
///
/// `qfc-core` historically encodes the transfer value as a length-prefixed
/// byte string (little-endian). Buffers wider than 32 bytes saturate at
/// `U256::MAX` so the policy engine sees a deterministic ceiling.
fn value_bytes_to_u256(bytes: &[u8]) -> U256 {
    if bytes.is_empty() {
        return U256::zero();
    }
    if bytes.len() > 32 {
        return U256::MAX;
    }
    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    U256::from_little_endian(&buf)
}

/// Zero-sized unit struct that implements [`VmDecoder`] for QVM payloads
/// (RFC §10 #5).
///
/// Constructed with `QvmDecoder` — no state. The policy evaluator holds
/// one of these per VM kind.
#[derive(Clone, Copy, Debug, Default)]
pub struct QvmDecoder;

impl VmDecoder for QvmDecoder {
    fn decode(&self, vm: VmType, raw: &[u8]) -> Option<DecodedTx> {
        if vm != VmType::Qvm {
            return None;
        }
        let decoded = decode_qvm_tx(raw).ok()?;
        Some(DecodedTx::from(decoded))
    }
}

impl From<DecodedQvmTx> for DecodedTx {
    fn from(tx: DecodedQvmTx) -> Self {
        Self {
            chain_id: tx.chain_id,
            to: if tx.to.is_empty() { None } else { Some(tx.to) },
            value: Some(tx.value),
            gas_limit: Some(tx.gas_limit),
            // `data` is opaque for QVM (RFC §9.6); no selector / args
            // surface for policy to bite on. M6 (when `qfc-core` adds a
            // `QvmCall` tx variant) re-populates these.
            method_selector: None,
            raw_args: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use borsh::BorshSerialize;

    /// Mirror the upstream wire format using borsh's derive macro on the
    /// helper struct below. Test-only: the production decoder hand-walks
    /// the bytes so it stays loose on trailing-field additions.
    #[derive(BorshSerialize)]
    struct TestTxBuilder {
        tx_type_disc: u8,
        chain_id: u64,
        to: Vec<u8>,
        value: Vec<u8>,
        gas_limit: u64,
        data: Vec<u8>,
    }

    fn build(tx: &TestTxBuilder) -> Vec<u8> {
        // borsh's derive emits exactly the layout the decoder reads.
        borsh::to_vec(tx).expect("borsh serialize")
    }

    fn u256_le_bytes(v: U256) -> Vec<u8> {
        let mut buf = [0u8; 32];
        v.to_little_endian(&mut buf);
        // Strip trailing zero bytes (canonical encoding).
        let last_nonzero = buf.iter().rposition(|b| *b != 0);
        match last_nonzero {
            Some(i) => buf[..=i].to_vec(),
            None => Vec::new(),
        }
    }

    #[test]
    fn empty_input_errors() {
        assert!(matches!(decode_qvm_tx(&[]), Err(QvmDecodeError::Empty)));
    }

    #[test]
    fn transfer_envelope_round_trips() {
        let payload = build(&TestTxBuilder {
            tx_type_disc: 0,
            chain_id: 1337,
            to: vec![0xAB; 32],
            value: u256_le_bytes(U256::from(1_000_000_000_000_000_000u64)),
            gas_limit: 21_000,
            data: Vec::new(),
        });
        let tx = decode_qvm_tx(&payload).expect("decode ok");
        assert_eq!(tx.tx_type, QvmTxType::Transfer);
        assert_eq!(tx.chain_id, 1337);
        assert_eq!(tx.to, vec![0xAB; 32]);
        assert_eq!(tx.value, U256::from(1_000_000_000_000_000_000u64));
        assert_eq!(tx.gas_limit, 21_000);
    }

    #[test]
    fn contract_call_envelope_drops_data() {
        // Even with non-empty `data`, the decoder lifts only the envelope
        // fields. `data` content is irrelevant to the result.
        let payload = build(&TestTxBuilder {
            tx_type_disc: 2,
            chain_id: 42,
            to: vec![0x11; 32],
            value: u256_le_bytes(U256::from(5_000_u64)),
            gas_limit: 200_000,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF, 0x42],
        });
        let tx = decode_qvm_tx(&payload).expect("decode ok");
        assert_eq!(tx.tx_type, QvmTxType::ContractCall);
        assert_eq!(tx.chain_id, 42);
        assert_eq!(tx.value, U256::from(5_000_u64));
        assert_eq!(tx.gas_limit, 200_000);
    }

    #[test]
    fn contract_create_envelope_recognized() {
        let payload = build(&TestTxBuilder {
            tx_type_disc: 1,
            chain_id: 1,
            to: Vec::new(), // empty `to` is legal for contract create
            value: Vec::new(),
            gas_limit: 1_000_000,
            data: vec![0x60, 0x80, 0x60, 0x40, 0x52],
        });
        let tx = decode_qvm_tx(&payload).expect("decode ok");
        assert_eq!(tx.tx_type, QvmTxType::ContractCreate);
        assert_eq!(tx.value, U256::zero());
        // Empty `to` surfaces as `None` in the cross-VM `DecodedTx`.
        let cross: DecodedTx = tx.into();
        assert_eq!(cross.to, None);
    }

    #[test]
    fn unknown_tx_type_preserved() {
        // Upstream `qfc-core` may add new variants; the decoder maps them
        // to `Other(d)` so policy still sees the envelope fields.
        let payload = build(&TestTxBuilder {
            tx_type_disc: 99,
            chain_id: 7,
            to: vec![0x42; 16],
            value: u256_le_bytes(U256::from(99u64)),
            gas_limit: 50_000,
            data: vec![],
        });
        let tx = decode_qvm_tx(&payload).expect("decode ok");
        assert_eq!(tx.tx_type, QvmTxType::Other(99));
        assert_eq!(tx.chain_id, 7);
    }

    #[test]
    fn trailing_bytes_tolerated() {
        // Future qfc-core may append fields to the envelope. The minimal
        // decoder reads through `gas_limit` then drops the rest, so a
        // payload with extra trailing bytes still parses cleanly.
        let mut payload = build(&TestTxBuilder {
            tx_type_disc: 0,
            chain_id: 1,
            to: vec![0xCC; 32],
            value: u256_le_bytes(U256::from(1u64)),
            gas_limit: 21_000,
            data: Vec::new(),
        });
        payload.extend_from_slice(&[0xFFu8; 16]); // simulate future field
        let tx = decode_qvm_tx(&payload).expect("decode ok despite trailing bytes");
        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.gas_limit, 21_000);
    }

    #[test]
    fn malformed_input_errors_cleanly() {
        // Truncated payload — first byte present, rest missing.
        let err = decode_qvm_tx(&[0u8]);
        assert!(matches!(err, Err(QvmDecodeError::Borsh(_))));
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // intentional: PRNG byte squeeze
    fn random_bytes_never_panic() {
        // Spray-test: pseudo-random bytes must never panic the decoder.
        for seed in 0u64..256 {
            let mut state = seed;
            let mut bytes = Vec::with_capacity(64);
            for _ in 0..64 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                bytes.push((state >> 33) as u8);
            }
            let _ = decode_qvm_tx(&bytes);
        }
    }

    #[test]
    fn vm_decoder_dispatch_only_decodes_qvm() {
        let dec = QvmDecoder;
        let payload = build(&TestTxBuilder {
            tx_type_disc: 0,
            chain_id: 1,
            to: vec![0x01; 32],
            value: u256_le_bytes(U256::from(10u64)),
            gas_limit: 21_000,
            data: Vec::new(),
        });
        // QVM payload goes through.
        let decoded = dec.decode(VmType::Qvm, &payload).expect("qvm decode");
        assert_eq!(decoded.chain_id, 1);
        // Same bytes with the EVM tag => decoder declines.
        assert!(dec.decode(VmType::Evm, &payload).is_none());
        // Same with WASM tag (deferred per RFC §9.6).
        assert!(dec.decode(VmType::Wasm, &payload).is_none());
    }

    #[test]
    fn oversized_value_saturates_to_u256_max() {
        // 33-byte value blob saturates at U256::MAX.
        let value = vec![0xFFu8; 33];
        // Build envelope manually since the test helper produces a
        // canonical-length value.
        let mut buf = Vec::new();
        0u8.serialize(&mut buf).unwrap();
        1u64.serialize(&mut buf).unwrap();
        vec![0u8; 32].serialize(&mut buf).unwrap();
        value.serialize(&mut buf).unwrap();
        21_000u64.serialize(&mut buf).unwrap();
        Vec::<u8>::new().serialize(&mut buf).unwrap();
        let tx = decode_qvm_tx(&buf).unwrap();
        assert_eq!(tx.value, U256::MAX);
    }
}
