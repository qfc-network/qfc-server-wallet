//! VM-payload decoding seam.
//!
//! P3 only defines the trait and the `DecodedTx` shape. The concrete EVM
//! decoder (`alloy_consensus`-based) lands in P4; QVM and WASM decoders
//! are deferred per RFC §9.6 (`qfc-core` integration prerequisite).
//!
//! `RuleSetPolicy` takes `Option<Arc<dyn VmDecoder>>` — when `None`, the
//! evaluator falls back to whatever fields are visible on the raw
//! `SigningPayload::VmTransaction` (most importantly, `chain_id` + `to`).

use primitive_types::U256;

use crate::request::VmType;

/// The cross-VM common shape extracted by a `VmDecoder`. Fields are
/// optional because some VMs (notably bare WASM dispatch) don't carry
/// every concept.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTx {
    /// Chain id (or chain-like identifier for non-EVM VMs).
    pub chain_id: u64,
    /// Recipient address (raw bytes — VM-defined width).
    pub to: Option<Vec<u8>>,
    /// Value transferred. Width is up to U256 to accommodate EVM wei.
    pub value: Option<U256>,
    /// Gas limit (EVM) / compute-unit budget (QVM).
    pub gas_limit: Option<u64>,
    /// 4-byte method selector (EVM `data[0..4]`). Optional because not
    /// every transaction encodes one (plain transfer, contract creation).
    pub method_selector: Option<[u8; 4]>,
    /// Decoded argument bytes after the selector. Useful for arg-shape
    /// constraints in later milestones.
    pub raw_args: Option<Vec<u8>>,
}

impl DecodedTx {
    /// Convenience constructor: empty decoded shape for a chain. Used by
    /// tests and by the fallback path when no decoder is configured.
    #[must_use]
    pub fn minimal(chain_id: u64) -> Self {
        Self {
            chain_id,
            to: None,
            value: None,
            gas_limit: None,
            method_selector: None,
            raw_args: None,
        }
    }
}

/// Trait implemented by per-VM decoders. The decoder is responsible for
/// turning a raw transaction envelope into the common `DecodedTx`. It
/// MUST be deterministic and side-effect free (the policy evaluator may
/// call it multiple times per request as more rules are checked).
pub trait VmDecoder: Send + Sync {
    /// Decode `raw` as a `vm` transaction. Returns `None` on malformed
    /// input so the evaluator can downgrade to fallback inspection of
    /// the raw payload's `to`/`chain_id`.
    fn decode(&self, vm: VmType, raw: &[u8]) -> Option<DecodedTx>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy decoder used to exercise the seam from unit tests. Yields a
    /// pre-baked `DecodedTx` regardless of input. Real EVM/QVM decoders
    /// ship in P4 and M5 respectively.
    pub(crate) struct FakeDecoder(pub DecodedTx);

    impl VmDecoder for FakeDecoder {
        fn decode(&self, _vm: VmType, _raw: &[u8]) -> Option<DecodedTx> {
            Some(self.0.clone())
        }
    }

    #[test]
    fn minimal_is_all_none_except_chain() {
        let d = DecodedTx::minimal(42);
        assert_eq!(d.chain_id, 42);
        assert!(d.to.is_none());
        assert!(d.value.is_none());
        assert!(d.gas_limit.is_none());
        assert!(d.method_selector.is_none());
        assert!(d.raw_args.is_none());
    }

    #[test]
    fn fake_decoder_returns_some() {
        let dec = FakeDecoder(DecodedTx::minimal(7));
        let d = dec.decode(VmType::Evm, &[1, 2, 3]).unwrap();
        assert_eq!(d.chain_id, 7);
    }
}
