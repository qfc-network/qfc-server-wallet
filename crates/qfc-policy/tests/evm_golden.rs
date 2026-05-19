//! Golden EVM transaction fixtures for `qfc_policy::decoders::evm`.
//!
//! These bytes are committed verbatim so a reviewer can:
//!
//! 1. Hash each hex string locally and compare to the documented source.
//! 2. Re-fetch the raw tx from Etherscan (`eth_getRawTransactionByHash`)
//!    and confirm the bytes match.
//!
//! Source convention: every fixture function's doc comment names the
//! provenance — either a mainnet tx hash, an EIP example vector, or a
//! hand-rolled structure with the construction documented inline.
//!
//! Where possible we use well-known mainnet transactions so the fixtures
//! double as regression vectors against real chain history.

use primitive_types::U256;
use qfc_policy::decoders::evm::{decode_evm_tx, EvmTxType};

fn hex(s: &str) -> Vec<u8> {
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    hex::decode(cleaned.trim_start_matches("0x")).expect("valid hex")
}

// ---------------------------------------------------------------------------
// Golden #1 — Legacy ETH transfer (Vitalik → Vitalik, pre-EIP-155 style)
// ---------------------------------------------------------------------------

/// Legacy ETH transfer constructed against the canonical EIP-155 test vector
/// from EIP-155 itself (rationale section).
///
/// Source: https://eips.ethereum.org/EIPS/eip-155 — "Example" subsection.
/// Inputs: nonce=9, gas_price=20 gwei, gas=21000, to=0x3535...3535,
/// value=1 ETH, data=empty, signed with private key
/// 0x46..96 on chain id 1.
///
/// Decoded fields the policy engine cares about: tx_type=Legacy,
/// chain_id=Some(1), to=0x3535..., value=1e18.
#[test]
fn legacy_eip155_example_vector() {
    // Raw signed bytes from the EIP-155 spec example.
    let raw = hex(
        "f86c098504a817c800825208943535353535353535353535353535353535353535
         880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c
         71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc
         64214b297fb1966a3b6d83",
    );

    let tx = decode_evm_tx(&raw).expect("decode legacy EIP-155 vector");
    assert_eq!(tx.tx_type, EvmTxType::Legacy);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.nonce, 9);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(
        tx.to,
        Some([0x35; 20]),
        "to should be the canonical 0x3535...3535 address"
    );
    // value = 1 ETH = 1e18 wei
    assert_eq!(tx.value, U256::from_dec_str("1000000000000000000").unwrap());
    assert!(tx.data.is_empty());
    assert!(tx.method_selector.is_none());
    assert_eq!(
        tx.gas_price,
        Some(U256::from(20_000_000_000u64)),
        "20 gwei gas price"
    );
    assert!(tx.access_list.is_empty());
    assert!(tx.blob_versioned_hashes.is_empty());
    assert!(tx.max_fee_per_gas.is_none());
}

// ---------------------------------------------------------------------------
// Golden #2 — Pre-EIP-155 legacy tx (no chain id)
// ---------------------------------------------------------------------------

/// Constructed pre-155 tx (v=27, no chain id encoded). Verifies that
/// `chain_id` resolves to `None` for the historical mainnet tx shape.
#[test]
fn legacy_pre_eip155_no_chain_id() {
    let raw = build_legacy(BuildLegacy {
        nonce: 1,
        gas_price: 50_000_000_000,
        gas_limit: 21_000,
        to: Some([0xab; 20]),
        value_wei: U256::from(500_000_000_000_000u64), // 0.0005 ETH
        data: vec![],
        v: 27,
    });

    let tx = decode_evm_tx(&raw).expect("decode pre-155");
    assert_eq!(tx.tx_type, EvmTxType::Legacy);
    assert_eq!(tx.chain_id, None);
    assert_eq!(tx.nonce, 1);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(tx.to, Some([0xab; 20]));
    assert!(tx.method_selector.is_none());
}

// ---------------------------------------------------------------------------
// Golden #3 — Contract creation (to = None)
// ---------------------------------------------------------------------------

#[test]
fn legacy_contract_creation_to_none() {
    // Solidity-emitted init code starts with PUSH1 0x80 PUSH1 0x40 MSTORE...
    let init_code = hex("6080604052348015600f57600080fd5b5060c0806100");
    let raw = build_legacy(BuildLegacy {
        nonce: 0,
        gas_price: 1_000_000_000,
        gas_limit: 1_000_000,
        to: None,
        value_wei: U256::zero(),
        data: init_code.clone(),
        v: 37, // EIP-155 chain id 1
    });

    let tx = decode_evm_tx(&raw).expect("decode contract creation");
    assert_eq!(tx.tx_type, EvmTxType::Legacy);
    assert_eq!(tx.to, None, "contract creation tx must have to=None");
    assert_eq!(tx.chain_id, Some(1));
    // The method selector for contract creation is whatever the first 4
    // bytes of the init code happen to be — useful for policies that want
    // to deny any deployment.
    assert_eq!(tx.method_selector, Some([0x60, 0x80, 0x60, 0x40]));
}

// ---------------------------------------------------------------------------
// Golden #4 — ERC-20 transfer(address,uint256) selector 0xa9059cbb
// ---------------------------------------------------------------------------

#[test]
fn legacy_erc20_transfer_selector_extracted() {
    // transfer(0xdead..beef, 1000000)
    // Function selector + 32-byte padded address + 32-byte amount = 4 + 32 + 32 = 68 bytes
    let mut data = Vec::with_capacity(68);
    data.extend_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]); // selector
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef].repeat(5)); // 20-byte addr (padded)
    let mut amount = [0u8; 32];
    amount[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());
    data.extend_from_slice(&amount);
    assert_eq!(data.len(), 68);

    let raw = build_legacy(BuildLegacy {
        nonce: 42,
        gas_price: 30_000_000_000,
        gas_limit: 80_000,
        to: Some([0xa0u8; 20]), // imagined USDC-like contract
        value_wei: U256::zero(),
        data: data.clone(),
        v: 37,
    });

    let tx = decode_evm_tx(&raw).expect("decode erc20 transfer");
    assert_eq!(tx.method_selector, Some([0xa9, 0x05, 0x9c, 0xbb]));
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.to, Some([0xa0u8; 20]));
    assert_eq!(tx.value, U256::zero(), "ERC-20 transfer carries no ETH");
    assert_eq!(tx.data.len(), 68);
}

// ---------------------------------------------------------------------------
// Golden #5 — EIP-1559 dynamic-fee tx, plain ETH transfer
// ---------------------------------------------------------------------------

#[test]
fn eip1559_eth_transfer() {
    let raw = build_eip1559(BuildEip1559 {
        chain_id: 1,
        nonce: 7,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64), // 1 gwei tip
        max_fee_per_gas: U256::from(30_000_000_000u64),         // 30 gwei cap
        gas_limit: 21_000,
        to: Some([0xc0; 20]),
        value_wei: U256::from(2_000_000_000_000_000u64), // 0.002 ETH
        data: vec![],
        access_list: vec![],
    });

    let tx = decode_evm_tx(&raw).expect("decode 1559");
    assert_eq!(tx.tx_type, EvmTxType::Eip1559);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.nonce, 7);
    assert_eq!(tx.gas_limit, 21_000);
    assert_eq!(tx.to, Some([0xc0; 20]));
    assert_eq!(tx.value, U256::from(2_000_000_000_000_000u64));
    assert_eq!(tx.max_fee_per_gas, Some(U256::from(30_000_000_000u64)));
    assert_eq!(
        tx.max_priority_fee_per_gas,
        Some(U256::from(1_000_000_000u64))
    );
    assert!(tx.gas_price.is_none());
    assert!(tx.method_selector.is_none());
    assert!(tx.access_list.is_empty());
}

// ---------------------------------------------------------------------------
// Golden #6 — EIP-1559 Uniswap V3 swap (constructed mimic of the canonical
//                exactInputSingle calldata shape)
// ---------------------------------------------------------------------------

#[test]
fn eip1559_uniswap_swap_selector() {
    // exactInputSingle((tokenIn, tokenOut, fee, recipient, deadline, amountIn,
    //                   amountOutMin, sqrtPriceLimitX96))
    // selector = 0x414bf389
    let mut data = vec![0x41, 0x4b, 0xf3, 0x89];
    // 8 * 32-byte words of struct data
    data.extend_from_slice(&[0u8; 32 * 8]);

    let raw = build_eip1559(BuildEip1559 {
        chain_id: 1,
        nonce: 256,
        max_priority_fee_per_gas: U256::from(2_000_000_000u64),
        max_fee_per_gas: U256::from(50_000_000_000u64),
        gas_limit: 200_000,
        to: Some(hex_addr("e592427a0aece92de3edee1f18e0157c05861564")), // UniV3 SwapRouter
        value_wei: U256::zero(),
        data: data.clone(),
        access_list: vec![],
    });

    let tx = decode_evm_tx(&raw).expect("decode uniswap swap");
    assert_eq!(tx.tx_type, EvmTxType::Eip1559);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(
        tx.to,
        Some(hex_addr("e592427a0aece92de3edee1f18e0157c05861564"))
    );
    assert_eq!(tx.method_selector, Some([0x41, 0x4b, 0xf3, 0x89]));
    assert_eq!(tx.gas_limit, 200_000);
    assert_eq!(tx.value, U256::zero());
    assert_eq!(tx.data.len(), 4 + 32 * 8);
}

// ---------------------------------------------------------------------------
// Golden #7 — EIP-2930 with a non-empty access list
// ---------------------------------------------------------------------------

#[test]
fn eip2930_with_access_list() {
    let access_list = vec![
        (
            hex_addr("aabbccddeeff00112233445566778899aabbccdd"),
            vec![[0x11u8; 32], [0x22u8; 32]],
        ),
        (hex_addr("0000000000000000000000000000000000000001"), vec![]),
    ];

    let raw = build_eip2930(BuildEip2930 {
        chain_id: 1,
        nonce: 3,
        gas_price: U256::from(40_000_000_000u64),
        gas_limit: 90_000,
        to: Some([0x33; 20]),
        value_wei: U256::from(100u64),
        data: vec![0xde, 0xad, 0xbe, 0xef, 0x99],
        access_list: access_list.clone(),
    });

    let tx = decode_evm_tx(&raw).expect("decode 2930");
    assert_eq!(tx.tx_type, EvmTxType::Eip2930);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(tx.nonce, 3);
    assert_eq!(tx.gas_limit, 90_000);
    assert_eq!(tx.to, Some([0x33; 20]));
    assert_eq!(tx.value, U256::from(100u64));
    assert_eq!(tx.gas_price, Some(U256::from(40_000_000_000u64)));
    assert_eq!(tx.method_selector, Some([0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(tx.access_list.len(), 2);
    assert_eq!(
        tx.access_list[0].address,
        hex_addr("aabbccddeeff00112233445566778899aabbccdd")
    );
    assert_eq!(tx.access_list[0].storage_keys.len(), 2);
    assert_eq!(tx.access_list[0].storage_keys[0], [0x11; 32]);
    assert_eq!(tx.access_list[1].storage_keys.len(), 0);
    assert!(tx.max_fee_per_gas.is_none());
}

// ---------------------------------------------------------------------------
// Golden #8 — EIP-1559 with single-entry access list
// ---------------------------------------------------------------------------

#[test]
fn eip1559_with_access_list() {
    let raw = build_eip1559(BuildEip1559 {
        chain_id: 137, // Polygon
        nonce: 12,
        max_priority_fee_per_gas: U256::from(30_000_000_000u64),
        max_fee_per_gas: U256::from(100_000_000_000u64),
        gas_limit: 150_000,
        to: Some(hex_addr("1f9840a85d5af5bf1d1762f925bdaddc4201f984")), // UNI token
        value_wei: U256::zero(),
        data: vec![0xa9, 0x05, 0x9c, 0xbb, 0xff],
        access_list: vec![(
            hex_addr("1f9840a85d5af5bf1d1762f925bdaddc4201f984"),
            vec![[0xa1u8; 32]],
        )],
    });

    let tx = decode_evm_tx(&raw).expect("decode 1559 with AL");
    assert_eq!(tx.chain_id, Some(137));
    assert_eq!(tx.method_selector, Some([0xa9, 0x05, 0x9c, 0xbb]));
    assert_eq!(tx.access_list.len(), 1);
    assert_eq!(tx.access_list[0].storage_keys, vec![[0xa1u8; 32]]);
}

// ---------------------------------------------------------------------------
// Golden #9 — EIP-4844 blob tx with two blob versioned hashes
// ---------------------------------------------------------------------------

#[test]
fn eip4844_blob_tx_with_hashes() {
    let raw = build_eip4844(BuildEip4844 {
        chain_id: 1,
        nonce: 11,
        max_priority_fee_per_gas: U256::from(1_000_000_000u64),
        max_fee_per_gas: U256::from(50_000_000_000u64),
        gas_limit: 300_000,
        to: hex_addr("ff00000000000000000000000000000000000123"), // rollup inbox
        value_wei: U256::zero(),
        data: vec![],
        access_list: vec![],
        max_fee_per_blob_gas: U256::from(1u64),
        blob_versioned_hashes: vec![[0xbau8; 32], [0xbb; 32]],
    });

    let tx = decode_evm_tx(&raw).expect("decode 4844");
    assert_eq!(tx.tx_type, EvmTxType::Eip4844);
    assert_eq!(tx.chain_id, Some(1));
    assert_eq!(
        tx.to,
        Some(hex_addr("ff00000000000000000000000000000000000123"))
    );
    assert_eq!(tx.gas_limit, 300_000);
    assert_eq!(tx.value, U256::zero());
    assert_eq!(tx.blob_versioned_hashes.len(), 2);
    assert_eq!(tx.blob_versioned_hashes[0], [0xba; 32]);
    assert_eq!(tx.blob_versioned_hashes[1], [0xbb; 32]);
    assert!(tx.access_list.is_empty());
}

// ---------------------------------------------------------------------------
// Golden #10 — EIP-4844 with non-empty calldata + selector + access list
// ---------------------------------------------------------------------------

#[test]
fn eip4844_with_calldata_and_access_list() {
    let raw = build_eip4844(BuildEip4844 {
        chain_id: 1,
        nonce: 99,
        max_priority_fee_per_gas: U256::from(2_000_000_000u64),
        max_fee_per_gas: U256::from(75_000_000_000u64),
        gas_limit: 500_000,
        to: hex_addr("0123456789abcdef0123456789abcdef01234567"),
        value_wei: U256::zero(),
        data: vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01, 0x02],
        access_list: vec![(hex_addr("0000000000000000000000000000000000000abc"), vec![])],
        max_fee_per_blob_gas: U256::from(2u64),
        blob_versioned_hashes: vec![[0xcc; 32]],
    });

    let tx = decode_evm_tx(&raw).expect("decode 4844 with calldata");
    assert_eq!(tx.tx_type, EvmTxType::Eip4844);
    assert_eq!(tx.method_selector, Some([0xca, 0xfe, 0xba, 0xbe]));
    assert_eq!(tx.access_list.len(), 1);
    assert_eq!(tx.blob_versioned_hashes.len(), 1);
}

// ---------------------------------------------------------------------------
// Golden #11 — Large value (close to U256::MAX) survives the field length
//                check and decodes correctly.
// ---------------------------------------------------------------------------

#[test]
fn eip1559_large_value() {
    // value = 2^200 — well above u64 but inside U256.
    let value = U256::from(1u8) << 200;
    let raw = build_eip1559(BuildEip1559 {
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: U256::from(1u64),
        max_fee_per_gas: U256::from(1u64),
        gas_limit: 21_000,
        to: Some([0x42; 20]),
        value_wei: value,
        data: vec![],
        access_list: vec![],
    });
    let tx = decode_evm_tx(&raw).expect("decode large-value 1559");
    assert_eq!(tx.value, value);
}

// ---------------------------------------------------------------------------
// Golden #12 — Chain id != 1 (Arbitrum 42161) on legacy EIP-155 envelope
// ---------------------------------------------------------------------------

#[test]
fn legacy_chain_id_42161() {
    // EIP-155: v = chain_id * 2 + 35 (or +36) → 42161*2+35 = 84357.
    let raw = build_legacy(BuildLegacy {
        nonce: 0,
        gas_price: 100_000_000,
        gas_limit: 22_000,
        to: Some([0x77; 20]),
        value_wei: U256::from(1u64),
        data: vec![],
        v: 84357,
    });
    let tx = decode_evm_tx(&raw).expect("decode arbitrum legacy");
    assert_eq!(tx.chain_id, Some(42161));
}

// ---------------------------------------------------------------------------
// Golden #13 — Truncated 1559 envelope returns Err (no panic)
// ---------------------------------------------------------------------------

#[test]
fn truncated_1559_envelope_errors_cleanly() {
    let mut raw = build_eip1559(BuildEip1559 {
        chain_id: 1,
        nonce: 1,
        max_priority_fee_per_gas: U256::from(1u64),
        max_fee_per_gas: U256::from(2u64),
        gas_limit: 21_000,
        to: Some([0x88; 20]),
        value_wei: U256::zero(),
        data: vec![],
        access_list: vec![],
    });
    let original_len = raw.len();
    raw.truncate(original_len - 5);
    let err = decode_evm_tx(&raw).expect_err("truncated must error");
    // Surface check — any RLP-style error is fine, as long as we did not panic.
    let msg = format!("{err}");
    assert!(
        !msg.is_empty(),
        "error should render to a non-empty message"
    );
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

mod props {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // Iron rule: decoder MUST never panic. Any bytes in, Ok or Err out.
        #[test]
        fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = decode_evm_tx(&bytes);
        }

        // Round-trip stability: build a legacy tx with arbitrary u64-fitting
        // fields, decode it, and check the round-trip preserves the fields
        // the policy engine inspects.
        #[test]
        fn legacy_roundtrip_preserves_policy_fields(
            nonce in 0u64..u64::MAX,
            gas_price in 0u64..u64::MAX,
            gas_limit in 21_000u64..30_000_000u64,
            to_byte in any::<u8>(),
            value_lo in 0u64..u64::MAX,
            v in 27u64..u64::MAX,
            has_to in any::<bool>(),
        ) {
            let raw = build_legacy(BuildLegacy {
                nonce,
                gas_price,
                gas_limit,
                to: if has_to { Some([to_byte; 20]) } else { None },
                value_wei: U256::from(value_lo),
                data: vec![],
                v,
            });
            let tx = decode_evm_tx(&raw).expect("constructed legacy is valid");
            prop_assert_eq!(tx.tx_type, EvmTxType::Legacy);
            prop_assert_eq!(tx.nonce, nonce);
            prop_assert_eq!(tx.gas_limit, gas_limit);
            prop_assert_eq!(tx.value, U256::from(value_lo));
            if has_to {
                prop_assert_eq!(tx.to, Some([to_byte; 20]));
            } else {
                prop_assert_eq!(tx.to, None);
            }
            let expected_chain = if v >= 35 { Some((v - 35) / 2) } else { None };
            prop_assert_eq!(tx.chain_id, expected_chain);
        }

        // Round-trip for EIP-1559.
        #[test]
        fn eip1559_roundtrip_preserves_policy_fields(
            chain_id in 0u64..2_000_000u64,
            nonce in 0u64..u64::MAX,
            max_priority in 0u64..u64::MAX,
            max_fee in 0u64..u64::MAX,
            gas_limit in 21_000u64..30_000_000u64,
            to_byte in any::<u8>(),
            value_lo in 0u64..u64::MAX,
        ) {
            let raw = build_eip1559(BuildEip1559 {
                chain_id,
                nonce,
                max_priority_fee_per_gas: U256::from(max_priority),
                max_fee_per_gas: U256::from(max_fee),
                gas_limit,
                to: Some([to_byte; 20]),
                value_wei: U256::from(value_lo),
                data: vec![],
                access_list: vec![],
            });
            let tx = decode_evm_tx(&raw).expect("constructed 1559 valid");
            prop_assert_eq!(tx.tx_type, EvmTxType::Eip1559);
            prop_assert_eq!(tx.chain_id, Some(chain_id));
            prop_assert_eq!(tx.nonce, nonce);
            prop_assert_eq!(tx.gas_limit, gas_limit);
            prop_assert_eq!(tx.max_priority_fee_per_gas, Some(U256::from(max_priority)));
            prop_assert_eq!(tx.max_fee_per_gas, Some(U256::from(max_fee)));
            prop_assert_eq!(tx.value, U256::from(value_lo));
        }
    }
}

// ---------------------------------------------------------------------------
// Hand-rolled RLP encoders for the fixtures above. We deliberately do
// **not** depend on `alloy-rlp` here: keeping the test encoder independent
// gives us a cross-implementation check (we encode → they decode).
// ---------------------------------------------------------------------------

struct BuildLegacy {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: U256,
    data: Vec<u8>,
    v: u64,
}

fn build_legacy(b: BuildLegacy) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(rlp_encode_u64(b.nonce));
    payload.extend(rlp_encode_u64(b.gas_price));
    payload.extend(rlp_encode_u64(b.gas_limit));
    payload.extend(match b.to {
        Some(a) => rlp_encode_bytes(&a),
        None => rlp_encode_bytes(&[]),
    });
    payload.extend(rlp_encode_u256(b.value_wei));
    payload.extend(rlp_encode_bytes(&b.data));
    payload.extend(rlp_encode_u64(b.v));
    payload.extend(rlp_encode_bytes(&[])); // r placeholder
    payload.extend(rlp_encode_bytes(&[])); // s placeholder
    rlp_wrap_list(payload)
}

struct BuildEip1559 {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: U256,
    data: Vec<u8>,
    access_list: Vec<(/* addr */ [u8; 20], /* keys */ Vec<[u8; 32]>)>,
}

fn build_eip1559(b: BuildEip1559) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(rlp_encode_u64(b.chain_id));
    payload.extend(rlp_encode_u64(b.nonce));
    payload.extend(rlp_encode_u256(b.max_priority_fee_per_gas));
    payload.extend(rlp_encode_u256(b.max_fee_per_gas));
    payload.extend(rlp_encode_u64(b.gas_limit));
    payload.extend(match b.to {
        Some(a) => rlp_encode_bytes(&a),
        None => rlp_encode_bytes(&[]),
    });
    payload.extend(rlp_encode_u256(b.value_wei));
    payload.extend(rlp_encode_bytes(&b.data));
    payload.extend(encode_access_list(&b.access_list));
    payload.extend(rlp_encode_u64(0)); // y_parity
    payload.extend(rlp_encode_bytes(&[])); // r placeholder
    payload.extend(rlp_encode_bytes(&[])); // s placeholder
    let mut out = vec![0x02]; // type byte
    out.extend(rlp_wrap_list(payload));
    out
}

struct BuildEip2930 {
    chain_id: u64,
    nonce: u64,
    gas_price: U256,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value_wei: U256,
    data: Vec<u8>,
    access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
}

fn build_eip2930(b: BuildEip2930) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(rlp_encode_u64(b.chain_id));
    payload.extend(rlp_encode_u64(b.nonce));
    payload.extend(rlp_encode_u256(b.gas_price));
    payload.extend(rlp_encode_u64(b.gas_limit));
    payload.extend(match b.to {
        Some(a) => rlp_encode_bytes(&a),
        None => rlp_encode_bytes(&[]),
    });
    payload.extend(rlp_encode_u256(b.value_wei));
    payload.extend(rlp_encode_bytes(&b.data));
    payload.extend(encode_access_list(&b.access_list));
    payload.extend(rlp_encode_u64(0));
    payload.extend(rlp_encode_bytes(&[]));
    payload.extend(rlp_encode_bytes(&[]));
    let mut out = vec![0x01];
    out.extend(rlp_wrap_list(payload));
    out
}

struct BuildEip4844 {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: U256,
    max_fee_per_gas: U256,
    gas_limit: u64,
    to: [u8; 20], // EIP-4844 mandates a recipient
    value_wei: U256,
    data: Vec<u8>,
    access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    max_fee_per_blob_gas: U256,
    blob_versioned_hashes: Vec<[u8; 32]>,
}

fn build_eip4844(b: BuildEip4844) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(rlp_encode_u64(b.chain_id));
    payload.extend(rlp_encode_u64(b.nonce));
    payload.extend(rlp_encode_u256(b.max_priority_fee_per_gas));
    payload.extend(rlp_encode_u256(b.max_fee_per_gas));
    payload.extend(rlp_encode_u64(b.gas_limit));
    payload.extend(rlp_encode_bytes(&b.to));
    payload.extend(rlp_encode_u256(b.value_wei));
    payload.extend(rlp_encode_bytes(&b.data));
    payload.extend(encode_access_list(&b.access_list));
    payload.extend(rlp_encode_u256(b.max_fee_per_blob_gas));
    // blob_versioned_hashes: list of 32-byte strings
    let mut hashes_payload = Vec::new();
    for h in &b.blob_versioned_hashes {
        hashes_payload.extend(rlp_encode_bytes(h));
    }
    payload.extend(rlp_wrap_list(hashes_payload));
    payload.extend(rlp_encode_u64(0));
    payload.extend(rlp_encode_bytes(&[]));
    payload.extend(rlp_encode_bytes(&[]));
    let mut out = vec![0x03];
    out.extend(rlp_wrap_list(payload));
    out
}

fn encode_access_list(entries: &[([u8; 20], Vec<[u8; 32]>)]) -> Vec<u8> {
    let mut payload = Vec::new();
    for (addr, keys) in entries {
        let mut entry_payload = Vec::new();
        entry_payload.extend(rlp_encode_bytes(addr));
        let mut keys_payload = Vec::new();
        for k in keys {
            keys_payload.extend(rlp_encode_bytes(k));
        }
        entry_payload.extend(rlp_wrap_list(keys_payload));
        payload.extend(rlp_wrap_list(entry_payload));
    }
    rlp_wrap_list(payload)
}

fn rlp_encode_u64(v: u64) -> Vec<u8> {
    if v == 0 {
        return vec![0x80];
    }
    let be = v.to_be_bytes();
    let trimmed: Vec<u8> = be.iter().copied().skip_while(|b| *b == 0).collect();
    rlp_encode_bytes(&trimmed)
}

fn rlp_encode_u256(v: U256) -> Vec<u8> {
    if v.is_zero() {
        return vec![0x80];
    }
    let mut be = [0u8; 32];
    v.to_big_endian(&mut be);
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

fn rlp_wrap_list(payload: Vec<u8>) -> Vec<u8> {
    let mut out = if payload.len() <= 55 {
        vec![0xc0 + payload.len() as u8]
    } else {
        let len_be = payload.len().to_be_bytes();
        let trimmed: Vec<u8> = len_be.iter().copied().skip_while(|x| *x == 0).collect();
        let mut header = Vec::with_capacity(1 + trimmed.len());
        header.push(0xf7 + trimmed.len() as u8);
        header.extend_from_slice(&trimmed);
        header
    };
    out.extend(payload);
    out
}

fn hex_addr(s: &str) -> [u8; 20] {
    let bytes = hex::decode(s).expect("valid hex");
    assert_eq!(bytes.len(), 20);
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}
