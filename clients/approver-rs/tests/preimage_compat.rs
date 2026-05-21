//! Cross-crate integration test: the bytes the client signs MUST equal
//! what the server's verifier will reconstruct.
//!
//! Both sides call the *same* `qfc_quorum::SignedApproval::signing_preimage`
//! function — that's already a strong guarantee — but pinning it here
//! gives us a deterministic golden-vector that the TypeScript client's
//! test fixture also consumes (see
//! `clients/approver-ts/test/fixtures/preimage_golden.json`).

use qfc_quorum::{ApprovalDecision, SignedApproval};
use qfc_wallet_types::{ApprovalId, RequestId};
use ulid::Ulid;

/// Build a preimage with deterministic inputs and check the byte length
/// plus a snapshot of the layout. This is the same recipe used by
/// `tools/gen-golden-vectors` to produce the TS fixture.
#[test]
fn deterministic_preimage_snapshot() {
    let approval_id =
        ApprovalId::from_ulid(Ulid::from_string("01J7Z9C5K3MX5W1H7E1D9V4Q2R").unwrap());
    let request_id = RequestId::from_ulid(Ulid::from_string("01J7Z9C5K3MX5W1H7E1D9V4Q2S").unwrap());
    let message_hash: [u8; 32] = [0xAB; 32];
    let timestamp_unix_ms: i64 = 1_724_400_000_000;

    let approve = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        ApprovalDecision::Approve,
        timestamp_unix_ms,
    );
    let reject = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &message_hash,
        ApprovalDecision::Reject,
        timestamp_unix_ms,
    );

    // Layout: approval_id (26) | '|' | request_id (26) | '|' |
    //         message_hash (32) | '|' | decision_byte (1) | '|' |
    //         timestamp_be (8) = 26 + 1 + 26 + 1 + 32 + 1 + 1 + 1 + 8 = 97
    assert_eq!(approve.len(), 97);
    assert_eq!(reject.len(), 97);

    // The only differing byte is the decision marker.
    let diffs: Vec<usize> = approve
        .iter()
        .zip(reject.iter())
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    assert_eq!(diffs, vec![26 + 1 + 26 + 1 + 32 + 1]);
    // Approve = 0x01, Reject = 0x00.
    assert_eq!(approve[diffs[0]], 0x01);
    assert_eq!(reject[diffs[0]], 0x00);

    // Pinned hex of the approve preimage. Any change here means the wire
    // contract changed — bump the golden vector + TS fixture in lockstep.
    let approve_hex = hex::encode(&approve);
    let expected = "30314a375a3943354b334d583557314837453144395634513252\
         7c\
         30314a375a3943354b334d583557314837453144395634513253\
         7c\
         abababababababababababababababababababababababababababababababab\
         7c\
         01\
         7c\
         000001917e3fdc00";
    let expected_clean: String = expected.chars().filter(|c| !c.is_whitespace()).collect();
    assert_eq!(approve_hex, expected_clean);
}

/// Sanity: timestamp is encoded as i64 big-endian (NOT little-endian).
#[test]
fn timestamp_is_big_endian_i64() {
    let approval_id =
        ApprovalId::from_ulid(Ulid::from_string("01J7Z9C5K3MX5W1H7E1D9V4Q2R").unwrap());
    let request_id = RequestId::from_ulid(Ulid::from_string("01J7Z9C5K3MX5W1H7E1D9V4Q2S").unwrap());
    let preimage = SignedApproval::signing_preimage(
        &approval_id,
        &request_id,
        &[0u8; 32],
        ApprovalDecision::Approve,
        1,
    );
    let ts_bytes = &preimage[preimage.len() - 8..];
    assert_eq!(ts_bytes, &[0, 0, 0, 0, 0, 0, 0, 1]);
}
