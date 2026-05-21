/**
 * Byte-exact reconstruction of `qfc_quorum::SignedApproval::signing_preimage`.
 *
 * Layout (matches `crates/qfc-quorum/src/approval.rs`):
 *   approval_id_ascii (26)
 *   '|' (0x7c)
 *   request_id_ascii  (26)
 *   '|'
 *   message_hash      (32 bytes)
 *   '|'
 *   decision_byte     (0x01 approve, 0x00 reject)
 *   '|'
 *   timestamp_unix_ms BIG-ENDIAN i64 (8 bytes)
 *
 * Total length: 97 bytes.
 *
 * Pinned against the Rust side via the JSON fixture at
 * `test/fixtures/preimage_golden.json`.
 */

export type Decision = "approve" | "reject";

export interface PreimageInputs {
  /** ULID string of the approval action (26 chars). */
  approvalId: string;
  /** ULID string of the signing request being approved (26 chars). */
  requestId: string;
  /** Raw 32-byte SHA-256 of the message being signed. */
  messageHash: Uint8Array;
  /** Approve or reject. */
  decision: Decision;
  /** Unix-millisecond timestamp the approval was signed at. */
  timestampUnixMs: bigint;
}

/** Total preimage length in bytes. Public so callers can assert. */
export const PREIMAGE_LEN = 97;

/** Build the canonical preimage bytes. Pure function, no side effects. */
export function buildSigningPreimage(inputs: PreimageInputs): Uint8Array {
  if (inputs.approvalId.length !== 26) {
    throw new RangeError(`approvalId must be 26 chars, got ${inputs.approvalId.length}`);
  }
  if (inputs.requestId.length !== 26) {
    throw new RangeError(`requestId must be 26 chars, got ${inputs.requestId.length}`);
  }
  if (inputs.messageHash.length !== 32) {
    throw new RangeError(
      `messageHash must be 32 bytes, got ${inputs.messageHash.length}`,
    );
  }
  const out = new Uint8Array(PREIMAGE_LEN);
  const enc = new TextEncoder();
  let off = 0;
  out.set(enc.encode(inputs.approvalId), off);
  off += 26;
  out[off++] = 0x7c; // '|'
  out.set(enc.encode(inputs.requestId), off);
  off += 26;
  out[off++] = 0x7c;
  out.set(inputs.messageHash, off);
  off += 32;
  out[off++] = 0x7c;
  out[off++] = inputs.decision === "approve" ? 0x01 : 0x00;
  out[off++] = 0x7c;
  // i64 BE encoding of timestamp.
  // BigInt64Array would do little-endian on most hosts; we encode by hand
  // so the byte order is unambiguous regardless of platform.
  let ts = inputs.timestampUnixMs;
  for (let i = 7; i >= 0; i--) {
    out[off + i] = Number(ts & 0xffn);
    ts >>= 8n;
  }
  off += 8;
  if (off !== PREIMAGE_LEN) {
    throw new Error(`preimage length sanity check failed: ${off} != ${PREIMAGE_LEN}`);
  }
  return out;
}

/** Convenience: hex-encode a byte buffer (lowercase, no prefix). */
export function bytesToHex(buf: Uint8Array): string {
  let s = "";
  for (let i = 0; i < buf.length; i++) {
    s += buf[i].toString(16).padStart(2, "0");
  }
  return s;
}

/** Convenience: parse a hex string into raw bytes. */
export function hexToBytes(hex: string): Uint8Array {
  const s = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (s.length % 2 !== 0) {
    throw new RangeError(`hex string has odd length: ${s.length}`);
  }
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new RangeError(`invalid hex byte at offset ${i * 2}`);
    }
    out[i] = byte;
  }
  return out;
}
