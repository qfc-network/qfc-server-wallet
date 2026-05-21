/**
 * Tiny ULID minter.
 *
 * Per the ULID spec (https://github.com/ulid/spec):
 *   - 48-bit timestamp (ms since epoch, big-endian)   → first 10 base32 chars
 *   - 80 bits of cryptographic randomness             → next 16 base32 chars
 *
 * Encoded as 26 chars of Crockford base32.
 */

import { randomBytes } from "node:crypto";

const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Encode a non-negative bigint into exactly `len` base32 chars. */
function encodeBigInt(value: bigint, len: number): string {
  let out = "";
  let v = value;
  for (let i = 0; i < len; i++) {
    out = ENCODING[Number(v & 0x1fn)] + out;
    v >>= 5n;
  }
  if (v !== 0n) {
    throw new Error(`encodeBigInt overflow: ${value} needs more than ${len} chars`);
  }
  return out;
}

/** Generate a fresh ULID string (26 chars, Crockford base32). */
export function newUlid(): string {
  const now = BigInt(Date.now()); // fits in 48 bits for the next ~8900 years
  const tsPart = encodeBigInt(now, 10); // 48 bits encoded as 10 chars (50 bits, top 2 zero)

  const randB = randomBytes(10);
  let randAcc = 0n;
  for (let i = 0; i < 10; i++) {
    randAcc = (randAcc << 8n) | BigInt(randB[i]);
  }
  const randPart = encodeBigInt(randAcc, 16); // 80 bits exactly → 16 chars
  return tsPart + randPart;
}
