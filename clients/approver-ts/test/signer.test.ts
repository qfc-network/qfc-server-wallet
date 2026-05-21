/**
 * Signer smoke tests. We can't easily verify against the Rust signer in
 * JS, but we can round-trip via @noble/curves' own verify path — that's
 * the same library both sides would ultimately deserialize signatures
 * with at the curve layer.
 */

import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";

import { publicKeyFor, signApproval } from "../src/signer.js";

describe("signer", () => {
  it("ed25519 signs and round-trips", () => {
    const secret = new Uint8Array(32).fill(42);
    const pub = publicKeyFor("ed25519", secret);
    expect(pub).toHaveLength(32);
    const preimage = Buffer.from("hello world");
    const sig = signApproval("ed25519", secret, preimage);
    expect(sig).toHaveLength(64);
    expect(ed25519.verify(sig, preimage, pub)).toBe(true);
  });

  it("secp256k1 signs and round-trips with sha256 prehash", () => {
    // Use a key safely inside the curve order.
    const secret = new Uint8Array(32);
    secret[31] = 0x01;
    const pub = publicKeyFor("secp256k1", secret);
    expect(pub).toHaveLength(33);
    const preimage = Buffer.from("hello world");
    const sig = signApproval("secp256k1", secret, preimage);
    expect(sig).toHaveLength(64);
    // @noble verifies against the raw 32-byte digest.
    const digest = sha256(preimage);
    expect(secp256k1.verify(sig, digest, pub, { lowS: true })).toBe(true);
  });

  it("rejects non-32-byte secrets", () => {
    expect(() => signApproval("ed25519", new Uint8Array(16), new Uint8Array(1))).toThrow();
  });
});
