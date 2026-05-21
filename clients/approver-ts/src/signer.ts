/**
 * Approver-side signer. Wraps `@noble/curves` so the rest of the client
 * only sees `signApproval(scheme, secret, preimage) -> hex`.
 *
 * Both schemes accept exactly 32 bytes of secret material:
 *   - ed25519 — RFC 8032 seed
 *   - secp256k1 — raw scalar (1..=N-1)
 *
 * Hash alg follows what `qfc_quorum::approval::hash_alg_for(scheme)` does:
 *   - ed25519: None (ed25519 hashes internally)
 *   - secp256k1: SHA-256 prehash (k256 `ecdsa` deterministic mode)
 *
 * Production hardware-backed integrations can replace this module
 * wholesale — the only contract the rest of the client cares about is
 * `signApproval(...) -> hex` + `publicKeyFor(...) -> hex`.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";

import { bytesToHex } from "./preimage.js";

export type Scheme = "ed25519" | "secp256k1";

/** Validate that `secret` is 32 bytes; throw a friendly error otherwise. */
function require32(secret: Uint8Array): void {
  if (secret.length !== 32) {
    throw new RangeError(`secret must be exactly 32 bytes, got ${secret.length}`);
  }
}

/** Compute the compressed public key for `secret` under `scheme`. */
export function publicKeyFor(scheme: Scheme, secret: Uint8Array): Uint8Array {
  require32(secret);
  switch (scheme) {
    case "ed25519":
      return ed25519.getPublicKey(secret);
    case "secp256k1":
      // SEC1 compressed (33 bytes). Matches the Rust `Secp256k1Signer::public_key` shape.
      return secp256k1.getPublicKey(secret, true);
    default: {
      const _exhaustive: never = scheme;
      throw new Error(`unsupported scheme: ${_exhaustive as string}`);
    }
  }
}

/**
 * Sign `preimage` and return the raw signature bytes.
 *
 * The signature encoding matches what the Rust enclave's `Signer`
 * produces — ed25519 = 64 bytes (R || S), secp256k1 = 64 bytes (r || s)
 * fixed-width, low-S form.
 */
export function signApproval(
  scheme: Scheme,
  secret: Uint8Array,
  preimage: Uint8Array,
): Uint8Array {
  require32(secret);
  switch (scheme) {
    case "ed25519":
      return ed25519.sign(preimage, secret);
    case "secp256k1": {
      // SHA-256 prehash + deterministic ECDSA, normalized to low-S.
      // `signature.toCompactRawBytes()` returns 64 bytes (r || s).
      const digest = sha256(preimage);
      const sig = secp256k1.sign(digest, secret, { lowS: true });
      return sig.toCompactRawBytes();
    }
    default: {
      const _exhaustive: never = scheme;
      throw new Error(`unsupported scheme: ${_exhaustive as string}`);
    }
  }
}

/** Hex-encoded signature. Convenience wrapper. */
export function signApprovalHex(
  scheme: Scheme,
  secret: Uint8Array,
  preimage: Uint8Array,
): string {
  return bytesToHex(signApproval(scheme, secret, preimage));
}
