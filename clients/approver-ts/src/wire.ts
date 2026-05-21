/**
 * Wire-format DTOs. These mirror `clients/approver-rs/src/wire.rs` and
 * the server-side `qfc_server_wallet::api::schemas::SubmitApprovalRequest`.
 *
 * Kept as `interface` types so the JSON shape is self-documenting.
 */

import type { Scheme } from "./signer.js";

/** Curves on the wire. snake_case to match the Rust serde rename. */
export type SchemeWire =
  | "ed25519"
  | "secp256k1"
  | "secp256k1_recoverable"
  | "ml_dsa44"
  | "ml_dsa65"
  | "ml_dsa87";

/** Approver-identity payload. Tagged-union via `kind`. */
export type ApproverIdentityWire =
  | {
      kind: "chain";
      chain_id: number;
      address_hex: string;
      public_key_hex: string;
      scheme: SchemeWire;
    }
  | {
      kind: "external";
      id: string;
      public_key_hex: string;
      scheme: SchemeWire;
    }
  | {
      kind: "hardware";
      handle: string;
      public_key_hex: string;
      scheme: SchemeWire;
    }
  | {
      kind: "nested_wallet";
      wallet_id: string;
      public_key_hex: string;
      scheme: SchemeWire;
    };

/** `ApprovalRequest` body emitted by the server's WebhookApprover. */
export interface ApprovalRequestWire {
  request_id: string;
  message_hash: string;
  approver_set: ApproverIdentityWire[];
  threshold: number;
}

/** `POST /requests/{request_id}/approvals` body. */
export interface SubmitApprovalWire {
  approver_id: string;
  approval_id: string;
  decision: "approve" | "reject";
  signature_hex: string;
  timestamp_unix_ms: number;
  message_hash_hex: string;
  identity: ApproverIdentityWire;
}

/** Narrow a CLI `--scheme` value into the wire form. */
export function schemeToWire(s: Scheme): SchemeWire {
  return s; // both CLI values match snake-case wire form one-to-one
}
