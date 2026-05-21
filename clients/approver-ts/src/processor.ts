/**
 * Per-request approval flow. Mirrors `clients/approver-rs/src/processor.rs`.
 */

import { request as undiciRequest } from "undici";

import { appendAudit, type AuditRecord } from "./audit.js";
import { buildSigningPreimage, bytesToHex, hexToBytes } from "./preimage.js";
import { promptForDecision } from "./prompt.js";
import { publicKeyFor, signApproval, type Scheme } from "./signer.js";
import { newUlid } from "./ulid.js";
import type {
  ApprovalRequestWire,
  ApproverIdentityWire,
  SubmitApprovalWire,
} from "./wire.js";

export type DecisionPolicy = "auto_approve" | "auto_reject" | "interactive" | "refuse";

export interface ProcessorConfig {
  server: string;
  approverId: string;
  policy: DecisionPolicy;
  auditPath: string;
  scheme: Scheme;
  secret: Uint8Array;
  /** Optional identity override echoed on the wire. */
  identity?: ApproverIdentityWire;
}

export interface ProcessOutcome {
  decision: "approve" | "reject" | "refuse";
  serverStatus?: number;
  approvalId: string;
}

export class Processor {
  constructor(private readonly cfg: ProcessorConfig) {}

  async process(req: ApprovalRequestWire): Promise<ProcessOutcome> {
    const decision = await this.decide(req);
    if (decision === "refuse") {
      await this.audit({
        timestamp: nowIso(),
        event: "refused",
        request_id: req.request_id,
        approver_id: this.cfg.approverId,
        message_hash_hex: req.message_hash,
        decision: "refused",
        note: "operator refused",
      });
      return { decision, approvalId: "" };
    }

    const approvalId = newUlid();
    const timestampUnixMs = BigInt(Date.now());
    const messageHash = hexToBytes(req.message_hash);
    if (messageHash.length !== 32) {
      throw new RangeError(
        `message_hash must decode to 32 bytes, got ${messageHash.length}`,
      );
    }
    const preimage = buildSigningPreimage({
      approvalId,
      requestId: req.request_id,
      messageHash,
      decision,
      timestampUnixMs,
    });
    const signature = signApproval(this.cfg.scheme, this.cfg.secret, preimage);
    const signatureHex = bytesToHex(signature);

    const body: SubmitApprovalWire = {
      approver_id: this.cfg.approverId,
      approval_id: approvalId,
      decision,
      signature_hex: signatureHex,
      timestamp_unix_ms: Number(timestampUnixMs),
      message_hash_hex: req.message_hash,
      identity: this.identityForWire(),
    };

    const url = `${this.cfg.server.replace(/\/$/, "")}/requests/${req.request_id}/approvals`;
    const resp = await undiciRequest(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const status = resp.statusCode;
    // Drain body to free the socket.
    await resp.body.text();

    await this.audit({
      timestamp: nowIso(),
      event: status >= 200 && status < 300 ? "posted" : "error",
      request_id: req.request_id,
      approver_id: this.cfg.approverId,
      message_hash_hex: req.message_hash,
      decision,
      signature_hex: signatureHex,
      server_status: status,
    });

    return { decision, serverStatus: status, approvalId };
  }

  private async decide(req: ApprovalRequestWire): Promise<"approve" | "reject" | "refuse"> {
    switch (this.cfg.policy) {
      case "auto_approve":
        return "approve";
      case "auto_reject":
        return "reject";
      case "refuse":
        return "refuse";
      case "interactive": {
        const summary =
          `request_id    = ${req.request_id}\n` +
          `message_hash  = ${req.message_hash}\n` +
          `threshold     = ${req.threshold} of ${req.approver_set.length}`;
        return promptForDecision(summary);
      }
    }
  }

  private identityForWire(): ApproverIdentityWire {
    if (this.cfg.identity) {
      return this.cfg.identity;
    }
    return {
      kind: "external",
      id: this.cfg.approverId,
      public_key_hex: bytesToHex(publicKeyFor(this.cfg.scheme, this.cfg.secret)),
      scheme: this.cfg.scheme,
    };
  }

  private async audit(record: AuditRecord): Promise<void> {
    try {
      await appendAudit(this.cfg.auditPath, record);
    } catch {
      // Audit failures shouldn't crash the daemon; log via stderr.
      process.stderr.write(`audit write failed for request ${record.request_id}\n`);
    }
  }
}

function nowIso(): string {
  return new Date().toISOString();
}
