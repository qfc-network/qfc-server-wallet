/**
 * Express router that receives `POST /` webhooks from the qfc-server-wallet,
 * verifies the `X-QFC-Signature` HMAC, parses the body, and dispatches
 * to a `Processor`-style handler.
 */

import express, { type Express, type Request, type Response } from "express";
import { createHmac, timingSafeEqual } from "node:crypto";

import type { ApprovalRequestWire } from "./wire.js";

export const WEBHOOK_SIGNATURE_HEADER = "x-qfc-signature";

export type WebhookHandler = (
  req: ApprovalRequestWire,
) => Promise<void>;

export interface WebhookOptions {
  /** Shared HMAC secret. */
  hmacSecret: Buffer;
  /** Handler called once per verified webhook. */
  handler: WebhookHandler;
}

/**
 * Verify the HMAC header in constant time. Returns true on match.
 *
 * Constant-time over the comparison; the early-exit checks (header
 * missing / wrong length) leak only the size of the failure, never the
 * MAC contents.
 */
export function verifyHmac(
  rawBody: Buffer,
  headerHex: string | undefined,
  secret: Buffer,
): true | { error: "missing" | "malformed" | "mismatch"; reason?: string } {
  if (!headerHex) {
    return { error: "missing" };
  }
  if (!/^[0-9a-fA-F]+$/.test(headerHex)) {
    return { error: "malformed", reason: "not hex" };
  }
  let provided: Buffer;
  try {
    provided = Buffer.from(headerHex, "hex");
  } catch {
    return { error: "malformed", reason: "hex decode failed" };
  }
  if (provided.length !== 32) {
    return {
      error: "malformed",
      reason: `expected 32 raw bytes, got ${provided.length}`,
    };
  }
  const expected = createHmac("sha256", secret).update(rawBody).digest();
  if (expected.length !== provided.length) {
    return { error: "mismatch" };
  }
  if (!timingSafeEqual(expected, provided)) {
    return { error: "mismatch" };
  }
  return true;
}

/**
 * Build the express app. The raw body is buffered (not JSON-parsed
 * first) so the HMAC is computed over the exact bytes the server sent.
 */
export function buildApp(opts: WebhookOptions): Express {
  const app = express();
  app.use(express.raw({ type: "*/*", limit: "1mb" }));
  app.post("/", async (req: Request, res: Response) => {
    const raw = req.body as Buffer;
    const sig = req.header(WEBHOOK_SIGNATURE_HEADER);
    const verdict = verifyHmac(raw, sig, opts.hmacSecret);
    if (verdict !== true) {
      const status = verdict.error === "mismatch" ? 401 : verdict.error === "missing" ? 401 : 401;
      res.status(status).send(
        `signature ${verdict.error}${verdict.reason ? `: ${verdict.reason}` : ""}`,
      );
      return;
    }
    let parsed: ApprovalRequestWire;
    try {
      parsed = JSON.parse(raw.toString("utf8")) as ApprovalRequestWire;
    } catch (err) {
      res.status(400).send(`invalid json: ${(err as Error).message}`);
      return;
    }
    try {
      await opts.handler(parsed);
      res.status(200).send("ok");
    } catch (err) {
      res.status(500).send(`handler failed: ${(err as Error).message}`);
    }
  });
  return app;
}
