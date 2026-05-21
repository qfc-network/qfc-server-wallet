/**
 * End-to-end Processor test. Uses a stub HTTP server (node `http`) as
 * the qfc-server-wallet, observes the outbound POST shape.
 */

import { afterEach, describe, expect, it } from "vitest";
import { createServer, type IncomingMessage, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { Processor, type ProcessorConfig } from "../src/processor.js";

interface CapturedRequest {
  url: string;
  body: string;
}

function startStubServer(
  status: number,
  collected: CapturedRequest[],
): Promise<{ server: Server; port: number }> {
  return new Promise((resolve) => {
    const server = createServer((req: IncomingMessage, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        collected.push({
          url: req.url ?? "",
          body: Buffer.concat(chunks).toString("utf8"),
        });
        res.statusCode = status;
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ recorded: true, approval_id: "ignored" }));
      });
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") throw new Error("no addr");
      resolve({ server, port: addr.port });
    });
  });
}

describe("Processor", () => {
  let cleanup: Server | undefined;
  afterEach(() => {
    cleanup?.close();
    cleanup = undefined;
  });

  it("auto_approve signs + POSTs the canonical shape", async () => {
    const collected: CapturedRequest[] = [];
    const { server, port } = await startStubServer(200, collected);
    cleanup = server;
    const dir = mkdtempSync(join(tmpdir(), "qfc-approver-ts-"));
    const cfg: ProcessorConfig = {
      server: `http://127.0.0.1:${port}`,
      approverId: "01HABCDEFGHJKMNPQRSTVWXYZ0",
      policy: "auto_approve",
      auditPath: join(dir, "audit.log"),
      scheme: "ed25519",
      secret: new Uint8Array(32).fill(7),
    };
    const p = new Processor(cfg);
    const req = {
      request_id: "01J7Z9C5K3MX5W1H7E1D9V4Q2S",
      message_hash: "ab".repeat(32),
      approver_set: [],
      threshold: 1,
    };
    const outcome = await p.process(req);
    expect(outcome.decision).toBe("approve");
    expect(outcome.serverStatus).toBe(200);
    expect(collected).toHaveLength(1);
    expect(collected[0].url).toBe("/requests/01J7Z9C5K3MX5W1H7E1D9V4Q2S/approvals");
    const body = JSON.parse(collected[0].body);
    expect(body.decision).toBe("approve");
    expect(body.approver_id).toBe("01HABCDEFGHJKMNPQRSTVWXYZ0");
    expect(body.signature_hex).toMatch(/^[0-9a-f]{128}$/);
    expect(body.message_hash_hex).toBe("ab".repeat(32));
    expect(body.identity.kind).toBe("external");

    const audit = readFileSync(cfg.auditPath, "utf8");
    expect(audit).toMatch(/"posted"/);
  });

  it("refuse policy skips HTTP entirely", async () => {
    const collected: CapturedRequest[] = [];
    const { server, port } = await startStubServer(500, collected);
    cleanup = server;
    const dir = mkdtempSync(join(tmpdir(), "qfc-approver-ts-"));
    const cfg: ProcessorConfig = {
      server: `http://127.0.0.1:${port}`,
      approverId: "01H",
      policy: "refuse",
      auditPath: join(dir, "audit.log"),
      scheme: "ed25519",
      secret: new Uint8Array(32).fill(1),
    };
    const p = new Processor(cfg);
    const outcome = await p.process({
      request_id: "01J7Z9C5K3MX5W1H7E1D9V4Q2S",
      message_hash: "00".repeat(32),
      approver_set: [],
      threshold: 1,
    });
    expect(outcome.decision).toBe("refuse");
    expect(outcome.serverStatus).toBeUndefined();
    expect(collected).toHaveLength(0);
    const audit = readFileSync(cfg.auditPath, "utf8");
    expect(audit).toMatch(/"refused"/);
  });
});
