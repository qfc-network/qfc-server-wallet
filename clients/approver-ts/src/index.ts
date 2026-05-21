#!/usr/bin/env node
/**
 * qfc-approver — reference approver-side daemon (TypeScript).
 *
 * See `clients/approver-ts/README.md` for the quickstart.
 */

import { readFileSync } from "node:fs";
import { Command, Option } from "commander";
import pino from "pino";

import { defaultAuditPath } from "./audit.js";
import { Processor, type DecisionPolicy, type ProcessorConfig } from "./processor.js";
import { type Scheme } from "./signer.js";
import { buildApp } from "./webhook.js";

const log = pino({ level: process.env.LOG_LEVEL ?? "info" });

function loadSecret(path: string): Uint8Array {
  const bytes = readFileSync(path);
  if (bytes.length !== 32) {
    throw new RangeError(`secret file ${path} must be exactly 32 bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

function loadWebhookSecret(spec: string): Buffer {
  if (spec.startsWith("@")) {
    return readFileSync(spec.slice(1));
  }
  return Buffer.from(spec, "utf8");
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name("qfc-approver")
    .description("Reference approver-side client for the QFC server wallet")
    .version("0.1.0")
    .requiredOption("--server <url>", "qfc-server-wallet base URL")
    .requiredOption("--approver-id <ulid>", "ULID this client identifies as")
    .requiredOption("--secret-file <path>", "32-byte raw signing key file")
    .requiredOption("--webhook-secret <spec>", "HMAC secret (literal or @path/to/file)")
    .addOption(
      new Option("--scheme <s>", "signing scheme")
        .choices(["ed25519", "secp256k1"])
        .default("ed25519"),
    )
    .option("--listen <addr>", "host:port for the webhook receiver", "0.0.0.0:7000")
    .option("--auto-approve", "demo/staging only: approve every request", false)
    .option("--auto-reject", "auto-reject every request (wiring test)", false)
    .option("--interactive", "prompt the operator on stdin per request", false)
    .option("--audit-path <path>", `audit log (default ${defaultAuditPath()})`);

  program.parse();
  const opts = program.opts<{
    server: string;
    approverId: string;
    secretFile: string;
    webhookSecret: string;
    scheme: Scheme;
    listen: string;
    autoApprove: boolean;
    autoReject: boolean;
    interactive: boolean;
    auditPath?: string;
  }>();

  const exclusives = [opts.autoApprove, opts.autoReject, opts.interactive].filter(Boolean).length;
  if (exclusives > 1) {
    log.error("--auto-approve, --auto-reject, --interactive are mutually exclusive");
    process.exit(2);
  }
  let policy: DecisionPolicy;
  if (opts.autoApprove) {
    policy = "auto_approve";
  } else if (opts.autoReject) {
    policy = "auto_reject";
  } else if (opts.interactive) {
    policy = "interactive";
  } else {
    log.warn(
      "no decision policy specified; running in refuse mode (every webhook will be dropped). " +
        "Pass --interactive, --auto-approve, or --auto-reject.",
    );
    policy = "refuse";
  }

  const cfg: ProcessorConfig = {
    server: opts.server,
    approverId: opts.approverId,
    policy,
    auditPath: opts.auditPath ?? defaultAuditPath(),
    scheme: opts.scheme,
    secret: loadSecret(opts.secretFile),
  };
  const processor = new Processor(cfg);
  const app = buildApp({
    hmacSecret: loadWebhookSecret(opts.webhookSecret),
    handler: async (req) => {
      const outcome = await processor.process(req);
      log.info(
        {
          request_id: req.request_id,
          decision: outcome.decision,
          server_status: outcome.serverStatus,
        },
        "processed webhook",
      );
    },
  });

  const [host, portStr] = opts.listen.split(":");
  if (!host || !portStr) {
    throw new Error(`invalid --listen ${opts.listen}; want host:port`);
  }
  const port = Number(portStr);
  app.listen(port, host, () => {
    log.info({ host, port, approver_id: opts.approverId, scheme: opts.scheme }, "qfc-approver ready");
  });
}

main().catch((err: unknown) => {
  log.error({ err: (err as Error).message }, "fatal");
  process.exit(1);
});
