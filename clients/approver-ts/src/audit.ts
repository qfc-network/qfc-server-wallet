/**
 * Local NDJSON audit log. One line per processed webhook.
 */

import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import { homedir } from "node:os";

export interface AuditRecord {
  timestamp: string;
  event: "received" | "signed" | "posted" | "rejected" | "refused" | "error";
  request_id: string;
  approver_id: string;
  message_hash_hex: string;
  decision: "approve" | "reject" | "refused";
  signature_hex?: string;
  server_status?: number;
  note?: string;
}

/** Default audit path — `~/.qfc-approver/audit.log`. */
export function defaultAuditPath(): string {
  return `${homedir()}/.qfc-approver/audit.log`;
}

/** Append one record, creating the parent dir if needed. */
export async function appendAudit(path: string, record: AuditRecord): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${JSON.stringify(record)}\n`, "utf8");
}
