/**
 * Interactive stdin prompt. Returns the operator's chosen action for
 * one incoming webhook.
 */

import { createInterface } from "node:readline/promises";

export type PromptDecision = "approve" | "reject" | "refuse";

export async function promptForDecision(summary: string): Promise<PromptDecision> {
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  try {
    process.stderr.write("\n=== QFC approval request ===\n");
    process.stderr.write(`${summary}\n`);
    const answer = (
      await rl.question(
        "Approve? [y]es / [n]o (reject) / anything else = refuse: ",
      )
    )
      .trim()
      .toLowerCase();
    if (answer === "y" || answer === "yes" || answer === "approve") {
      return "approve";
    }
    if (answer === "n" || answer === "no" || answer === "reject") {
      return "reject";
    }
    return "refuse";
  } finally {
    rl.close();
  }
}
