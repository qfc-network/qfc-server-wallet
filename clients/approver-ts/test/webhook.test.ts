/**
 * HMAC verification + end-to-end flow tests.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { createHmac } from "node:crypto";
import { createServer, type AddressInfo, type Server } from "node:net";
import { request as undiciRequest } from "undici";

import { verifyHmac, buildApp, WEBHOOK_SIGNATURE_HEADER } from "../src/webhook.js";

describe("verifyHmac", () => {
  const secret = Buffer.from("sssh", "utf8");
  const body = Buffer.from(JSON.stringify({ any: "body" }), "utf8");

  it("accepts a correct signature", () => {
    const sig = createHmac("sha256", secret).update(body).digest("hex");
    expect(verifyHmac(body, sig, secret)).toBe(true);
  });

  it("rejects a wrong signature", () => {
    const sig = createHmac("sha256", Buffer.from("DIFFERENT")).update(body).digest("hex");
    const result = verifyHmac(body, sig, secret);
    expect(result).not.toBe(true);
    if (result !== true) expect(result.error).toBe("mismatch");
  });

  it("rejects a missing header", () => {
    const result = verifyHmac(body, undefined, secret);
    if (result === true) throw new Error("expected error");
    expect(result.error).toBe("missing");
  });

  it("rejects a non-hex header", () => {
    const result = verifyHmac(body, "zzznotvalidhex", secret);
    if (result === true) throw new Error("expected error");
    expect(result.error).toBe("malformed");
  });

  it("rejects a short header", () => {
    const result = verifyHmac(body, "aa".repeat(30), secret);
    if (result === true) throw new Error("expected error");
    expect(result.error).toBe("malformed");
  });
});

describe("buildApp", () => {
  let server: Server | undefined;
  afterEach(() => {
    server?.close();
  });

  async function listen(app: ReturnType<typeof buildApp>): Promise<number> {
    return new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => {
        server = s as unknown as Server;
        const addr = (s.address() as AddressInfo);
        resolve(addr.port);
      });
    });
  }

  it("returns 200 for a valid webhook and 401 for a missing signature", async () => {
    const secret = Buffer.from("k");
    const handler = vi.fn(async () => {});
    const app = buildApp({ hmacSecret: secret, handler });
    const port = await listen(app);

    const body = Buffer.from(
      JSON.stringify({
        request_id: "01J7Z9C5K3MX5W1H7E1D9V4Q2S",
        message_hash: "0".repeat(64),
        approver_set: [],
        threshold: 1,
      }),
      "utf8",
    );
    const sig = createHmac("sha256", secret).update(body).digest("hex");

    const ok = await undiciRequest(`http://127.0.0.1:${port}/`, {
      method: "POST",
      headers: { [WEBHOOK_SIGNATURE_HEADER]: sig, "content-type": "application/json" },
      body,
    });
    expect(ok.statusCode).toBe(200);
    expect(handler).toHaveBeenCalledOnce();

    const bad = await undiciRequest(`http://127.0.0.1:${port}/`, {
      method: "POST",
      body,
    });
    expect(bad.statusCode).toBe(401);
  });
});

// Bridge express's `listen` return to a closable Server. The cast in
// `listen` is safe — express's listen returns a node http.Server.
function _typeShim(): Server {
  return createServer();
}
_typeShim;
