import { describe, expect, it, vi } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

describe("HMAC auth - HTTP middleware", () => {
  it("supports verifyHttpRequest as middleware and keeps middleware aliases", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_middleware", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const makeRes = () => {
      return {
        statusCode: 200,
        body: undefined as unknown,
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        json(payload: unknown) {
          this.body = payload;
          return this;
        },
      };
    };

    const body = JSON.stringify({ ok: true });
    const ts1 = Date.now();
    const headers1 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts1,
        nonce: "nonce_mw_1",
      }),
    );

    const req1: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers1,
      rawBody: body,
    };
    const res1 = makeRes();
    const next1 = vi.fn();

    await auth.verifyHttpRequest(req1, res1 as any, next1);
    expect(next1).toHaveBeenCalledTimes(1);
    expect(req1.hmacAuth?.clientId).toBe("app_a");

    const ts2 = ts1 + 1;
    const headers2 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts2,
        nonce: "nonce_mw_2",
      }),
    );

    const req2: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers2,
      rawBody: body,
    };
    const res2 = makeRes();
    const next2 = vi.fn();

    await auth.createHttpMiddleware()(req2, res2 as any, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    expect(req2.hmacAuth?.clientId).toBe("app_a");

    const ts3 = ts2 + 1;
    const headers3 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts3,
        nonce: "nonce_mw_3",
      }),
    );

    const req3: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers3,
      rawBody: body,
    };
    const res3 = makeRes();
    const next3 = vi.fn();

    await auth.createExpressHttpMiddleware()(req3, res3 as any, next3);
    expect(next3).toHaveBeenCalledTimes(1);
    expect(req3.hmacAuth?.clientId).toBe("app_a");
  });
});
