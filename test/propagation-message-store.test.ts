import { describe, expect, it, vi } from "vitest";
import { initializeHmacHttpAuth, initializeHmacMessageAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

/**
 * v1.1.0 message-store propagation contract:
 *  - the source ships `payload.kind = "message"` only when `targetStore` is
 *    explicitly set to "message"; HTTP propagation stays byte-identical to v1.0.0
 *  - the source throws if `targetStore = "message"` is requested but the
 *    `messageAuth` bridge was not passed to `initializeHmacHttpAuth`
 *  - the target rejects `kind: "message"` payloads when its own `messageAuth`
 *    bridge is not configured (403 FORBIDDEN, no side-effect)
 *  - when both sides have the bridge, the target writes the record to the
 *    message store, NOT the HTTP store
 */
describe("HMAC auth - propagation - message store (v1.1.0)", () => {
  it("targetStore='message' ships payload.kind='message' and falls back to messageAuth Redis", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_msg",
      secretToken: "tenant_specific_pepper",
    });
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_http_with_msg",
      internalManagementRoute: "/api/internal/hmac",
      secretToken: "tenant_specific_pepper",
      maxSkewMs: 5000,
      messageAuth,
    });

    const seeded = await messageAuth.clients.create({
      clientId: "msg_only",
      plainSecret: "msg_secret",
      expiresAt: null,
      allowedIps: [],
    });

    const fetchMock = vi.fn(
      async (_url: RequestInfo | URL, _init?: RequestInit) =>
        new Response(JSON.stringify({ ok: true }), {
          status: 201,
          headers: { "content-type": "application/json" },
        })
    );

    await auth.propagateClientToApis({
      operation: "create",
      targets: ["https://api-1.example.com"],
      clientId: "msg_only",
      allowedIps: ["0.0.0.0/0"],
      apiFetch: fetchMock as any,
      targetStore: "message",
    });

    const firstCallOptions = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const firstCallBody = JSON.parse(String(firstCallOptions.body));

    expect(firstCallBody.kind).toBe("message");
    expect(firstCallBody.secret).toBeUndefined();
    expect(firstCallBody.secretHash).toBe(seeded.secretHash);
  });

  it("source side throws when targetStore='message' but messageAuth not configured", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_no_msg_bridge",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
      // messageAuth intentionally omitted
    });

    await expect(
      auth.propagateClientToApis({
        operation: "create",
        targets: ["https://api-1.example.com"],
        clientId: "msg_only",
        secret: "ignored",
        allowedIps: ["0.0.0.0/0"],
        targetStore: "message",
      })
    ).rejects.toThrow(/targetStore='message' requires messageAuth/);
  });

  it("handleInternalManagementRequest rejects kind='message' when the target has no messageAuth", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_target_no_msg",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
      // messageAuth intentionally omitted on the target
    });

    const rawBody = Buffer.from(
      JSON.stringify({
        clientId: "ghost",
        secretHash: "a".repeat(64),
        allowedIps: [],
        kind: "message",
      })
    );

    const result = await auth.handleInternalManagementRequest({
      method: "POST",
      path: "/api/internal/hmac",
      headers: {},
      rawBody,
      now: Date.now(),
    });

    expect(result.handled).toBe(true);
    expect(result.status).toBe(403);
    expect(result.body).toMatchObject({ error: "FORBIDDEN", message: expect.stringMatching(/Message store not configured/) });
  });

  it("handleInternalManagementRequest writes a kind='message' payload to messageAuth store", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_target_msg",
      secretToken: "remote_pepper",
    });
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_target_http",
      internalManagementRoute: "/api/internal/hmac",
      secretToken: "remote_pepper",
      messageAuth,
    });

    const sentHash = "b".repeat(64);
    const rawBody = Buffer.from(
      JSON.stringify({
        clientId: "msg_arriving",
        secretHash: sentHash,
        allowedIps: [],
        kind: "message",
      })
    );

    // bootstrap path (no clients yet) so no HMAC signature required
    const result = await auth.handleInternalManagementRequest({
      method: "POST",
      path: "/api/internal/hmac",
      headers: {},
      rawBody,
      now: Date.now(),
    });

    expect(result.status).toBe(201);
    expect(result.body).toMatchObject({ ok: true, operation: "create", clientId: "msg_arriving", kind: "message" });

    // Verify it ended up in the message store with the same hash, NOT the HTTP store
    const stored = await messageAuth.clients.get("msg_arriving");
    expect(stored?.secretHash).toBe(sentHash);
    const httpStored = await auth.clients.get("msg_arriving");
    expect(httpStored).toBeNull();
  });
});
