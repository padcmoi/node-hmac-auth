import { describe, expect, it, vi } from "vitest";
import { buildHttpSignedHeaders, hashClientSecret, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

describe("HMAC auth - internal management", () => {
  it("supports internal management route bootstrap and authenticated updates", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_internal",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });

    const route = "/api/internal/hmac";

    const bootstrapCreate = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({
        clientId: "bootstrap_client",
        secret: "bootstrap_secret",
      }),
      now: Date.now(),
    });

    expect(bootstrapCreate.handled).toBe(true);
    expect(bootstrapCreate.status).toBe(201);
    expect((await auth.clients.get("bootstrap_client"))?.clientId).toBe("bootstrap_client");

    const unauthorizedCreate = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({
        clientId: "blocked_client",
        secret: "blocked_secret",
      }),
      now: Date.now(),
    });

    expect(unauthorizedCreate.status).toBe(403);
    expect((await auth.clients.get("blocked_client")) == null).toBe(true);

    const authorizedBody = JSON.stringify({
      clientId: "sync_client",
      secret: "sync_secret",
      allowedIps: ["10.0.0.1", "10.0.0.0/24"],
    });

    const createHeaders = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: route,
        body: authorizedBody,
        clientId: "bootstrap_client",
        secret: "bootstrap_secret",
        timestamp: Date.now(),
        nonce: "nonce_internal_create_1",
      }),
    );

    const authorizedCreate = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: createHeaders,
      rawBody: authorizedBody,
      now: Date.now(),
    });

    expect(authorizedCreate.status).toBe(201);
    const createdSyncClient = await auth.clients.get("sync_client");
    expect(createdSyncClient?.clientId).toBe("sync_client");
    expect(createdSyncClient?.allowedIps).toEqual(["10.0.0.1", "10.0.0.0/24"]);

    const updateBody = JSON.stringify({
      clientId: "sync_client",
      secret: "sync_secret_rotated",
      allowedIps: ["172.16.0.0/16"],
    });

    const updateHeaders = headersToRecord(
      buildHttpSignedHeaders({
        method: "PUT",
        url: route,
        body: updateBody,
        clientId: "bootstrap_client",
        secret: "bootstrap_secret",
        timestamp: Date.now(),
        nonce: "nonce_internal_update_1",
      }),
    );

    const updateResult = await auth.handleInternalManagementRequest({
      method: "PUT",
      path: route,
      headers: updateHeaders,
      rawBody: updateBody,
      now: Date.now(),
    });

    expect(updateResult.status).toBe(201);

    const updatedClient = await auth.clients.get("sync_client");
    expect(updatedClient?.secretHash).toBe(hashClientSecret("sync_secret_rotated"));
    expect(updatedClient?.allowedIps).toEqual(["172.16.0.0/16"]);
  });

  it("creates internal management middleware and skips unknown routes", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_internal_mw",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });

    const middleware = auth.createInternalManagementMiddleware();

    const nextUnknown = vi.fn();
    const reqUnknown: any = {
      method: "GET",
      originalUrl: "/other",
      url: "/other",
      headers: {},
      rawBody: "",
    };
    const resUnknown: any = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn().mockReturnThis(),
    };

    await middleware(reqUnknown, resUnknown, nextUnknown);
    expect(nextUnknown).toHaveBeenCalledTimes(1);

    const nextInternal = vi.fn();
    const reqInternal: any = {
      method: "GET",
      originalUrl: "/api/internal/hmac",
      url: "/api/internal/hmac",
      headers: {},
      rawBody: "",
    };

    const resInternal: any = {
      statusCode: 0,
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

    await middleware(reqInternal, resInternal, nextInternal);
    expect(nextInternal).toHaveBeenCalledTimes(0);
    expect(resInternal.statusCode).toBe(200);
    expect((resInternal.body as Record<string, unknown>)?.ok).toBe(true);
  });
});
