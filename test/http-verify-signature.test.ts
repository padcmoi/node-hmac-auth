import { describe, expect, it, vi } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth, verifyHttpSignature } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * Signature verification core: happy path, nonce replay, missing clientId,
 * unknown clientId, wrong secret, and the `onBadSignature` callback hook.
 */
describe("HMAC auth - HTTP verify - signature core", () => {
  it("verifies a valid signed request with redis-backed secrets", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_a",
      maxSkewMs: 5000,
    });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const body = JSON.stringify({ hello: "world" });

    const headers = buildHttpSignedHeaders({
      method: "POST",
      url: "/v1/messages?x=1",
      body,
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_1",
    });

    const verified = await auth.verifyHttpSignature({
      method: "POST",
      path: "/v1/messages?x=1",
      headers: headersToRecord(headers),
      rawBody: body,
      now: timestamp,
    });

    expect(verified.clientId).toBe("app_a");
    expect(verified.nonce).toBe("nonce_1");
    expect(redis.hasHashKey("tenant_a:clients")).toBe(true);
  });

  it("rejects replayed nonce", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_a", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const body = "";
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body,
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "same_nonce",
    });
    const headerRecord = headersToRecord(headers);

    await auth.verifyHttpSignature({
      method: "GET",
      path: "/health",
      headers: headerRecord,
      rawBody: body,
      now: timestamp,
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headerRecord,
        rawBody: body,
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "REPLAYED_NONCE" });
  });

  it("returns 401 when clientId is missing", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_b", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_1",
    });
    headers.delete("x-client-id");

    await expect(
      verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headers),
        rawBody: "",
        redis,
        namespace: "tenant_b",
        maxSkewMs: 5000,
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "MISSING_CLIENT_ID", status: 401 });
  });

  it("returns 401 for unknown client or wrong secret", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_c", maxSkewMs: 5000 });
    await auth.clients.setSecret("known_client", "server_secret");

    const timestamp = Date.now();

    const unknownClientHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "unknown_client",
      secret: "server_secret",
      timestamp,
      nonce: "nonce_unknown",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(unknownClientHeaders),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "UNKNOWN_CLIENT", status: 401 });

    const wrongSecretHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "known_client",
      secret: "wrong_secret",
      timestamp,
      nonce: "nonce_wrong_secret",
    });
    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(wrongSecretHeaders),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
  });

  it("triggers onBadSignature callback before BAD_SIGNATURE", async () => {
    const redis = new FakeRedis();
    const onBadSignature = vi.fn();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_callback",
      maxSkewMs: 5000,
      onBadSignature,
    });
    await auth.clients.setSecret("known_client", "server_secret");

    const timestamp = Date.now();
    const wrongSecretHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "known_client",
      secret: "wrong_secret",
      timestamp,
      nonce: "nonce_callback",
    });
    const wrongSecretHeaderRecord = headersToRecord(wrongSecretHeaders);

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: wrongSecretHeaderRecord,
        rawBody: "",
        now: timestamp,
        metadata: { source: "unit-test" },
      })
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });

    expect(onBadSignature).toHaveBeenCalledTimes(1);

    const event = onBadSignature.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(event.clientId).toBe("known_client");
    expect(event.method).toBe("GET");
    expect(event.path).toBe("/health");
    expect(event.timestamp).toBe(timestamp);
    expect(event.nonce).toBe("nonce_callback");
    expect(event.receivedSignature).toBe(wrongSecretHeaderRecord["x-signature"]);
    expect(typeof event.expectedSignature).toBe("string");
    expect((event.expectedSignature as string).length).toBe(64);
    expect(event.metadata).toEqual({ source: "unit-test" });
  });

  it("keeps BAD_SIGNATURE when onBadSignature callback throws", async () => {
    const redis = new FakeRedis();
    const onBadSignature = vi.fn(async () => {
      throw new Error("callback failure");
    });

    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_callback_error",
      maxSkewMs: 5000,
      onBadSignature,
    });
    await auth.clients.setSecret("known_client", "server_secret");

    const timestamp = Date.now();
    const wrongSecretHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "known_client",
      secret: "wrong_secret",
      timestamp,
      nonce: "nonce_callback_error",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(wrongSecretHeaders),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });

    expect(onBadSignature).toHaveBeenCalledTimes(1);
  });
});
