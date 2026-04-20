import { describe, expect, it, vi } from "vitest";
import { buildHttpSignedHeaders, hashClientSecret, initializeHmacHttpAuth, verifyHttpSignature } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

describe("HMAC auth - HTTP verify", () => {
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

  it("returns 401 when client secret is expired", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_expired", maxSkewMs: 5000 });
    await auth.clients.setSecret("exp_client", "secret_a", Date.now() - 1000);

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "exp_client",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_expired",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headers),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "CLIENT_EXPIRED", status: 401 });
  });

  it("supports client IP/CIDR allowlist on verify", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_ip_allowlist", maxSkewMs: 5000 });

    await auth.clients.create({
      clientId: "ip_locked_client",
      plainSecret: "secret_ip_lock",
      allowedIps: ["195.7.8.9", "195.7.8.0/24"],
    });

    const makeHeaders = (nonce: string, timestamp: number) =>
      headersToRecord(
        buildHttpSignedHeaders({
          method: "GET",
          url: "/secure/get",
          body: "",
          clientId: "ip_locked_client",
          secret: "secret_ip_lock",
          timestamp,
          nonce,
        })
      );

    const timestamp = Date.now();
    const headersAllowed = makeHeaders("nonce_ip_allowed", timestamp);

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/secure/get",
        headers: headersAllowed,
        rawBody: "",
        now: timestamp,
        metadata: { ip: "195.7.8.9" },
      })
    ).resolves.toMatchObject({ clientId: "ip_locked_client" });

    const headersAllowedCidr = makeHeaders("nonce_ip_allowed_cidr", timestamp + 1);
    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/secure/get",
        headers: headersAllowedCidr,
        rawBody: "",
        now: timestamp + 1,
        metadata: { ip: "195.7.8.44" },
      })
    ).resolves.toMatchObject({ clientId: "ip_locked_client" });

    const headersDenied = makeHeaders("nonce_ip_denied", timestamp + 2);
    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/secure/get",
        headers: headersDenied,
        rawBody: "",
        now: timestamp + 2,
        metadata: { ip: "8.8.8.8" },
      })
    ).rejects.toMatchObject({ code: "CLIENT_IP_NOT_ALLOWED", status: 403 });
  });

  it("rejects allowlisted clients when request IP is missing", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_ip_required", maxSkewMs: 5000 });

    await auth.clients.create({
      clientId: "ip_required_client",
      plainSecret: "secret_ip_required",
      allowedIps: ["195.7.8.9"],
    });

    const timestamp = Date.now();
    const headers = headersToRecord(
      buildHttpSignedHeaders({
        method: "GET",
        url: "/secure/get",
        body: "",
        clientId: "ip_required_client",
        secret: "secret_ip_required",
        timestamp,
        nonce: "nonce_missing_ip",
      })
    );

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/secure/get",
        headers,
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "MISSING_CLIENT_IP", status: 403 });
  });

  it("supports secretToken for deterministic tokenized secret hashes", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_tokenized",
      maxSkewMs: 5000,
      secretToken: "abc",
    });

    const first = await auth.clients.create({
      clientId: "client_a",
      plainSecret: "helloworld",
    });
    const second = await auth.clients.create({
      clientId: "client_b",
      plainSecret: "helloworld",
    });

    expect(first.secretHash).toBe(second.secretHash);
    expect(first.secretHash).toBe(hashClientSecret("helloworld", "abc"));
    expect(first.secretHash).not.toBe(hashClientSecret("helloworld"));
  });

  it("verifies tokenized signatures only when using the same secretToken", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_token_verify",
      maxSkewMs: 5000,
      secretToken: "abc",
    });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const headersWithToken = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      hashToken: "abc",
      timestamp,
      nonce: "nonce_tokenized",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headersWithToken),
        rawBody: "",
        now: timestamp,
      })
    ).resolves.toMatchObject({ clientId: "app_a" });

    const headersWithoutToken = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_no_token",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headersWithoutToken),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
  });
});
