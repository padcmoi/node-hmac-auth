import { describe, expect, it, vi } from "vitest";
import { initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

describe("HMAC auth - propagation", () => {
  it("propagates client operations to multiple APIs and returns acceptance per target", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_propagate",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });

    const fetchMock = vi.fn(async (url: RequestInfo | URL, _init?: RequestInit) => {
      const asString = String(url);
      if (asString.includes("api-1.example.com")) {
        return new Response(JSON.stringify({ ok: true }), {
          status: 201,
          headers: { "content-type": "application/json" },
        });
      }

      return new Response(JSON.stringify({ error: "FORBIDDEN" }), {
        status: 403,
        headers: { "content-type": "application/json" },
      });
    });

    const results = await auth.propagateClientToApis({
      operation: "create",
      targets: ["https://api-1.example.com", "https://api-2.example.com"],
      clientId: "client_sync",
      secret: "secret_sync",
      allowedIps: ["195.7.8.9", "195.7.8.0/24"],
      apiFetch: fetchMock as any,
    });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(results).toHaveLength(2);
    expect(results[0]?.accepted).toBe(true);
    expect(results[0]?.status).toBe(201);
    expect(results[1]?.accepted).toBe(false);
    expect(results[1]?.status).toBe(403);
    expect(results[0]?.url).toContain("/api/internal/hmac");
    expect(results[1]?.url).toContain("/api/internal/hmac");

    const firstCallOptions = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const firstCallBody = JSON.parse(String(firstCallOptions.body));
    expect(firstCallBody.allowedIps).toEqual(["195.7.8.9", "195.7.8.0/24"]);
  });

  it("requires allowedIps for create/update propagation", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_propagate_allowed_ips_required",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });

    await expect(
      auth.propagateClientToApis({
        operation: "create",
        targets: ["https://api-1.example.com"],
        clientId: "client_sync",
        secret: "secret_sync",
      })
    ).rejects.toThrow("allowedIps array is required for create/update propagation");

    await expect(
      auth.propagateClientToApis({
        operation: "update",
        targets: ["https://api-1.example.com"],
        clientId: "client_sync",
        secret: "secret_sync",
      })
    ).rejects.toThrow("allowedIps array is required for create/update propagation");
  });

  it("rejects propagation when internal management route is disabled", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_no_internal_route",
      maxSkewMs: 5000,
    });

    await expect(
      auth.propagateClientToApis({
        operation: "create",
        targets: ["https://api-1.example.com"],
        clientId: "client_sync",
        secret: "secret_sync",
      })
    ).rejects.toMatchObject({ code: "INTERNAL_ROUTE_DISABLED" });
  });

  // ── 1.0.0 ────────────────────────────────────────────────────────────────
  it("1.0.0: never sends plain `secret` on the wire; ships locally-hashed secretHash", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_hash_on_wire",
      internalManagementRoute: "/api/internal/hmac",
      secretToken: "tenant_specific_pepper",
      maxSkewMs: 5000,
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
      clientId: "client_sync",
      secret: "plain_secret_should_never_ship",
      allowedIps: ["0.0.0.0/0"],
      apiFetch: fetchMock as any,
    });

    const firstCallOptions = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const firstCallBody = JSON.parse(String(firstCallOptions.body));

    expect(firstCallBody.secret).toBeUndefined();
    expect(typeof firstCallBody.secretHash).toBe("string");
    expect(firstCallBody.secretHash).toMatch(/^[0-9a-f]{64}$/);
    // Hash derived from local secretToken => caller secret is never exposed verbatim
    expect(firstCallBody.secretHash).not.toContain("plain_secret_should_never_ship");
  });

  it("1.0.0: falls back to local Redis secretHash when both `secret` and `secretHash` are omitted", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_redis_fallback",
      internalManagementRoute: "/api/internal/hmac",
      secretToken: "tenant_specific_pepper",
      maxSkewMs: 5000,
    });

    // Seed the local Redis: clientId exists locally (e.g. via internalCredentials)
    const seeded = await auth.clients.create({
      clientId: "already_local",
      plainSecret: "the_one_true_secret",
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
      clientId: "already_local",
      // secret AND secretHash both omitted => Redis fallback
      allowedIps: ["0.0.0.0/0"],
      apiFetch: fetchMock as any,
    });

    const firstCallOptions = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const firstCallBody = JSON.parse(String(firstCallOptions.body));

    expect(firstCallBody.secret).toBeUndefined();
    expect(firstCallBody.secretHash).toBe(seeded.secretHash);
  });

  it("1.0.0: throws when `secret`, `secretHash` AND the local Redis record are all absent", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_missing_everything",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });

    await expect(
      auth.propagateClientToApis({
        operation: "create",
        targets: ["https://api-1.example.com"],
        clientId: "never_seen_before",
        // secret + secretHash omitted, and no local Redis record exists
        allowedIps: ["0.0.0.0/0"],
      })
    ).rejects.toThrow("secret or secretHash is required");
  });

  it("1.0.0: explicit caller `secretHash` wins over local Redis lookup and over plain `secret`", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_priority",
      internalManagementRoute: "/api/internal/hmac",
      secretToken: "tenant_specific_pepper",
      maxSkewMs: 5000,
    });

    // Local record exists with hash A
    await auth.clients.create({
      clientId: "override_target",
      plainSecret: "local_secret",
      expiresAt: null,
      allowedIps: [],
    });

    const callerExplicitHash = "deadbeef".repeat(8); // 64 hex chars
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
      clientId: "override_target",
      secret: "this_should_be_ignored",
      secretHash: callerExplicitHash,
      allowedIps: ["0.0.0.0/0"],
      apiFetch: fetchMock as any,
    });

    const firstCallOptions = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const firstCallBody = JSON.parse(String(firstCallOptions.body));

    expect(firstCallBody.secret).toBeUndefined();
    expect(firstCallBody.secretHash).toBe(callerExplicitHash);
  });
});
