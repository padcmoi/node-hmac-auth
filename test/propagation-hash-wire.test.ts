import { describe, expect, it, vi } from "vitest";
import { initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

/**
 * v1.0.0 hash-on-the-wire propagation contract:
 *  - the payload always carries `secretHash`, never the plain `secret`
 *  - when neither `secret` nor `secretHash` is supplied, fall back to the
 *    locally stored secretHash for that clientId
 *  - the priority is: explicit caller `secretHash` > local Redis lookup
 *    > hash derived from the caller-provided plain `secret`
 */
describe("HMAC auth - propagation - hash on the wire (v1.0.0)", () => {
  it("never sends plain `secret` on the wire; ships locally-hashed secretHash", async () => {
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

  it("falls back to local Redis secretHash when both `secret` and `secretHash` are omitted", async () => {
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

  it("throws when `secret`, `secretHash` AND the local Redis record are all absent", async () => {
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

  it("explicit caller `secretHash` wins over local Redis lookup and over plain `secret`", async () => {
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
