import { describe, expect, it, vi } from "vitest";
import { initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

describe("HMAC auth - propagation - core (multi-API, validation, route gating)", () => {
  it("propagates client operations to multiple APIs and returns acceptance per target", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_propagate",
      internalManagementRoute: "/api/internal/hmac",
      maxSkewMs: 5000,
    });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");

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
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");

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
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_no_internal_route", maxSkewMs: 5000 });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");

    await expect(
      auth.propagateClientToApis({
        operation: "create",
        targets: ["https://api-1.example.com"],
        clientId: "client_sync",
        secret: "secret_sync",
      })
    ).rejects.toMatchObject({ code: "INTERNAL_ROUTE_DISABLED" });
  });
});
