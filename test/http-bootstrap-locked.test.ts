import { describe, expect, it } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * v1.4.0 (security): the bootstrap-window lock is always active. When the
 * caller omits `requireBootstrapClientId` the lib resolves it to the
 * federation-default `DEFAULT_PROPAGATION_KEY_CLIENT_ID`, so there is no
 * way to ship an unlocked store. The pre-1.4.0 "no lock" branch is gone;
 * the suite below covers the lock-then-unlock lifecycle that replaces it.
 */
describe("HMAC auth - v1.4.0 - bootstrap-window lock (federation default)", () => {
  const route = "/api/internal/hmac";
  const propagationClientId = "self_propagation_signer";

  function buildAuth() {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_bootstrap",
      internalManagementRoute: route,
      maxSkewMs: 5000,
    });
    return auth;
  }

  it("reports bootstrapLocked: true on GET while locked, then false once unlocked", async () => {
    const auth = buildAuth();

    const lockedHealth = await auth.handleInternalManagementRequest({
      method: "GET",
      path: route,
      headers: {},
      rawBody: "",
      now: Date.now(),
    });
    expect(lockedHealth.status).toBe(200);
    expect(lockedHealth.body).toMatchObject({
      ok: true,
      clientsCount: 0,
      bootstrapLocked: true,
    });

    const bootstrapPost = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({ clientId: propagationClientId, secret: "prop_secret" }),
      now: Date.now(),
    });
    expect(bootstrapPost.status).toBe(201);

    const timestamp = Date.now();
    const signedGetHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: route,
      body: "",
      clientId: propagationClientId,
      secret: "prop_secret",
      timestamp,
      nonce: "nonce_unlocked_health",
    });

    const unlockedHealth = await auth.handleInternalManagementRequest({
      method: "GET",
      path: route,
      headers: headersToRecord(signedGetHeaders),
      rawBody: "",
      now: timestamp,
    });
    expect(unlockedHealth.body).toMatchObject({
      bootstrapLocked: false,
      clientsCount: 1,
    });
  });

  it("refuses POST for any clientId other than the bootstrap one while locked", async () => {
    const auth = buildAuth();
    const intruderPost = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({ clientId: "intruder", secret: "evil" }),
      now: Date.now(),
    });
    expect(intruderPost.status).toBe(403);
    expect(intruderPost.body).toMatchObject({ error: "BOOTSTRAP_LOCKED" });
  });

  it("refuses PUT / PATCH / DELETE while locked", async () => {
    const auth = buildAuth();
    for (const method of ["PUT", "PATCH", "DELETE"]) {
      const result = await auth.handleInternalManagementRequest({
        method,
        path: route,
        headers: {},
        rawBody: JSON.stringify({ clientId: propagationClientId }),
        now: Date.now(),
      });
      expect(result.status, `${method} should be locked`).toBe(403);
      expect(result.body).toMatchObject({ error: "BOOTSTRAP_LOCKED" });
    }
  });

  it("refuses signed business requests with BOOTSTRAP_LOCKED while locked", async () => {
    const auth = buildAuth();
    await auth.clients.setSecret("data_plane_alpha", "alpha_secret");

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/business/widgets",
      body: "",
      clientId: "data_plane_alpha",
      secret: "alpha_secret",
      timestamp,
      nonce: "nonce_bootstrap_locked",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/business/widgets",
        headers: headersToRecord(headers),
        rawBody: "",
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "BOOTSTRAP_LOCKED", status: 403 });
  });

  it("releases the lock once the bootstrap credential is stored", async () => {
    const auth = buildAuth();
    await auth.clients.setSecret(propagationClientId, "prop_secret", undefined, undefined, {
      purpose: "propagation-only",
    });
    await auth.clients.setSecret("data_plane_alpha", "alpha_secret");

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/business/widgets",
      body: "",
      clientId: "data_plane_alpha",
      secret: "alpha_secret",
      timestamp,
      nonce: "nonce_after_bootstrap",
    });

    const verified = await auth.verifyHttpSignature({
      method: "GET",
      path: "/business/widgets",
      headers: headersToRecord(headers),
      rawBody: "",
      now: timestamp,
    });
    expect(verified.clientId).toBe("data_plane_alpha");
  });
});
