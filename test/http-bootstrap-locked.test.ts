import { describe, expect, it } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * v1.3.0 Feature 2: requireBootstrapClientId lock.
 *
 * While the named credential is missing from the local store:
 *   - verifyHttpSignature rejects every signed business request with
 *     BOOTSTRAP_LOCKED (HTTP 403).
 *   - handleInternalManagementRequest accepts only POST whose clientId equals
 *     the named bootstrap clientId; every other write returns BOOTSTRAP_LOCKED.
 *   - GET stays open and reports bootstrapLocked: true.
 * Once the named credential is stored, the lock releases.
 */
describe("HMAC auth - v1.3.0 - requireBootstrapClientId", () => {
  const route = "/api/internal/hmac";
  const propagationClientId = "self_propagation_signer";

  function buildAuth() {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_bootstrap",
      internalManagementRoute: route,
      maxSkewMs: 5000,
      requireBootstrapClientId: propagationClientId,
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

    // After the bootstrap write, authRequired flips to true. GET probes must
    // be signed by the bootstrap clientId from now on. Build a signed GET
    // and verify the body now reports bootstrapLocked: false.
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
    // Even with the data-plane credential present, the lock is on the
    // propagation key. Until propagationClientId is stored, ANY verify call
    // throws BOOTSTRAP_LOCKED.

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

  it("does not affect APIs that did not opt-in (1.2.x behavior preserved)", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_no_bootstrap",
      internalManagementRoute: route,
      maxSkewMs: 5000,
    });

    const lockedHealth = await auth.handleInternalManagementRequest({
      method: "GET",
      path: route,
      headers: {},
      rawBody: "",
      now: Date.now(),
    });
    expect(lockedHealth.body).toMatchObject({ bootstrapLocked: false });

    const anyBootstrap = await auth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({ clientId: "any_first_client", secret: "x" }),
      now: Date.now(),
    });
    expect(anyBootstrap.status).toBe(201);
  });
});
