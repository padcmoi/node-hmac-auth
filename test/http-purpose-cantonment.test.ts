import { describe, expect, it } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * v1.3.0 Feature 1: purpose='propagation-only' cantonment.
 *
 * A credential whose stored purpose is "propagation-only" can sign requests
 * only on the configured internalManagementRoute. Any other path is rejected
 * with HTTP 403 PROPAGATION_ONLY_FORBIDDEN even when the signature is valid.
 */
describe("HMAC auth - v1.3.0 - purpose cantonment", () => {
  const route = "/api/internal/hmac";

  async function buildAuthWithPropagationKey() {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_purpose", internalManagementRoute: route, maxSkewMs: 5000 });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");
    await auth.clients.setSecret("self_propagation_signer", "prop_secret", undefined, undefined, {
      purpose: "propagation-only",
    });
    return auth;
  }

  it("accepts a propagation-only credential on the internalManagementRoute", async () => {
    const auth = await buildAuthWithPropagationKey();
    const timestamp = Date.now();
    const body = "";
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: route,
      body,
      clientId: "self_propagation_signer",
      secret: "prop_secret",
      timestamp,
      nonce: "nonce_purpose_ok",
    });

    const verified = await auth.verifyHttpSignature({
      method: "GET",
      path: route,
      headers: headersToRecord(headers),
      rawBody: body,
      now: timestamp,
    });

    expect(verified.clientId).toBe("self_propagation_signer");
  });

  it("rejects a propagation-only credential on any other route with PROPAGATION_ONLY_FORBIDDEN", async () => {
    const auth = await buildAuthWithPropagationKey();
    const timestamp = Date.now();
    const body = JSON.stringify({ should: "fail" });
    const headers = buildHttpSignedHeaders({
      method: "POST",
      url: "/business/widgets",
      body,
      clientId: "self_propagation_signer",
      secret: "prop_secret",
      timestamp,
      nonce: "nonce_purpose_forbidden",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "POST",
        path: "/business/widgets",
        headers: headersToRecord(headers),
        rawBody: body,
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "PROPAGATION_ONLY_FORBIDDEN", status: 403 });
  });

  it("does not affect credentials with default purpose (any)", async () => {
    const auth = await buildAuthWithPropagationKey();
    await auth.clients.setSecret("data_plane_alpha", "alpha_secret");

    const timestamp = Date.now();
    const body = "";
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/business/widgets",
      body,
      clientId: "data_plane_alpha",
      secret: "alpha_secret",
      timestamp,
      nonce: "nonce_alpha_business",
    });

    const verified = await auth.verifyHttpSignature({
      method: "GET",
      path: "/business/widgets",
      headers: headersToRecord(headers),
      rawBody: body,
      now: timestamp,
    });

    expect(verified.clientId).toBe("data_plane_alpha");
  });

  it("rejects a propagation-only credential when no internalManagementRoute was configured", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_purpose_no_route", maxSkewMs: 5000 });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");
    await auth.clients.setSecret("propagation_only", "secret", undefined, undefined, {
      purpose: "propagation-only",
    });

    const timestamp = Date.now();
    const body = "";
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/anything",
      body,
      clientId: "propagation_only",
      secret: "secret",
      timestamp,
      nonce: "nonce_no_route",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/anything",
        headers: headersToRecord(headers),
        rawBody: body,
        now: timestamp,
      })
    ).rejects.toMatchObject({ code: "PROPAGATION_ONLY_FORBIDDEN", status: 403 });
  });

  it("propagates the purpose marker from the create option through clients.get", async () => {
    const auth = await buildAuthWithPropagationKey();
    const stored = await auth.clients.get("self_propagation_signer");
    expect(stored?.purpose).toBe("propagation-only");
  });
});
