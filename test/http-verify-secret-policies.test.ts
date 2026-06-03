import { describe, expect, it } from "vitest";
import { buildHttpSignedHeaders, hashClientSecret, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * Secret-shape policies on the verify path:
 *  - expired credentials -> 401 CLIENT_EXPIRED
 *  - `secretToken` (a.k.a. HMAC_SECRET_TOKEN): when configured, every secret
 *    is hashed as `hmac-sha256(secretToken, secret)` instead of `sha256(secret)`,
 *    so signatures generated with a different token never verify.
 */
describe("HMAC auth - HTTP verify - secret policies (expiration + secretToken)", () => {
  it("returns 401 when client secret is expired", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_expired", maxSkewMs: 5000 });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");
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

  it("supports secretToken for deterministic tokenized secret hashes", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_tokenized", maxSkewMs: 5000, secretToken: "abc" });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");

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
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_token_verify", maxSkewMs: 5000, secretToken: "abc" });
    await auth.clients.setSecret("self_propagation_signer", "test_bootstrap_secret");
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
