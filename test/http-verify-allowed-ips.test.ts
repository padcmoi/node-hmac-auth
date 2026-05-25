import { describe, expect, it } from "vitest";
import { buildHttpSignedHeaders, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis, headersToRecord } from "./helpers/test-utils.js";

/**
 * `allowedIps` per-clientId IP/CIDR allowlist semantics on the verify path.
 * Tests cover the allow case (exact match + CIDR match), the deny case (IP
 * outside the allowlist), and the safety case where the client has an
 * allowlist but the verifier could not determine the request IP.
 */
describe("HMAC auth - HTTP verify - allowedIps allowlist", () => {
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
});
