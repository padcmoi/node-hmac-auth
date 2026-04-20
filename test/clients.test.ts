import { describe, expect, it } from "vitest";
import { hashClientSecret, initializeHmacHttpAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

describe("HMAC auth - clients", () => {
  it("supports client helpers create/list/delete/regenerate", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_admin", maxSkewMs: 5000 });

    const created = await auth.clients.create({
      clientId: "client_admin",
      expiresAt: Date.now() + 60_000,
      secretLengthBytes: 16,
    });

    expect(created.clientId).toBe("client_admin");
    expect(created.secret.length).toBe(32);
    expect(created.secretHash).toBeTruthy();
    expect(created.allowedIps).toEqual([]);

    const ids = await auth.clients.listClientIds();
    expect(ids).toContain("client_admin");

    const regenerated = await auth.clients.regenerateSecret("client_admin");
    expect(regenerated.clientId).toBe("client_admin");
    expect(regenerated.secret).not.toBe(created.secret);
    expect(regenerated.allowedIps).toEqual([]);

    await auth.clients.delete("client_admin");
    const deleted = await auth.clients.get("client_admin");
    expect(deleted).toBeNull();
  });

  it("supports create with provided plainSecret and deterministic hash", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_plain_secret", maxSkewMs: 5000 });

    const first = await auth.clients.create({
      clientId: "client_a",
      plainSecret: "helloworld",
    });
    const second = await auth.clients.create({
      clientId: "client_b",
      plainSecret: "helloworld",
    });

    expect(first.secret).toBe("helloworld");
    expect(second.secret).toBe("helloworld");
    expect(first.secretHash).toBe(second.secretHash);
    expect(first.secretHash).toBe(hashClientSecret("helloworld"));
    expect((await auth.clients.get("client_a"))?.secretHash).toBe(first.secretHash);
    expect((await auth.clients.get("client_b"))?.secretHash).toBe(second.secretHash);
  });

  it("rejects create when plainSecret is empty", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_empty_secret", maxSkewMs: 5000 });

    await expect(
      auth.clients.create({
        clientId: "client_empty",
        plainSecret: "   ",
      }),
    ).rejects.toThrow("plainSecret cannot be empty");
  });

  it("supports regenerateSecret with provided plainSecret", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_regen_plain_secret", maxSkewMs: 5000 });

    await auth.clients.create({
      clientId: "client_regen",
      plainSecret: "first_secret",
    });

    const regenerated = await auth.clients.regenerateSecret("client_regen", {
      plainSecret: "my_custom_secret",
    });

    expect(regenerated.secret).toBe("my_custom_secret");
    expect(regenerated.secretHash).toBe(hashClientSecret("my_custom_secret"));
    expect((await auth.clients.get("client_regen"))?.secretHash).toBe(hashClientSecret("my_custom_secret"));
  });

  it("supports allowedIps lifecycle on client credentials", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_allowed_ips_lifecycle", maxSkewMs: 5000 });

    const created = await auth.clients.create({
      clientId: "client_allowed_ips",
      plainSecret: "secret_allowed_ips",
      allowedIps: ["10.0.0.1", "10.0.0.0/24"],
    });
    expect(created.allowedIps).toEqual(["10.0.0.1", "10.0.0.0/24"]);

    await auth.clients.setAllowedIps("client_allowed_ips", ["172.16.1.5", "172.16.0.0/16"]);
    const afterSetAllowedIps = await auth.clients.get("client_allowed_ips");
    expect(afterSetAllowedIps?.allowedIps).toEqual(["172.16.1.5", "172.16.0.0/16"]);

    await auth.clients.setSecret("client_allowed_ips", "secret_rotated", undefined, ["192.168.1.1"]);
    const afterSetSecret = await auth.clients.get("client_allowed_ips");
    expect(afterSetSecret?.allowedIps).toEqual(["192.168.1.1"]);

    const regenerated = await auth.clients.regenerateSecret("client_allowed_ips", {
      plainSecret: "secret_rotated_again",
      allowedIps: ["203.0.113.0/24"],
    });
    expect(regenerated.allowedIps).toEqual(["203.0.113.0/24"]);
  });

  it("keeps random regeneration when plainSecret is not provided", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_regen_random", maxSkewMs: 5000 });

    await auth.clients.create({
      clientId: "client_regen_random",
      plainSecret: "seed_secret",
    });

    const regenerated = await auth.clients.regenerateSecret("client_regen_random", {
      secretLengthBytes: 24,
    });

    expect(regenerated.secret.length).toBe(48);
  });
});
