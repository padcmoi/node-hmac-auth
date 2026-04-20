import { describe, expect, it } from "vitest";
import { hashClientSecret, initializeHmacMessageAuth, signMessage, verifyMessage } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

describe("HMAC auth - message", () => {
  it("signs and verifies messages with low-level helpers", () => {
    const signed = signMessage({
      clientId: "app_msg",
      secret: "msg_secret",
      message: {
        z: 3,
        a: 1,
        nested: { y: true, x: "ok" },
      },
    });

    expect(signed.clientId).toBe("app_msg");
    expect(signed.signature).toBeTruthy();
    expect(signed.messageHash).toBeTruthy();

    const valid = verifyMessage({
      clientId: "app_msg",
      secret: "msg_secret",
      signature: signed.signature,
      message: {
        a: 1,
        nested: { x: "ok", y: true },
        z: 3,
      },
    });
    expect(valid).toBe(true);

    const invalid = verifyMessage({
      clientId: "app_msg",
      secret: "msg_secret",
      signature: signed.signature,
      message: {
        a: 1,
        nested: { x: "ok", y: false },
        z: 3,
      },
    });
    expect(invalid).toBe(false);
  });

  it("supports Redis-backed message sign/verify without anti-replay or skew checks", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_msg",
    });
    await messageAuth.clients.setSecret("app_msg", "msg_secret");

    const signed = await messageAuth.signMessage({
      clientId: "app_msg",
      message: { event: "order.created", id: 42 },
    });

    const verified1 = await messageAuth.verifyMessage({
      clientId: "app_msg",
      message: { id: 42, event: "order.created" },
      signature: signed.signature,
    });
    expect(verified1.clientId).toBe("app_msg");
    expect(verified1.messageHash).toBe(signed.messageHash);

    // Same signature can be verified multiple times by design for async message flows.
    const verified2 = await messageAuth.verifyMessage({
      clientId: "app_msg",
      message: { id: 42, event: "order.created" },
      signature: signed.signature,
    });
    expect(verified2.signature).toBe(signed.signature);

    await expect(
      messageAuth.verifyMessage({
        clientId: "unknown_msg",
        message: { id: 42, event: "order.created" },
        signature: signed.signature,
      })
    ).rejects.toMatchObject({ code: "UNKNOWN_CLIENT", status: 401 });

    await expect(
      messageAuth.signMessage({
        clientId: "unknown_msg",
        message: { id: 42, event: "order.created" },
      })
    ).rejects.toMatchObject({ code: "CLIENT_NOT_FOUND", status: 404 });
  });

  it("supports message regenerateSecret with provided plainSecret", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_msg_regen_plain",
    });

    await messageAuth.clients.create({
      clientId: "app_msg_regen",
      plainSecret: "initial_msg_secret",
    });

    const regenerated = await messageAuth.clients.regenerateSecret("app_msg_regen", {
      plainSecret: "custom_msg_secret",
    });

    expect(regenerated.secret).toBe("custom_msg_secret");
    expect(regenerated.secretHash).toBe(hashClientSecret("custom_msg_secret"));
    expect((await messageAuth.clients.get("app_msg_regen"))?.secretHash).toBe(hashClientSecret("custom_msg_secret"));
  });
});
