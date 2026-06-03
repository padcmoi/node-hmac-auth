import { describe, expect, it } from "vitest";
import { initializeHmacMessageAuth } from "../src/index.js";
import { FakeRedis } from "./helpers/test-utils.js";

/**
 * v1.3.0 / v1.4.0: the message track honors the same purpose +
 * bootstrap-lock semantics as the HTTP track. Messages have no path
 * concept, so a propagation-only credential is refused outright on both
 * signMessage and verifyMessage. v1.4.0 also makes
 * `requireBootstrapClientId` mandatory at boot.
 */
describe("HMAC auth - message track purpose & bootstrap", () => {
  it("signMessage and verifyMessage are locked until the bootstrap clientId is stored", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_msg_bootstrap",
    });
    await messageAuth.clients.setSecret("amqp_orders", "orders_secret");

    await expect(messageAuth.signMessage({ clientId: "amqp_orders", message: { id: 1 } })).rejects.toMatchObject({
      code: "BOOTSTRAP_LOCKED",
      status: 403,
    });

    await messageAuth.clients.setSecret("self_propagation_signer", "prop_secret", undefined, undefined, {
      purpose: "propagation-only",
    });

    const signed = await messageAuth.signMessage({ clientId: "amqp_orders", message: { id: 1 } });
    expect(signed.clientId).toBe("amqp_orders");
    expect(typeof signed.signature).toBe("string");
  });

  it("refuses to sign or verify with a propagation-only credential", async () => {
    const redis = new FakeRedis();
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: "tenant_msg_purpose",
    });
    await messageAuth.clients.setSecret("self_propagation_signer", "prop_secret", undefined, undefined, {
      purpose: "propagation-only",
    });

    await expect(
      messageAuth.signMessage({ clientId: "self_propagation_signer", message: { hello: "world" } })
    ).rejects.toMatchObject({ code: "PROPAGATION_ONLY_FORBIDDEN", status: 403 });

    await messageAuth.clients.setSecret("amqp_orders", "orders_secret");
    const signedByOrders = await messageAuth.signMessage({ clientId: "amqp_orders", message: { hello: "world" } });

    await expect(
      messageAuth.verifyMessage({
        clientId: "self_propagation_signer",
        message: { hello: "world" },
        signature: signedByOrders.signature,
      })
    ).rejects.toMatchObject({ code: "PROPAGATION_ONLY_FORBIDDEN", status: 403 });
  });
});
