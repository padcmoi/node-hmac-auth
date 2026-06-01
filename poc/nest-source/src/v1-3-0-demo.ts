import { buildHttpSignedHeaders, initializeHmacHttpAuth, initializeHmacMessageAuth } from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";

/**
 * v1.3.0 end-to-end demonstration of Feature 1 (purpose: "propagation-only")
 * and Feature 2 (requireBootstrapClientId), exercised against real Redis. The
 * demo spins up an isolated `initializeHmacHttpAuth` instance in a dedicated
 * namespace, runs a fixed assertion sequence, and tears the namespace down
 * before returning so the main POC traffic is unaffected.
 *
 * What the assertions prove:
 *   - GET on the management route stays open while the bootstrap-lock is
 *     active and exposes `bootstrapLocked: true` so an orchestrator can
 *     detect the state without parsing error bodies.
 *   - Any POST whose clientId is not the named bootstrap clientId is
 *     refused with HTTP 403 BOOTSTRAP_LOCKED.
 *   - PUT / PATCH / DELETE are refused with HTTP 403 BOOTSTRAP_LOCKED.
 *   - A POST matching the bootstrap clientId releases the lock; subsequent
 *     GETs report `bootstrapLocked: false`.
 *   - A credential stored with `purpose: "propagation-only"` can sign
 *     requests to the management route (used for further propagation) but
 *     any other route returns HTTP 403 PROPAGATION_ONLY_FORBIDDEN even
 *     when the signature is otherwise valid.
 *   - On the message track, the propagation-only credential is refused
 *     outright on signMessage / verifyMessage.
 *
 * Output: one summary line per assertion (PASS / FAIL). A failure is loud
 * but non-fatal so the legacy POC flow keeps running.
 */
export async function runV1_3_0_Demo(): Promise<void> {
  const redisUrl = process.env.REDIS_URL ?? "redis://redis:6379";
  const namespace = `poc-v1-3-0-demo-${Date.now()}`;
  const route = "/api/internal/hmac";
  const propagationClientId = "self_propagation_signer";
  const propagationSecret = "demo_propagation_secret";

  const redis: RedisClientType = createClient({ url: redisUrl });
  redis.on("error", (error) => {
    console.error("[v1.3.0-demo] Redis error:", error);
  });
  await redis.connect();

  const secretToken = "demo_token";

  const results: Array<{ name: string; ok: boolean; detail?: string }> = [];
  const record = (name: string, ok: boolean, detail?: string): void => {
    results.push({ name, ok, detail });
    console.log(`[v1.3.0-demo] ${ok ? "PASS" : "FAIL"} ${name}${detail ? ` :: ${detail}` : ""}`);
  };

  try {
    const messageAuth = initializeHmacMessageAuth({
      redis,
      namespace: `${namespace}-messages`,
      secretToken,
      requireBootstrapClientId: propagationClientId,
    });

    const hmacAuth = initializeHmacHttpAuth({
      redis,
      namespace,
      secretToken,
      internalManagementRoute: route,
      messageAuth,
      requireBootstrapClientId: propagationClientId,
    });

    // Assertion 1: GET reports bootstrapLocked=true while the lock is active.
    const lockedHealth = await hmacAuth.handleInternalManagementRequest({
      method: "GET",
      path: route,
      headers: {},
      rawBody: "",
      now: Date.now(),
    });
    record(
      "GET reports bootstrapLocked=true while locked",
      lockedHealth.status === 200 && (lockedHealth.body as { bootstrapLocked?: boolean }).bootstrapLocked === true,
      `status=${lockedHealth.status} body=${JSON.stringify(lockedHealth.body)}`
    );

    // Assertion 2: POST with a non-bootstrap clientId is refused with BOOTSTRAP_LOCKED.
    const intruderPost = await hmacAuth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({ clientId: "intruder", secret: "evil" }),
      now: Date.now(),
    });
    record(
      "POST {clientId:'intruder'} refused with BOOTSTRAP_LOCKED",
      intruderPost.status === 403 && (intruderPost.body as { error?: string }).error === "BOOTSTRAP_LOCKED"
    );

    // Assertion 3: PUT, PATCH, DELETE are all refused while locked.
    for (const method of ["PUT", "PATCH", "DELETE"] as const) {
      const result = await hmacAuth.handleInternalManagementRequest({
        method,
        path: route,
        headers: {},
        rawBody: JSON.stringify({ clientId: propagationClientId }),
        now: Date.now(),
      });
      record(
        `${method} refused with BOOTSTRAP_LOCKED while locked`,
        result.status === 403 && (result.body as { error?: string }).error === "BOOTSTRAP_LOCKED"
      );
    }

    // Assertion 4: POST {clientId: bootstrap} with purpose='propagation-only' releases the lock.
    const bootstrapPost = await hmacAuth.handleInternalManagementRequest({
      method: "POST",
      path: route,
      headers: {},
      rawBody: JSON.stringify({
        clientId: propagationClientId,
        secret: propagationSecret,
        purpose: "propagation-only",
        allowedIps: [],
      }),
      now: Date.now(),
    });
    record("bootstrap POST stores the named credential and releases the lock", bootstrapPost.status === 201);

    // The bootstrap POST only stored the credential in the HTTP store. The
    // message store stays locked until its OWN credential is stored. Add the
    // same record there so the F1 message-track assertion below can run.
    await messageAuth.clients.create({
      clientId: propagationClientId,
      plainSecret: propagationSecret,
      purpose: "propagation-only",
      allowedIps: [],
    });

    // Assertion 5: GET now reports bootstrapLocked=false (signed by the propagation key).
    const timestampUnlocked = Date.now();
    const unlockHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: route,
      body: "",
      clientId: propagationClientId,
      secret: propagationSecret,
      hashToken: secretToken,
      timestamp: timestampUnlocked,
      nonce: `nonce-unlock-${timestampUnlocked}`,
    });
    const unlockedHealth = await hmacAuth.handleInternalManagementRequest({
      method: "GET",
      path: route,
      headers: Object.fromEntries(unlockHeaders.entries()),
      rawBody: "",
      now: timestampUnlocked,
    });
    record(
      "GET reports bootstrapLocked=false after the bootstrap write",
      unlockedHealth.status === 200 && (unlockedHealth.body as { bootstrapLocked?: boolean }).bootstrapLocked === false,
      `body=${JSON.stringify(unlockedHealth.body)}`
    );

    // Assertion 6: signed request on a business route with propagation-only credential → PROPAGATION_ONLY_FORBIDDEN.
    const timestampBusiness = Date.now();
    const businessHeaders = buildHttpSignedHeaders({
      method: "POST",
      url: "/business/widgets",
      body: "",
      clientId: propagationClientId,
      secret: propagationSecret,
      hashToken: secretToken,
      timestamp: timestampBusiness,
      nonce: `nonce-business-${timestampBusiness}`,
    });
    try {
      await hmacAuth.verifyHttpSignature({
        method: "POST",
        path: "/business/widgets",
        headers: Object.fromEntries(businessHeaders.entries()),
        rawBody: "",
        now: timestampBusiness,
      });
      record("verifyHttpSignature rejects propagation-only on a business route", false, "expected throw, got success");
    } catch (error) {
      const code = (error as { code?: string }).code;
      record(
        "verifyHttpSignature rejects propagation-only on a business route",
        code === "PROPAGATION_ONLY_FORBIDDEN",
        `code=${code}`
      );
    }

    // Assertion 7: same signed credential is accepted on the internal-management route.
    const timestampManagement = Date.now();
    const managementHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: route,
      body: "",
      clientId: propagationClientId,
      secret: propagationSecret,
      hashToken: secretToken,
      timestamp: timestampManagement,
      nonce: `nonce-management-${timestampManagement}`,
    });
    try {
      const verified = await hmacAuth.verifyHttpSignature({
        method: "GET",
        path: route,
        headers: Object.fromEntries(managementHeaders.entries()),
        rawBody: "",
        now: timestampManagement,
      });
      record("verifyHttpSignature accepts propagation-only on the management route", verified.clientId === propagationClientId);
    } catch (error) {
      const code = (error as { code?: string }).code;
      record("verifyHttpSignature accepts propagation-only on the management route", false, `code=${code}`);
    }

    // Assertion 8: message track refuses signMessage with a propagation-only credential.
    try {
      await messageAuth.signMessage({ clientId: propagationClientId, message: { hello: "world" } });
      record("signMessage rejects propagation-only credential", false, "expected throw, got success");
    } catch (error) {
      const code = (error as { code?: string }).code;
      record("signMessage rejects propagation-only credential", code === "PROPAGATION_ONLY_FORBIDDEN", `code=${code}`);
    }

    const passed = results.filter((r) => r.ok).length;
    console.log(
      `[v1.3.0-demo] summary ok=${passed}/${results.length} ${passed === results.length ? "(all v1.3.0 assertions passed)" : "(SOME ASSERTIONS FAILED)"}`
    );
  } finally {
    // Clean up the demo namespace so a re-run from scratch starts locked again.
    const hashKey = `${namespace}:clients`;
    const messageHashKey = `${namespace}-messages:clients`;
    await redis.del([hashKey, messageHashKey]);
    await redis.quit();
  }
}
