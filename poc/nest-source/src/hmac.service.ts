import { initializeHmacHttpAuth, initializeHmacMessageAuth, type InitializedHmacHttpAuth } from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";
import { dbSeedRows } from "./db-seed.cfg";
import { microserviceConfig } from "./microservice.cfg";
import { runTortureSuite } from "./torture-suite";

export type HmacSourceRuntime = {
  hmacAuth: InitializedHmacHttpAuth;
  getInternalManagementMiddleware: () => ReturnType<InitializedHmacHttpAuth["createInternalManagementMiddleware"]>;
  syncFromConfig: () => Promise<void>;
  sendSignedHelloToTargets: () => Promise<void>;
  sendRejectedSignedHelloToTargets: () => Promise<void>;
  verifyAllPropagatedClients: () => Promise<void>;
  verifyAllPropagatedMessageClients: () => Promise<void>;
  logHttpClients: () => Promise<void>;
  logMessageClients: () => Promise<void>;
  close: () => Promise<void>;
};

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function isCreateAlreadyApplied(results: Array<{ accepted: boolean; body: unknown }>): boolean {
  return results.every((result) => {
    if (result.accepted) {
      return true;
    }

    const body = result.body as { message?: string } | null;
    return body?.message === "Client already exists";
  });
}

async function ensureHttpCredential(
  hmacAuth: InitializedHmacHttpAuth,
  clientId: string,
  secret: string,
  allowedIps?: string[]
): Promise<"created" | "updated"> {
  const current = await hmacAuth.clients.get(clientId);

  if (!current) {
    await hmacAuth.clients.create({
      clientId,
      plainSecret: secret,
      expiresAt: null,
      allowedIps: allowedIps ?? [],
    });
    return "created";
  }

  await hmacAuth.clients.setSecret(clientId, secret, current.expiresAt, allowedIps ?? current.allowedIps);
  return "updated";
}

export async function createHmacSourceRuntime(): Promise<HmacSourceRuntime> {
  const redisUrl = process.env.REDIS_URL ?? "redis://redis:6379";
  const namespace = process.env.HMAC_NAMESPACE ?? "poc-nest-source";
  const secretToken = process.env.HMAC_SECRET_TOKEN ?? "change_me";
  const internalManagementRoute = process.env.HMAC_INTERNAL_MANAGEMENT_ROUTE ?? "/api/internal/hmac";

  const redis: RedisClientType = createClient({ url: redisUrl });
  redis.on("error", (error) => {
    console.error("[nest_source] Redis error:", error);
  });
  await redis.connect();

  // v1.1.0: message store is bridged into the HTTP auth so propagateClientToApis
  // can be called with targetStore: "message" (Redis fallback reads from the
  // message store on the source side).
  const hmacMessageAuth = initializeHmacMessageAuth({
    redis,
    namespace: `${namespace}-messages`,
    secretToken,
  });

  const hmacAuth = initializeHmacHttpAuth({
    redis,
    namespace,
    secretToken,
    internalManagementRoute,
    messageAuth: hmacMessageAuth,
  });

  const hmacConfig = microserviceConfig.hmac_config;
  const httpInternalCredentials = hmacConfig?.hmacHttp?.internalCredentials ?? [];
  const httpPropagationPlans = hmacConfig?.hmacHttp?.propagationPlans ?? [];
  const messageCredentials = hmacConfig?.hmacMessage?.credentials ?? [];
  const credentialMap = new Map(httpInternalCredentials.map((credential) => [credential.clientId, credential.secret] as const));
  const secureTargets = Array.from(new Set(httpPropagationPlans.flatMap((plan) => plan.targets))).map((target) =>
    target.replace(/\/+$/, "")
  );
  const pocFetchClientId = process.env.POC_FETCH_CLIENT_ID ?? "internal_sync";
  const pocRejectedFetchClientId = process.env.POC_REJECTED_FETCH_CLIENT_ID ?? "source_only_client";

  const syncFromConfig = async (): Promise<void> => {
    for (const credential of messageCredentials) {
      const current = await hmacMessageAuth.clients.get(credential.clientId);
      if (!current) {
        await hmacMessageAuth.clients.create({
          clientId: credential.clientId,
          plainSecret: credential.secret,
          expiresAt: null,
          allowedIps: [],
        });
        console.log(`[nest_source] message credential created clientId=${credential.clientId}`);
      } else {
        await hmacMessageAuth.clients.setSecret(credential.clientId, credential.secret, current.expiresAt, current.allowedIps);
        console.log(`[nest_source] message credential updated clientId=${credential.clientId}`);
      }
    }

    for (const credential of httpInternalCredentials) {
      const action = await ensureHttpCredential(hmacAuth, credential.clientId, credential.secret, credential.allowedIps);
      console.log(`[nest_source] http internal credential ${action} clientId=${credential.clientId}`);
    }

    for (const plan of httpPropagationPlans) {
      const signerSecret = credentialMap.get(plan.signerClientId);
      if (!signerSecret) {
        throw new Error(`Missing signer secret for clientId '${plan.signerClientId}'`);
      }

      const signer = hmacAuth.createHttpSignedFetchClient({
        clientId: plan.signerClientId,
        secret: signerSecret,
      });

      const targetStore = plan.targetStore ?? "http";
      let applied = false;
      for (let attempt = 1; attempt <= 20; attempt += 1) {
        const results = await hmacAuth.propagateClientToApis({
          operation: "create",
          targets: plan.targets,
          clientId: plan.clientId,
          secret: plan.secret,
          allowedIps: plan.allowedIps,
          apiFetch: signer,
          targetStore,
        });

        console.log(
          `[nest_source] propagation attempt=${attempt} clientId=${plan.clientId} targetStore=${targetStore} results=${JSON.stringify(results)}`
        );

        if (isCreateAlreadyApplied(results)) {
          applied = true;
          break;
        }

        await sleep(1500);
      }

      if (!applied) {
        console.error(`[nest_source] propagation FAILED for clientId=${plan.clientId} (targetStore=${targetStore})`);
      } else {
        console.log(`[nest_source] propagation applied for clientId=${plan.clientId} (targetStore=${targetStore})`);
      }
    }

    // v1.2.0 dynamic db-seed origin: optional, simulated by db-seed.cfg.ts.
    // Each row is propagated with `fromDbSeed: true` so the targets store the
    // origin marker alongside the credential. The signer is the same static
    // HTTP credential (`internal_sync`) used above; nothing else changes.
    const dbSeedSigner = hmacAuth.createHttpSignedFetchClient({
      clientId: "internal_sync",
      secret: credentialMap.get("internal_sync") ?? "",
    });

    const dbSeedTargets = secureTargets;

    for (const row of dbSeedRows) {
      const targetStore = row.targetStore ?? "http";
      let applied = false;
      for (let attempt = 1; attempt <= 20; attempt += 1) {
        const results = await hmacAuth.propagateClientToApis({
          operation: "create",
          targets: dbSeedTargets,
          clientId: row.clientId,
          secret: row.secret,
          allowedIps: ["0.0.0.0/0", "::/0"],
          apiFetch: dbSeedSigner,
          targetStore,
          fromDbSeed: true,
        });

        console.log(
          `[nest_source] db-seed propagation attempt=${attempt} clientId=${row.clientId} targetStore=${targetStore} fromDbSeed=true results=${JSON.stringify(results)}`
        );

        if (isCreateAlreadyApplied(results)) {
          applied = true;
          break;
        }

        await sleep(1500);
      }

      if (!applied) {
        console.error(`[nest_source] db-seed propagation FAILED clientId=${row.clientId} (targetStore=${targetStore})`);
      } else {
        console.log(`[nest_source] db-seed propagation applied clientId=${row.clientId} (targetStore=${targetStore})`);
      }
    }

    // v1.2.0 revert demo: for each db-seeded row, rotate the secret (operation
    // "update" with `fromDbSeed: true`) so the target writes a TTL backup of
    // the previous hash, then immediately call revert (operation "revert") so
    // the target restores the previous hash from that backup. Observable via
    // the targets' periodic `http clients =>` / `message clients =>` log line
    // which shows `hash=...` (current) and `backup=...` (TTL key).
    for (const row of dbSeedRows) {
      const targetStore = row.targetStore ?? "http";
      const rotatedSecret = `${row.secret}-rotated`;

      const rotateResults = await hmacAuth.propagateClientToApis({
        operation: "update",
        targets: dbSeedTargets,
        clientId: row.clientId,
        secret: rotatedSecret,
        allowedIps: ["0.0.0.0/0", "::/0"],
        apiFetch: dbSeedSigner,
        targetStore,
        fromDbSeed: true,
      });
      console.log(
        `[nest_source] revert-demo step1 rotate clientId=${row.clientId} targetStore=${targetStore} accepted=${rotateResults.every((r) => r.accepted)}`
      );

      const revertResults = await hmacAuth.propagateClientToApis({
        operation: "revert",
        targets: dbSeedTargets,
        clientId: row.clientId,
        apiFetch: dbSeedSigner,
        targetStore,
      });
      console.log(
        `[nest_source] revert-demo step2 revert clientId=${row.clientId} targetStore=${targetStore} results=${JSON.stringify(revertResults.map((r) => ({ target: r.target, status: r.status, body: r.body })))}`
      );
    }

    // Exhaustive torture suite covering revert paths, CRUD propagate paths,
    // local clients management and field preservation on revert. Each helper
    // logs every assertion outcome; a green run shows zero `torture FAIL:` lines.
    await runTortureSuite({
      hmacAuth,
      hmacMessageAuth,
      signer: dbSeedSigner,
      targets: dbSeedTargets,
    });
  };

  const sendSignedPayloadToTargets = async (opts: { clientId: string; payload: unknown; logLabel: string }): Promise<void> => {
    if (secureTargets.length === 0) {
      console.error("[nest_source] secure fetch skipped: no targets found in propagationPlans");
      return;
    }

    const signerSecret = credentialMap.get(opts.clientId);
    if (!signerSecret) {
      throw new Error(`Missing signer secret for clientId '${opts.clientId}'`);
    }

    const signer = hmacAuth.createHttpSignedFetchClient({
      clientId: opts.clientId,
      secret: signerSecret,
    });

    const results = await Promise.all(
      secureTargets.map(async (target) => {
        const url = `${target}/secure/poc`;

        try {
          const response = await signer(url, {
            method: "POST",
            headers: {
              "content-type": "application/json",
            },
            body: JSON.stringify(opts.payload),
          });

          const rawBody = await response.text();
          let parsedBody: unknown = rawBody || null;
          if (rawBody) {
            try {
              parsedBody = JSON.parse(rawBody);
            } catch {
              parsedBody = rawBody;
            }
          }

          return {
            target,
            url,
            status: response.status,
            accepted: response.ok,
            body: parsedBody,
          };
        } catch (error: unknown) {
          return {
            target,
            url,
            status: 0,
            accepted: false,
            body: null,
            error: error instanceof Error ? error.message : String(error),
          };
        }
      })
    );

    console.log(`[nest_source] ${opts.logLabel}=${JSON.stringify(results)}`);
  };

  const sendSignedHelloToTargets = async (): Promise<void> => {
    await sendSignedPayloadToTargets({
      clientId: pocFetchClientId,
      payload: {
        message: "hello POC i am nestjs source",
        source: "nest_source",
        sentAt: new Date().toISOString(),
      },
      logLabel: "secure fetch results",
    });
  };

  const sendRejectedSignedHelloToTargets = async (): Promise<void> => {
    await sendSignedPayloadToTargets({
      clientId: pocRejectedFetchClientId,
      payload: {
        message: "hello POC i am nestjs source (rejected expected)",
        source: "nest_source",
        sentAt: new Date().toISOString(),
      },
      logLabel: "rejected secure fetch results",
    });
  };

  const verifyAllPropagatedClients = async (): Promise<void> => {
    // For each propagated clientId, sign a secure fetch from source and assert
    // both targets accept it (200) - proves cross-token verification works
    // because source/targets have DIFFERENT HMAC_SECRET_TOKEN yet share the
    // same secretHash (transported by the propagateClientToApis hotfix).
    //
    // v1.1.0: skip message-store propagation plans here - they don't sign
    // HTTP requests; they are exercised by verifyAllPropagatedMessageClients below.
    const propagatedClientIds = httpPropagationPlans
      .filter((plan) => (plan.targetStore ?? "http") === "http")
      .map((plan) => plan.clientId);
    const summary: Array<{ clientId: string; nest_target: number; express_target: number; allOk: boolean }> = [];

    for (const clientId of propagatedClientIds) {
      const signerSecret = credentialMap.get(clientId);
      if (!signerSecret) {
        console.error(`[nest_source] cross-token verify skipped clientId=${clientId}: no local credential`);
        continue;
      }

      const signer = hmacAuth.createHttpSignedFetchClient({
        clientId,
        secret: signerSecret,
      });

      const perTargetStatus: Record<string, number> = {};
      for (const target of secureTargets) {
        const url = `${target}/secure/poc`;
        try {
          const response = await signer(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              message: `cross-token verify clientId=${clientId}`,
              source: "nest_source",
              sentAt: new Date().toISOString(),
            }),
          });
          await response.text();
          perTargetStatus[target] = response.status;
        } catch (error: unknown) {
          perTargetStatus[target] = 0;
          console.error(`[nest_source] verify clientId=${clientId} target=${target} fetch error:`, error);
        }
      }

      const nest = perTargetStatus["http://nest_target:3002"] ?? 0;
      const exp = perTargetStatus["http://express_target:3003"] ?? 0;
      summary.push({
        clientId,
        nest_target: nest,
        express_target: exp,
        allOk: nest === 200 && exp === 200,
      });
    }

    const okCount = summary.filter((row) => row.allOk).length;
    console.log(`[nest_source] cross-token verify summary ok=${okCount}/${summary.length} details=${JSON.stringify(summary)}`);
  };

  const verifyAllPropagatedMessageClients = async (): Promise<void> => {
    // v1.1.0: each message clientId pushed to the targets via
    // targetStore="message" must produce a signature that the target's
    // hmacMessageAuth.verifyMessage accepts. This proves the propagated
    // secretHash matches byte-for-byte on the message store too, regardless
    // of HMAC_SECRET_TOKEN per-service.
    const messageClientIds = httpPropagationPlans.filter((plan) => plan.targetStore === "message").map((plan) => plan.clientId);

    const summary: Array<{
      clientId: string;
      nest_target: { status: number; ok: boolean };
      express_target: { status: number; ok: boolean };
      allOk: boolean;
    }> = [];

    for (const clientId of messageClientIds) {
      const messagePayload = {
        message: `cross-token message verify clientId=${clientId}`,
        source: "nest_source",
        sentAt: new Date().toISOString(),
      };
      let signed: { clientId: string; messageHash: string; signature: string };
      try {
        signed = await hmacMessageAuth.signMessage({ clientId, message: messagePayload });
      } catch (error) {
        console.error(`[nest_source] message verify skipped clientId=${clientId}: signMessage error`, error);
        continue;
      }

      const perTarget: Record<string, { status: number; ok: boolean }> = {};
      for (const target of secureTargets) {
        const url = `${target}/message/verify`;
        try {
          const response = await fetch(url, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              clientId,
              message: messagePayload,
              signature: signed.signature,
            }),
          });
          const rawBody = await response.text();
          let parsed: unknown = rawBody || null;
          try {
            parsed = rawBody ? JSON.parse(rawBody) : null;
          } catch {
            parsed = rawBody;
          }
          const ok = response.status === 200 && parsed != null && (parsed as { ok?: boolean }).ok === true;
          perTarget[target] = { status: response.status, ok };
        } catch (error: unknown) {
          perTarget[target] = { status: 0, ok: false };
          console.error(`[nest_source] message verify clientId=${clientId} target=${target} fetch error:`, error);
        }
      }

      const nest = perTarget["http://nest_target:3002"] ?? { status: 0, ok: false };
      const exp = perTarget["http://express_target:3003"] ?? { status: 0, ok: false };
      summary.push({ clientId, nest_target: nest, express_target: exp, allOk: nest.ok && exp.ok });
    }

    const okCount = summary.filter((row) => row.allOk).length;
    console.log(
      `[nest_source] cross-token message verify summary ok=${okCount}/${summary.length} details=${JSON.stringify(summary)}`
    );
  };

  const logHttpClients = async (): Promise<void> => {
    const clientIds = await hmacAuth.clients.listClientIds();
    console.log(`[nest_source] http clients => ${clientIds.join(",") || "(none)"}`);
  };

  const logMessageClients = async (): Promise<void> => {
    const clientIds = await hmacMessageAuth.clients.listClientIds();
    console.log(`[nest_source] message clients => ${clientIds.join(",") || "(none)"}`);
  };

  return {
    hmacAuth,
    getInternalManagementMiddleware: () => hmacAuth.createInternalManagementMiddleware(),
    syncFromConfig,
    sendSignedHelloToTargets,
    sendRejectedSignedHelloToTargets,
    verifyAllPropagatedClients,
    verifyAllPropagatedMessageClients,
    logHttpClients,
    logMessageClients,
    close: async () => {
      await redis.quit();
    },
  };
}
