import { initializeHmacHttpAuth, initializeHmacMessageAuth, type InitializedHmacHttpAuth } from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";
import { microserviceConfig } from "./microservice.cfg";

export type HmacSourceRuntime = {
  hmacAuth: InitializedHmacHttpAuth;
  getInternalManagementMiddleware: () => ReturnType<InitializedHmacHttpAuth["createInternalManagementMiddleware"]>;
  syncFromConfig: () => Promise<void>;
  sendSignedHelloToTargets: () => Promise<void>;
  sendRejectedSignedHelloToTargets: () => Promise<void>;
  logHttpClients: () => Promise<void>;
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

  const hmacAuth = initializeHmacHttpAuth({
    redis,
    namespace,
    secretToken,
    internalManagementRoute,
  });

  const hmacMessageAuth = initializeHmacMessageAuth({
    redis,
    namespace: `${namespace}-messages`,
    secretToken,
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

      let applied = false;
      for (let attempt = 1; attempt <= 20; attempt += 1) {
        const results = await hmacAuth.propagateClientToApis({
          operation: "create",
          targets: plan.targets,
          clientId: plan.clientId,
          secret: plan.secret,
          allowedIps: plan.allowedIps,
          apiFetch: signer,
        });

        console.log(`[nest_source] propagation attempt=${attempt} clientId=${plan.clientId} results=${JSON.stringify(results)}`);

        if (isCreateAlreadyApplied(results)) {
          applied = true;
          break;
        }

        await sleep(1500);
      }

      if (!applied) {
        console.error(`[nest_source] propagation FAILED for clientId=${plan.clientId}`);
      } else {
        console.log(`[nest_source] propagation applied for clientId=${plan.clientId}`);
      }
    }
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

  const logHttpClients = async (): Promise<void> => {
    const clientIds = await hmacAuth.clients.listClientIds();
    console.log(`[nest_source] http clients => ${clientIds.join(",") || "(none)"}`);
  };

  return {
    hmacAuth,
    getInternalManagementMiddleware: () => hmacAuth.createInternalManagementMiddleware(),
    syncFromConfig,
    sendSignedHelloToTargets,
    sendRejectedSignedHelloToTargets,
    logHttpClients,
    close: async () => {
      await redis.quit();
    },
  };
}
