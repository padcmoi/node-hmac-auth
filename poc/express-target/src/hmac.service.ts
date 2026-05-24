import {
  initializeHmacHttpAuth,
  initializeHmacMessageAuth,
  type InitializedHmacHttpAuth,
  type InitializedHmacMessageAuth,
} from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";

export type HmacExpressRuntime = {
  hmacAuth: InitializedHmacHttpAuth;
  hmacMessageAuth: InitializedHmacMessageAuth;
  getInternalManagementMiddleware: () => ReturnType<InitializedHmacHttpAuth["createInternalManagementMiddleware"]>;
  logHttpClients: () => Promise<void>;
  logMessageClients: () => Promise<void>;
  close: () => Promise<void>;
};

export async function createHmacExpressRuntime(label: string): Promise<HmacExpressRuntime> {
  const redisUrl = process.env.REDIS_URL ?? "redis://redis:6379";
  const namespace = process.env.HMAC_NAMESPACE ?? "poc-express-target";
  const secretToken = process.env.HMAC_SECRET_TOKEN ?? "change_me";
  const internalManagementRoute = process.env.HMAC_INTERNAL_MANAGEMENT_ROUTE ?? "/api/internal/hmac";

  const redis: RedisClientType = createClient({ url: redisUrl });
  redis.on("error", (error) => {
    console.error(`[${label}] Redis error:`, error);
  });
  await redis.connect();

  // v1.1.0: bridge message store so the internal-management route can dispatch
  // both HTTP and message propagation payloads.
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

  const logHttpClients = async (): Promise<void> => {
    const clientIds = await hmacAuth.clients.listClientIds();
    console.log(`[${label}] http clients => ${clientIds.join(",") || "(none)"}`);
  };

  const logMessageClients = async (): Promise<void> => {
    const clientIds = await hmacMessageAuth.clients.listClientIds();
    console.log(`[${label}] message clients => ${clientIds.join(",") || "(none)"}`);
  };

  return {
    hmacAuth,
    hmacMessageAuth,
    getInternalManagementMiddleware: () => hmacAuth.createInternalManagementMiddleware(),
    logHttpClients,
    logMessageClients,
    close: async () => {
      await redis.quit();
    },
  };
}
