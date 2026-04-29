import { initializeHmacHttpAuth, type InitializedHmacHttpAuth } from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";

export type HmacTargetRuntime = {
  hmacAuth: InitializedHmacHttpAuth;
  getInternalManagementMiddleware: () => ReturnType<InitializedHmacHttpAuth["createInternalManagementMiddleware"]>;
  logHttpClients: () => Promise<void>;
  close: () => Promise<void>;
};

export async function createHmacTargetRuntime(label: string): Promise<HmacTargetRuntime> {
  const redisUrl = process.env.REDIS_URL ?? "redis://redis:6379";
  const namespace = process.env.HMAC_NAMESPACE ?? "poc-nest-target";
  const secretToken = process.env.HMAC_SECRET_TOKEN ?? "change_me";
  const internalManagementRoute = process.env.HMAC_INTERNAL_MANAGEMENT_ROUTE ?? "/api/internal/hmac";

  const redis: RedisClientType = createClient({ url: redisUrl });
  redis.on("error", (error) => {
    console.error(`[${label}] Redis error:`, error);
  });
  await redis.connect();

  const hmacAuth = initializeHmacHttpAuth({
    redis,
    namespace,
    secretToken,
    internalManagementRoute,
  });

  const logHttpClients = async (): Promise<void> => {
    const clientIds = await hmacAuth.clients.listClientIds();
    console.log(`[${label}] http clients => ${clientIds.join(",") || "(none)"}`);
  };

  return {
    hmacAuth,
    getInternalManagementMiddleware: () => hmacAuth.createInternalManagementMiddleware(),
    logHttpClients,
    close: async () => {
      await redis.quit();
    },
  };
}
