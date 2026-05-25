import {
  initializeHmacHttpAuth,
  initializeHmacMessageAuth,
  type InitializedHmacHttpAuth,
  type InitializedHmacMessageAuth,
} from "@naskot/node-hmac-auth";
import { createClient, type RedisClientType } from "redis";

export type HmacTargetRuntime = {
  hmacAuth: InitializedHmacHttpAuth;
  hmacMessageAuth: InitializedHmacMessageAuth;
  getInternalManagementMiddleware: () => ReturnType<InitializedHmacHttpAuth["createInternalManagementMiddleware"]>;
  logHttpClients: () => Promise<void>;
  logMessageClients: () => Promise<void>;
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

  // v1.1.0: target now exposes a message store too, bridged into hmacAuth so a
  // single /api/internal/hmac route can dispatch HTTP-store and message-store
  // propagations based on payload.kind.
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

  const readBackupHash = async (storeNamespace: string, clientId: string): Promise<string | null> => {
    const key = `${storeNamespace}:credentials-backup:${clientId}`;
    const value = await redis.get(key);
    return value ?? null;
  };

  const summarizeHash = (hash: string | null | undefined): string => (hash ? hash.slice(0, 12) : "(none)");

  const logHttpClients = async (): Promise<void> => {
    const clientIds = await hmacAuth.clients.listClientIds();
    if (clientIds.length === 0) {
      console.log(`[${label}] http clients => (none)`);
      return;
    }
    const lines: string[] = [];
    for (const clientId of clientIds) {
      const credential = await hmacAuth.clients.get(clientId);
      const backup = await readBackupHash(namespace, clientId);
      lines.push(
        `${clientId}(fromDbSeed=${credential?.fromDbSeed === true},hash=${summarizeHash(credential?.secretHash)},backup=${summarizeHash(backup)})`
      );
    }
    console.log(`[${label}] http clients => ${lines.join(",")}`);
  };

  const logMessageClients = async (): Promise<void> => {
    const clientIds = await hmacMessageAuth.clients.listClientIds();
    if (clientIds.length === 0) {
      console.log(`[${label}] message clients => (none)`);
      return;
    }
    const messageNamespace = `${namespace}-messages`;
    const lines: string[] = [];
    for (const clientId of clientIds) {
      const credential = await hmacMessageAuth.clients.get(clientId);
      const backup = await readBackupHash(messageNamespace, clientId);
      lines.push(
        `${clientId}(fromDbSeed=${credential?.fromDbSeed === true},hash=${summarizeHash(credential?.secretHash)},backup=${summarizeHash(backup)})`
      );
    }
    console.log(`[${label}] message clients => ${lines.join(",")}`);
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
