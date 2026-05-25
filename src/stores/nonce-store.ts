import { buildRedisNamespaceKeys } from "./namespace.js";
import { assertRedisClient, redisSetNxEx, type RedisLikeClient } from "./redis-client.js";

/**
 * Redis-backed single-use nonce store. Keys live under
 * `<namespace>:nonce:<nonce>` and are inserted with `SET NX EX <ttlSeconds>`,
 * so a replayed nonce within the TTL window is rejected.
 */
export class RedisNonceStore {
  private readonly client: RedisLikeClient;
  private readonly keyPrefix: string;

  constructor(client: RedisLikeClient, namespace?: string) {
    assertRedisClient(client);
    const keys = buildRedisNamespaceKeys(namespace);
    this.client = client;
    this.keyPrefix = keys.nonceKeyPrefix;
  }

  async consume(key: string, ttlSeconds: number): Promise<boolean> {
    return redisSetNxEx(this.client, `${this.keyPrefix}:${key}`, "1", ttlSeconds);
  }
}
