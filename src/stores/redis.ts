/**
 * Public Redis-store façade. Kept as the single entry point that
 * `src/index.ts` re-exports from, so consumers continue to import every
 * Redis-related symbol from `@naskot/node-hmac-auth/dist/stores/redis.js`
 * (or via the package barrel). Underlying modules are split per
 * business-logic concern:
 *
 *   - `./redis-client.js`       - RedisLikeClient + low-level command wrappers
 *   - `./namespace.js`          - key-namespace conventions
 *   - `./credential-record.js`  - serialized credential record type + parsing
 *   - `./credential-store.js`   - RedisCredentialStore (clients hash + backup TTL)
 *   - `./nonce-store.js`        - RedisNonceStore (single-use replay protection)
 */
export {
  assertRedisClient,
  redisDel,
  redisGet,
  redisHDel,
  redisHGet,
  redisHKeys,
  redisHSet,
  redisSetEx,
  redisSetNxEx,
  type RedisLikeClient,
} from "./redis-client.js";

export { buildRedisNamespaceKeys, resolveNamespace, type RedisNamespaceKeys } from "./namespace.js";

export { parseStoredClientRecord, type StoredClientCredentialRecord } from "./credential-record.js";

export { RedisCredentialStore } from "./credential-store.js";

export { RedisNonceStore } from "./nonce-store.js";
