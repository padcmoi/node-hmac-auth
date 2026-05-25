/**
 * Redis client abstraction.
 *
 * The lib accepts any Redis client that exposes either the camelCase API
 * (node-redis style: `hGet`, `hSet`, ...) or the lowercase API (ioredis
 * style: `hget`, `hset`, ...). The helpers below paper over the difference
 * so the rest of the library code can use a single API.
 *
 * `set` accepts both `set(key, value, { NX: true, EX: ttl })` (node-redis)
 * and `set(key, value, "EX", ttl, "NX")` (ioredis). The lib tries the
 * node-redis form first, then falls back to the ioredis form.
 */
export interface RedisLikeClient {
  hGet?: (key: string, field: string) => Promise<string | null> | string | null;
  hget?: (key: string, field: string) => Promise<string | null> | string | null;
  hSet?: (key: string, field: string, value: string) => Promise<unknown> | unknown;
  hset?: (key: string, field: string, value: string) => Promise<unknown> | unknown;
  hDel?: (key: string, field: string) => Promise<unknown> | unknown;
  hdel?: (key: string, field: string) => Promise<unknown> | unknown;
  hKeys?: (key: string) => Promise<string[]> | string[];
  hkeys?: (key: string) => Promise<string[]> | string[];
  set?: (key: string, value: string, ...args: any[]) => Promise<unknown> | unknown;
  get?: (key: string) => Promise<string | null> | string | null;
  del?: (key: string | string[]) => Promise<unknown> | unknown;
}

export function assertRedisClient(client: RedisLikeClient): void {
  const hasHGet = typeof client.hGet === "function" || typeof client.hget === "function";
  const hasHSet = typeof client.hSet === "function" || typeof client.hset === "function";
  const hasHDel = typeof client.hDel === "function" || typeof client.hdel === "function";
  const hasHKeys = typeof client.hKeys === "function" || typeof client.hkeys === "function";
  const hasSet = typeof client.set === "function";
  const hasGet = typeof client.get === "function";
  const hasDel = typeof client.del === "function";

  if (!hasHGet || !hasHSet || !hasHDel || !hasHKeys || !hasSet || !hasGet || !hasDel) {
    throw new Error(
      "Redis client is missing required commands (hGet/hSet/hDel/hKeys + get/set/del, or hget/hset/hdel/hkeys + get/set/del)"
    );
  }
}

export async function redisHGet(client: RedisLikeClient, key: string, field: string): Promise<string | null> {
  if (typeof client.hGet === "function") {
    const value = await client.hGet(key, field);
    return value == null ? null : String(value);
  }
  if (typeof client.hget === "function") {
    const value = await client.hget(key, field);
    return value == null ? null : String(value);
  }
  throw new Error("Redis client does not expose hGet/hget");
}

export async function redisHSet(client: RedisLikeClient, key: string, field: string, value: string): Promise<void> {
  if (typeof client.hSet === "function") {
    await client.hSet(key, field, value);
    return;
  }
  if (typeof client.hset === "function") {
    await client.hset(key, field, value);
    return;
  }
  throw new Error("Redis client does not expose hSet/hset");
}

export async function redisHDel(client: RedisLikeClient, key: string, field: string): Promise<void> {
  if (typeof client.hDel === "function") {
    await client.hDel(key, field);
    return;
  }
  if (typeof client.hdel === "function") {
    await client.hdel(key, field);
    return;
  }
  throw new Error("Redis client does not expose hDel/hdel");
}

export async function redisHKeys(client: RedisLikeClient, key: string): Promise<string[]> {
  if (typeof client.hKeys === "function") {
    const value = await client.hKeys(key);
    return Array.isArray(value) ? value.map(String) : [];
  }
  if (typeof client.hkeys === "function") {
    const value = await client.hkeys(key);
    return Array.isArray(value) ? value.map(String) : [];
  }
  throw new Error("Redis client does not expose hKeys/hkeys");
}

export async function redisSetNxEx(client: RedisLikeClient, key: string, value: string, ttlSeconds: number): Promise<boolean> {
  if (typeof client.set !== "function") {
    throw new Error("Redis client does not expose set");
  }

  try {
    const nodeRedisStyle = await client.set(key, value, { NX: true, EX: ttlSeconds });
    if (nodeRedisStyle === "OK" || nodeRedisStyle === true) {
      return true;
    }
    if (nodeRedisStyle == null) {
      return false;
    }
  } catch {
    // fall back to ioredis command-style arguments
  }

  const ioRedisStyle = await client.set(key, value, "EX", ttlSeconds, "NX");
  return ioRedisStyle === "OK" || ioRedisStyle === true;
}

export async function redisSetEx(client: RedisLikeClient, key: string, value: string, ttlSeconds: number): Promise<void> {
  if (typeof client.set !== "function") {
    throw new Error("Redis client does not expose set");
  }

  try {
    const nodeRedisStyle = await client.set(key, value, { EX: ttlSeconds });
    if (nodeRedisStyle === "OK" || nodeRedisStyle === true) {
      return;
    }
  } catch {
    // fall back to ioredis command-style arguments
  }

  await client.set(key, value, "EX", ttlSeconds);
}

export async function redisGet(client: RedisLikeClient, key: string): Promise<string | null> {
  if (typeof client.get !== "function") {
    throw new Error("Redis client does not expose get");
  }
  const value = await client.get(key);
  return value == null ? null : String(value);
}

export async function redisDel(client: RedisLikeClient, key: string): Promise<void> {
  if (typeof client.del !== "function") {
    throw new Error("Redis client does not expose del");
  }
  await client.del(key);
}
