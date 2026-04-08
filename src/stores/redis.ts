export interface RedisLikeClient {
  hGet?: (key: string, field: string) => Promise<string | null> | string | null;
  hget?: (key: string, field: string) => Promise<string | null> | string | null;
  hSet?: (key: string, field: string, value: string) => Promise<unknown> | unknown;
  hset?: (key: string, field: string, value: string) => Promise<unknown> | unknown;
  hDel?: (key: string, field: string) => Promise<unknown> | unknown;
  hdel?: (key: string, field: string) => Promise<unknown> | unknown;
  hKeys?: (key: string) => Promise<string[]> | string[];
  hkeys?: (key: string) => Promise<string[]> | string[];
  set?: (key: string, value: string, ...args: unknown[]) => Promise<unknown> | unknown;
}

export interface RedisNamespaceKeys {
  clientsHashKey: string;
  nonceKeyPrefix: string;
}

export function resolveNamespace(namespace?: string): string {
  const raw = (namespace ?? "hmacauth").trim();
  if (!raw) {
    throw new Error("Namespace cannot be empty");
  }
  return raw;
}

export function buildRedisNamespaceKeys(namespace?: string): RedisNamespaceKeys {
  const resolved = resolveNamespace(namespace);
  return {
    clientsHashKey: `${resolved}:clients`,
    nonceKeyPrefix: `${resolved}:nonce`,
  };
}

export function assertRedisClient(client: RedisLikeClient): void {
  const hasHGet = typeof client.hGet === "function" || typeof client.hget === "function";
  const hasHSet = typeof client.hSet === "function" || typeof client.hset === "function";
  const hasHDel = typeof client.hDel === "function" || typeof client.hdel === "function";
  const hasHKeys = typeof client.hKeys === "function" || typeof client.hkeys === "function";
  const hasSet = typeof client.set === "function";

  if (!hasHGet || !hasHSet || !hasHDel || !hasHKeys || !hasSet) {
    throw new Error("Redis client is missing required commands (hGet/hSet/hDel/hKeys + set, or hget/hset/hdel/hkeys + set)");
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

export interface StoredClientCredentialRecord {
  secretHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function parseStoredClientRecord(rawValue: string): StoredClientCredentialRecord {
  try {
    const parsed = JSON.parse(rawValue) as Partial<StoredClientCredentialRecord>;
    if (typeof parsed?.secretHash === "string") {
      return {
        secretHash: parsed.secretHash,
        createdAt: isFiniteNumber(parsed.createdAt) ? parsed.createdAt : 0,
        updatedAt: isFiniteNumber(parsed.updatedAt) ? parsed.updatedAt : 0,
        expiresAt: isFiniteNumber(parsed.expiresAt) ? parsed.expiresAt : null,
      };
    }
  } catch {
    // Backward compatibility: old format stored only the secret hash
  }

  return {
    secretHash: rawValue,
    createdAt: 0,
    updatedAt: 0,
    expiresAt: null,
  };
}

export class RedisCredentialStore {
  private readonly client: RedisLikeClient;
  private readonly hashKey: string;

  constructor(client: RedisLikeClient, namespace?: string) {
    assertRedisClient(client);
    const keys = buildRedisNamespaceKeys(namespace);
    this.client = client;
    this.hashKey = keys.clientsHashKey;
  }

  async getClientRecord(clientId: string): Promise<StoredClientCredentialRecord | null> {
    const rawValue = await redisHGet(this.client, this.hashKey, clientId);
    if (!rawValue) {
      return null;
    }
    return parseStoredClientRecord(rawValue);
  }

  async setClientRecord(clientId: string, record: StoredClientCredentialRecord): Promise<void> {
    await redisHSet(this.client, this.hashKey, clientId, JSON.stringify(record));
  }

  async getSecretHash(clientId: string): Promise<string | null> {
    const record = await this.getClientRecord(clientId);
    return record?.secretHash ?? null;
  }

  async setSecretHash(clientId: string, secretHash: string): Promise<void> {
    const existing = await this.getClientRecord(clientId);
    const now = Date.now();
    await this.setClientRecord(clientId, {
      secretHash,
      createdAt: existing?.createdAt || now,
      updatedAt: now,
      expiresAt: existing?.expiresAt ?? null,
    });
  }

  async listClientIds(): Promise<string[]> {
    return redisHKeys(this.client, this.hashKey);
  }

  async deleteClient(clientId: string): Promise<void> {
    await redisHDel(this.client, this.hashKey, clientId);
  }
}

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
