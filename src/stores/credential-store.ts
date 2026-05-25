import { parseStoredClientRecord, type StoredClientCredentialRecord } from "./credential-record.js";
import { buildRedisNamespaceKeys } from "./namespace.js";
import {
  assertRedisClient,
  redisDel,
  redisGet,
  redisHDel,
  redisHGet,
  redisHKeys,
  redisHSet,
  redisSetEx,
  type RedisLikeClient,
} from "./redis-client.js";

/**
 * Redis-backed credential store.
 *
 * Wraps the `<namespace>:clients` hash for credential records and the
 * `<namespace>:credentials-backup:<clientId>` keys (TTL, v1.2.0) for
 * rotation backups used by `clients.revert(clientId)` on partial-failure
 * rollback scenarios.
 *
 * The implementation is namespace-aware but agnostic to the higher-level
 * semantics (HTTP vs message store) - both `initializeHmacHttpAuth` and
 * `initializeHmacMessageAuth` instantiate one of these with their own
 * namespace.
 */
export class RedisCredentialStore {
  private readonly client: RedisLikeClient;
  private readonly hashKey: string;
  private readonly backupKeyPrefix: string;

  constructor(client: RedisLikeClient, namespace?: string) {
    assertRedisClient(client);
    const keys = buildRedisNamespaceKeys(namespace);
    this.client = client;
    this.hashKey = keys.clientsHashKey;
    this.backupKeyPrefix = keys.credentialBackupKeyPrefix;
  }

  private buildBackupKey(clientId: string): string {
    return `${this.backupKeyPrefix}:${clientId}`;
  }

  async setBackupSecretHash(clientId: string, secretHash: string, ttlSeconds: number): Promise<void> {
    await redisSetEx(this.client, this.buildBackupKey(clientId), secretHash, ttlSeconds);
  }

  async getBackupSecretHash(clientId: string): Promise<string | null> {
    return redisGet(this.client, this.buildBackupKey(clientId));
  }

  async clearBackupSecretHash(clientId: string): Promise<void> {
    await redisDel(this.client, this.buildBackupKey(clientId));
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
      allowedIps: existing?.allowedIps ?? [],
      fromDbSeed: existing?.fromDbSeed ?? false,
    });
  }

  async listClientIds(): Promise<string[]> {
    return redisHKeys(this.client, this.hashKey);
  }

  async deleteClient(clientId: string): Promise<void> {
    await redisHDel(this.client, this.hashKey, clientId);
  }
}
