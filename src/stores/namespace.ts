/**
 * Redis key-namespace utilities. Keeps the key-shape contract in one place
 * so every store derives the exact same key prefixes from a given namespace.
 *
 *   `<namespace>:clients`             - hash map of credential records
 *   `<namespace>:nonce:*`             - single-use nonce keys (TTL)
 *   `<namespace>:credentials-backup:*` - rotation backup keys (TTL, v1.2.0)
 */
export interface RedisNamespaceKeys {
  clientsHashKey: string;
  nonceKeyPrefix: string;
  credentialBackupKeyPrefix: string;
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
    credentialBackupKeyPrefix: `${resolved}:credentials-backup`,
  };
}
