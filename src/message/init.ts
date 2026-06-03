import { HmacAuthError } from "../core/errors.js";
import type {
  CreateHmacClientOptions,
  HmacClientCredential,
  HmacClientCredentialWithSecret,
  HmacCredentialRevertResult,
  HmacCredentialWriteOptions,
  InitializeHmacMessageAuthOptions,
  RegenerateHmacSecretOptions,
  SignedMessage,
  SignMessageWithRedisInput,
  VerifyMessageWithRedisInput,
} from "../core/types.js";
import { createCredentialsClientsFactory } from "../stores/credentials-clients-factory.js";
import { assertRedisClient, RedisCredentialStore, resolveNamespace, type RedisLikeClient } from "../stores/redis.js";
import { signMessage as signMessageCore, verifyMessage as verifyMessageCore } from "./signature.js";
import { DEFAULT_PROPAGATION_KEY_CLIENT_ID } from "../http/constants.js";

const DEFAULT_SECRET_LENGTH_BYTES = 32;
const DEFAULT_DB_SEED_BACKUP_TTL_SECONDS = 600;

function assertSecretLength(secretLengthBytes: number): void {
  if (!Number.isInteger(secretLengthBytes) || secretLengthBytes < 16 || secretLengthBytes > 128) {
    throw new Error("secretLengthBytes must be an integer between 16 and 128");
  }
}

function assertClientId(clientId: string): void {
  if (!clientId || !clientId.trim()) {
    throw new HmacAuthError("MISSING_CLIENT_ID", "clientId cannot be empty", 400);
  }
}

export interface InitializedHmacMessageAuth {
  readonly redis: RedisLikeClient;
  readonly namespace: string;
  readonly secretToken?: string;
  signMessage: (input: SignMessageWithRedisInput) => Promise<SignedMessage>;
  verifyMessage: (input: VerifyMessageWithRedisInput) => Promise<SignedMessage>;
  clients: {
    create: (options: CreateHmacClientOptions) => Promise<HmacClientCredentialWithSecret>;
    listClientIds: () => Promise<string[]>;
    get: (clientId: string) => Promise<HmacClientCredential | null>;
    delete: (clientId: string) => Promise<void>;
    regenerateSecret: (clientId: string, options?: RegenerateHmacSecretOptions) => Promise<HmacClientCredentialWithSecret>;
    setSecret: (
      clientId: string,
      secret: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[],
      options?: HmacCredentialWriteOptions
    ) => Promise<void>;
    setSecretHash: (
      clientId: string,
      secretHash: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[],
      options?: HmacCredentialWriteOptions
    ) => Promise<void>;
    setAllowedIps: (clientId: string, allowedIps: string[]) => Promise<void>;
    getSecretHash: (clientId: string) => Promise<string | null>;
    revert: (clientId: string) => Promise<HmacCredentialRevertResult>;
  };
}

export function initializeHmacMessageAuth(options: InitializeHmacMessageAuthOptions): InitializedHmacMessageAuth {
  if (!options?.redis) {
    throw new Error("Redis connection is mandatory");
  }

  assertRedisClient(options.redis);

  const namespace = resolveNamespace(options.namespace);
  const defaultSecretLengthBytes = options.defaultSecretLengthBytes ?? DEFAULT_SECRET_LENGTH_BYTES;
  const dbSeedBackupTtlSeconds = options.dbSeedBackupTtlSeconds ?? DEFAULT_DB_SEED_BACKUP_TTL_SECONDS;
  const secretToken = options.secretToken;
  // v1.4.0: federation-default clientId for the bootstrap lock. Override via
  // options to intentionally isolate the message store; omitted = canonical.
  const requireBootstrapClientId =
    typeof options.requireBootstrapClientId === "string" && options.requireBootstrapClientId.trim()
      ? options.requireBootstrapClientId.trim()
      : DEFAULT_PROPAGATION_KEY_CLIENT_ID;
  assertSecretLength(defaultSecretLengthBytes);
  const credentialStore = new RedisCredentialStore(options.redis, namespace);

  const clients = createCredentialsClientsFactory({
    credentialStore,
    secretToken,
    defaultSecretLengthBytes,
    dbSeedBackupTtlSeconds,
  });

  // v1.3.0: bootstrap-window lock on the message track. While the required
  // clientId is missing, both signMessage and verifyMessage throw 403
  // BOOTSTRAP_LOCKED. Once stored, the lock releases for the rest of the
  // process lifetime (subsequent removes still pass through, since auth
  // happens on the HTTP plane).
  async function assertBootstrapUnlocked(): Promise<void> {
    const bootstrapRecord = await credentialStore.getClientRecord(requireBootstrapClientId);
    if (!bootstrapRecord) {
      throw new HmacAuthError(
        "BOOTSTRAP_LOCKED",
        `Message store is locked until clientId '${requireBootstrapClientId}' is stored`,
        403
      );
    }
  }

  function assertNotPropagationOnly(clientId: string, record: { purpose?: string }): void {
    if (record.purpose === "propagation-only") {
      throw new HmacAuthError(
        "PROPAGATION_ONLY_FORBIDDEN",
        `Credential '${clientId}' has purpose 'propagation-only' and cannot sign or verify messages`,
        403
      );
    }
  }

  return {
    redis: options.redis,
    namespace,
    secretToken,
    signMessage: async (input) => {
      assertClientId(input.clientId);
      await assertBootstrapUnlocked();
      const record = await credentialStore.getClientRecord(input.clientId);
      if (!record) {
        throw new HmacAuthError("CLIENT_NOT_FOUND", "Cannot sign message: client not found", 404);
      }

      const now = Date.now();
      if (record.expiresAt != null && now > record.expiresAt) {
        throw new HmacAuthError("CLIENT_EXPIRED", "Client secret has expired");
      }

      assertNotPropagationOnly(input.clientId, record);

      return signMessageCore({
        clientId: input.clientId,
        message: input.message,
        secret: record.secretHash,
        secretIsHashed: true,
      });
    },
    verifyMessage: async (input) => {
      assertClientId(input.clientId);
      await assertBootstrapUnlocked();
      if (!input.signature || !input.signature.trim()) {
        throw new HmacAuthError("MISSING_SIGNATURE", "Missing message signature");
      }

      const record = await credentialStore.getClientRecord(input.clientId);
      if (!record) {
        throw new HmacAuthError("UNKNOWN_CLIENT", "Unknown client id");
      }

      const now = Date.now();
      if (record.expiresAt != null && now > record.expiresAt) {
        throw new HmacAuthError("CLIENT_EXPIRED", "Client secret has expired");
      }

      assertNotPropagationOnly(input.clientId, record);

      const isValid = verifyMessageCore({
        clientId: input.clientId,
        message: input.message,
        signature: input.signature,
        secret: record.secretHash,
        secretIsHashed: true,
      });

      if (!isValid) {
        throw new HmacAuthError("BAD_SIGNATURE", "Invalid message signature");
      }

      return signMessageCore({
        clientId: input.clientId,
        message: input.message,
        secret: record.secretHash,
        secretIsHashed: true,
      });
    },
    clients,
  };
}
