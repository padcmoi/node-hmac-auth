import { randomBytes } from "node:crypto";
import {
  createHttpSignedFetchClient,
  type CreateHttpSignedFetchClientOptions,
  type SignedHttpFetchClientCallOptions,
} from "./client/signed-fetch.js";
import { HmacAuthError } from "./errors.js";
import { hashClientSecret } from "./hmac.js";
import { createExpressHttpHmacMiddleware } from "./server/express.js";
import { verifyHttpSignature as verifyHttpSignatureCore } from "./server/verify.js";
import {
  RedisCredentialStore,
  assertRedisClient,
  resolveNamespace,
  type RedisLikeClient,
  type StoredClientCredentialRecord,
} from "./stores/redis.js";
import type {
  CreateHmacClientOptions,
  HmacClientCredential,
  HmacClientCredentialWithSecret,
  InitializeHmacHttpAuthOptions,
  OnBadHttpSignature,
  RegenerateHmacSecretOptions,
  VerifiedHttpRequest,
  VerifyHttpWithRedisInput,
} from "./types.js";

const DEFAULT_MAX_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_SECRET_LENGTH_BYTES = 32;

function assertClientId(clientId: string): void {
  if (!clientId || !clientId.trim()) {
    throw new HmacAuthError("MISSING_CLIENT_ID", "clientId cannot be empty", 400);
  }
}

function normalizeSecretHash(secretHash: string): string {
  return secretHash.trim().toLowerCase();
}

function normalizeExpiresAt(value?: number | Date | null): number | null {
  if (value == null) {
    return null;
  }

  const expiresAt = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(expiresAt)) {
    throw new Error("expiresAt must be a valid timestamp or Date");
  }
  return expiresAt;
}

function assertSecretLength(secretLengthBytes: number): void {
  if (!Number.isInteger(secretLengthBytes) || secretLengthBytes < 16 || secretLengthBytes > 128) {
    throw new Error("secretLengthBytes must be an integer between 16 and 128");
  }
}

function assertPlainSecret(secret: string): void {
  if (!secret || !secret.trim()) {
    throw new Error("plainSecret cannot be empty");
  }
}

function mapCredential(clientId: string, record: StoredClientCredentialRecord): HmacClientCredential {
  return {
    clientId,
    secretHash: record.secretHash,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    expiresAt: record.expiresAt,
  };
}

function generateSecret(secretLengthBytes: number): string {
  assertSecretLength(secretLengthBytes);
  return randomBytes(secretLengthBytes).toString("hex");
}

export interface InitializedHmacHttpAuth {
  readonly redis: RedisLikeClient;
  readonly namespace: string;
  readonly maxSkewMs: number;
  readonly secretToken?: string;
  verifyHttpRequest: (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  verifyHttpSignature: (input: VerifyHttpWithRedisInput) => Promise<VerifiedHttpRequest>;
  createHttpMiddleware: (options?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) => (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  createExpressHttpMiddleware: (options?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) => (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  createHttpSignedFetchClient: (
    options: CreateHttpSignedFetchClientOptions,
  ) => (url: string, options?: SignedHttpFetchClientCallOptions) => Promise<Response>;
  clients: {
    create: (options: CreateHmacClientOptions) => Promise<HmacClientCredentialWithSecret>;
    listClientIds: () => Promise<string[]>;
    get: (clientId: string) => Promise<HmacClientCredential | null>;
    delete: (clientId: string) => Promise<void>;
    regenerateSecret: (clientId: string, options?: RegenerateHmacSecretOptions) => Promise<HmacClientCredentialWithSecret>;
    setSecret: (clientId: string, secret: string, expiresAt?: number | Date | null) => Promise<void>;
    setSecretHash: (clientId: string, secretHash: string, expiresAt?: number | Date | null) => Promise<void>;
    getSecretHash: (clientId: string) => Promise<string | null>;
  };
}

export function initializeHmacHttpAuth(options: InitializeHmacHttpAuthOptions): InitializedHmacHttpAuth {
  if (!options?.redis) {
    throw new Error("Redis connection is mandatory");
  }

  assertRedisClient(options.redis);

  const namespace = resolveNamespace(options.namespace);
  const maxSkewMs = options.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
  const defaultSecretLengthBytes = options.defaultSecretLengthBytes ?? DEFAULT_SECRET_LENGTH_BYTES;
  const secretToken = options.secretToken;
  assertSecretLength(defaultSecretLengthBytes);
  const credentialStore = new RedisCredentialStore(options.redis, namespace);
  const verifyHttpSignature = async (input: VerifyHttpWithRedisInput): Promise<VerifiedHttpRequest> =>
    verifyHttpSignatureCore({
      ...input,
      redis: options.redis,
      namespace,
      maxSkewMs: input.maxSkewMs ?? maxSkewMs,
      onBadSignature: input.onBadSignature ?? options.onBadSignature,
      metadata: input.metadata,
    });

  const httpMiddlewareFactory = (middlewareOptions?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) =>
    createExpressHttpHmacMiddleware({
      redis: options.redis,
      namespace,
      maxSkewMs: middlewareOptions?.maxSkewMs ?? maxSkewMs,
      attachAuthTo: middlewareOptions?.attachAuthTo,
      onError: middlewareOptions?.onError,
      onBadSignature: middlewareOptions?.onBadSignature ?? options.onBadSignature,
    });
  const verifyHttpRequest = httpMiddlewareFactory();

  return {
    redis: options.redis,
    namespace,
    maxSkewMs,
    secretToken,
    verifyHttpRequest,
    verifyHttpSignature,
    createHttpMiddleware: httpMiddlewareFactory,
    createExpressHttpMiddleware: httpMiddlewareFactory,
    createHttpSignedFetchClient: (clientOptions) =>
      createHttpSignedFetchClient({
        ...clientOptions,
        hashToken: clientOptions.hashToken ?? secretToken,
      }),
    clients: {
      create: async (createOptions) => {
        assertClientId(createOptions.clientId);
        let secret: string;
        if (createOptions.plainSecret !== undefined) {
          assertPlainSecret(createOptions.plainSecret);
          secret = createOptions.plainSecret;
        } else {
          secret = generateSecret(createOptions.secretLengthBytes ?? defaultSecretLengthBytes);
        }
        const secretHash = hashClientSecret(secret, secretToken);
        const now = Date.now();
        const record: StoredClientCredentialRecord = {
          secretHash,
          createdAt: now,
          updatedAt: now,
          expiresAt: normalizeExpiresAt(createOptions.expiresAt),
        };

        await credentialStore.setClientRecord(createOptions.clientId, record);

        return {
          ...mapCredential(createOptions.clientId, record),
          secret,
        };
      },
      listClientIds: async () => credentialStore.listClientIds(),
      get: async (clientId) => {
        assertClientId(clientId);
        const record = await credentialStore.getClientRecord(clientId);
        if (!record) {
          return null;
        }
        return mapCredential(clientId, record);
      },
      delete: async (clientId) => {
        assertClientId(clientId);
        await credentialStore.deleteClient(clientId);
      },
      regenerateSecret: async (clientId, regenerateOptions) => {
        assertClientId(clientId);
        const existing = await credentialStore.getClientRecord(clientId);
        if (!existing) {
          throw new HmacAuthError("CLIENT_NOT_FOUND", "Cannot regenerate secret: client not found", 404);
        }

        let secret: string;
        if (regenerateOptions?.plainSecret !== undefined) {
          assertPlainSecret(regenerateOptions.plainSecret);
          secret = regenerateOptions.plainSecret;
        } else {
          const secretLength = regenerateOptions?.secretLengthBytes ?? defaultSecretLengthBytes;
          secret = generateSecret(secretLength);
        }
        const now = Date.now();
        const expiresAt =
          regenerateOptions?.expiresAt !== undefined
            ? normalizeExpiresAt(regenerateOptions.expiresAt)
            : regenerateOptions?.preserveExpiresAt === false
              ? null
              : existing.expiresAt;

        const updatedRecord: StoredClientCredentialRecord = {
          secretHash: hashClientSecret(secret, secretToken),
          createdAt: existing.createdAt || now,
          updatedAt: now,
          expiresAt,
        };

        await credentialStore.setClientRecord(clientId, updatedRecord);
        return {
          ...mapCredential(clientId, updatedRecord),
          secret,
        };
      },
      setSecret: async (clientId, secret, expiresAt) => {
        assertClientId(clientId);
        const now = Date.now();
        const existing = await credentialStore.getClientRecord(clientId);
        const record: StoredClientCredentialRecord = {
          secretHash: hashClientSecret(secret, secretToken),
          createdAt: existing?.createdAt || now,
          updatedAt: now,
          expiresAt: expiresAt === undefined ? (existing?.expiresAt ?? null) : normalizeExpiresAt(expiresAt),
        };
        await credentialStore.setClientRecord(clientId, record);
      },
      setSecretHash: async (clientId, secretHash, expiresAt) => {
        assertClientId(clientId);
        const now = Date.now();
        const existing = await credentialStore.getClientRecord(clientId);
        const record: StoredClientCredentialRecord = {
          secretHash: normalizeSecretHash(secretHash),
          createdAt: existing?.createdAt || now,
          updatedAt: now,
          expiresAt: expiresAt === undefined ? (existing?.expiresAt ?? null) : normalizeExpiresAt(expiresAt),
        };
        await credentialStore.setClientRecord(clientId, record);
      },
      getSecretHash: async (clientId) => {
        assertClientId(clientId);
        return credentialStore.getSecretHash(clientId);
      },
    },
  };
}
