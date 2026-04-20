import { randomBytes } from "node:crypto";
import { hashClientSecret } from "../core/crypto.js";
import { HmacAuthError } from "../core/errors.js";
import { normalizeAllowedIpRules } from "../core/ip.js";
import type {
  CreateHmacClientOptions,
  HmacClientCredential,
  HmacClientCredentialWithSecret,
  HmacInternalManagementRequestInput,
  HmacInternalManagementRequestResult,
  InitializeHmacHttpAuthOptions,
  OnBadHttpSignature,
  PropagateHmacClientOptions,
  PropagateHmacClientResult,
  RegenerateHmacSecretOptions,
  VerifiedHttpRequest,
  VerifyHttpWithRedisInput,
} from "../core/types.js";
import { normalizePath, toBodyString } from "../core/utils.js";
import {
  RedisCredentialStore,
  assertRedisClient,
  resolveNamespace,
  type RedisLikeClient,
  type StoredClientCredentialRecord,
} from "../stores/redis.js";
import {
  createHttpSignedFetchClient,
  type CreateHttpSignedFetchClientOptions,
  type SignedHttpFetchClientCallOptions,
} from "./client/signed-fetch.js";
import { createExpressHttpHmacMiddleware } from "./server/express.js";
import { verifyHttpSignature as verifyHttpSignatureCore } from "./server/verify.js";

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
    allowedIps: record.allowedIps,
  };
}

function generateSecret(secretLengthBytes: number): string {
  assertSecretLength(secretLengthBytes);
  return randomBytes(secretLengthBytes).toString("hex");
}

function parseInternalBody(rawBody: unknown): Record<string, unknown> {
  if (rawBody == null) {
    return {};
  }

  if (typeof rawBody === "object" && !Buffer.isBuffer(rawBody) && !(rawBody instanceof Uint8Array)) {
    return rawBody as Record<string, unknown>;
  }

  const asString = toBodyString(rawBody).trim();
  if (!asString) {
    return {};
  }

  try {
    const parsed = JSON.parse(asString) as unknown;
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

function normalizeRoutePath(pathOrUrl: string): string {
  const normalized = normalizePath(pathOrUrl);
  const [pathOnly] = normalized.split("?");
  if (!pathOnly || pathOnly === "") {
    return "/";
  }
  if (pathOnly.length > 1 && pathOnly.endsWith("/")) {
    return pathOnly.slice(0, -1);
  }
  return pathOnly;
}

function parseExpiresAtFromPayload(payload: Record<string, unknown>): number | null | undefined {
  if (!("expiresAt" in payload)) {
    return undefined;
  }

  const raw = payload.expiresAt;
  if (raw == null) {
    return null;
  }

  const numeric = Number(raw);
  if (!Number.isFinite(numeric)) {
    throw new Error("expiresAt must be a valid timestamp");
  }
  return numeric;
}

function parseAllowedIpsFromPayload(payload: Record<string, unknown>): string[] | undefined {
  if (!("allowedIps" in payload)) {
    return undefined;
  }

  if (payload.allowedIps == null) {
    return [];
  }

  if (!Array.isArray(payload.allowedIps)) {
    throw new Error("allowedIps must be an array of IP/CIDR strings");
  }

  return normalizeAllowedIpRules(payload.allowedIps as string[]);
}

function resolveTargetInternalUrl(target: string, routePath: string): string {
  const url = new URL(target);
  if (!url.pathname || url.pathname === "/") {
    url.pathname = routePath;
    url.search = "";
  }
  return url.toString();
}

async function parseFetchResponseBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    try {
      return await response.text();
    } catch {
      return null;
    }
  }
}

function normalizeInternalClientId(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function toHmacError(error: unknown): HmacAuthError {
  if (error instanceof HmacAuthError) {
    return error;
  }

  if (error instanceof Error) {
    return new HmacAuthError("INTERNAL_ERROR", error.message, 500);
  }

  return new HmacAuthError("INTERNAL_ERROR", "Internal auth error", 500);
}

function forbiddenInternal(message: string): HmacInternalManagementRequestResult {
  return {
    handled: true,
    status: 403,
    body: {
      error: "FORBIDDEN",
      message,
    },
    verifiedAuth: null,
  };
}

export interface InitializedHmacHttpAuth {
  readonly redis: RedisLikeClient;
  readonly namespace: string;
  readonly maxSkewMs: number;
  readonly secretToken?: string;
  readonly internalManagementRoute?: string;
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
  handleInternalManagementRequest: (input: HmacInternalManagementRequestInput) => Promise<HmacInternalManagementRequestResult>;
  createInternalManagementMiddleware: (options?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) => (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  createExpressInternalManagementMiddleware: (options?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) => (req: any, res: any, next: (error?: unknown) => void) => Promise<void>;
  propagateClientToApis: (options: PropagateHmacClientOptions) => Promise<PropagateHmacClientResult[]>;
  createHttpSignedFetchClient: (
    options: CreateHttpSignedFetchClientOptions,
  ) => (url: string, options?: SignedHttpFetchClientCallOptions) => Promise<Response>;
  clients: {
    create: (options: CreateHmacClientOptions) => Promise<HmacClientCredentialWithSecret>;
    listClientIds: () => Promise<string[]>;
    get: (clientId: string) => Promise<HmacClientCredential | null>;
    delete: (clientId: string) => Promise<void>;
    regenerateSecret: (clientId: string, options?: RegenerateHmacSecretOptions) => Promise<HmacClientCredentialWithSecret>;
    setSecret: (clientId: string, secret: string, expiresAt?: number | Date | null, allowedIps?: string[]) => Promise<void>;
    setSecretHash: (
      clientId: string,
      secretHash: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[],
    ) => Promise<void>;
    setAllowedIps: (clientId: string, allowedIps: string[]) => Promise<void>;
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
  const internalManagementRoute =
    typeof options.internalManagementRoute === "string" && options.internalManagementRoute.trim()
      ? normalizeRoutePath(options.internalManagementRoute)
      : undefined;
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

  const clients = {
    create: async (createOptions: CreateHmacClientOptions): Promise<HmacClientCredentialWithSecret> => {
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
        allowedIps: normalizeAllowedIpRules(createOptions.allowedIps),
      };

      await credentialStore.setClientRecord(createOptions.clientId, record);

      return {
        ...mapCredential(createOptions.clientId, record),
        secret,
      };
    },
    listClientIds: async (): Promise<string[]> => credentialStore.listClientIds(),
    get: async (clientId: string): Promise<HmacClientCredential | null> => {
      assertClientId(clientId);
      const record = await credentialStore.getClientRecord(clientId);
      if (!record) {
        return null;
      }
      return mapCredential(clientId, record);
    },
    delete: async (clientId: string): Promise<void> => {
      assertClientId(clientId);
      await credentialStore.deleteClient(clientId);
    },
    regenerateSecret: async (
      clientId: string,
      regenerateOptions?: RegenerateHmacSecretOptions,
    ): Promise<HmacClientCredentialWithSecret> => {
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
        allowedIps:
          regenerateOptions?.allowedIps !== undefined
            ? normalizeAllowedIpRules(regenerateOptions.allowedIps)
            : existing.allowedIps,
      };

      await credentialStore.setClientRecord(clientId, updatedRecord);
      return {
        ...mapCredential(clientId, updatedRecord),
        secret,
      };
    },
    setSecret: async (
      clientId: string,
      secret: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[],
    ): Promise<void> => {
      assertClientId(clientId);
      const now = Date.now();
      const existing = await credentialStore.getClientRecord(clientId);
      const record: StoredClientCredentialRecord = {
        secretHash: hashClientSecret(secret, secretToken),
        createdAt: existing?.createdAt || now,
        updatedAt: now,
        expiresAt: expiresAt === undefined ? (existing?.expiresAt ?? null) : normalizeExpiresAt(expiresAt),
        allowedIps: allowedIps === undefined ? (existing?.allowedIps ?? []) : normalizeAllowedIpRules(allowedIps),
      };
      await credentialStore.setClientRecord(clientId, record);
    },
    setSecretHash: async (
      clientId: string,
      secretHash: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[],
    ): Promise<void> => {
      assertClientId(clientId);
      const now = Date.now();
      const existing = await credentialStore.getClientRecord(clientId);
      const record: StoredClientCredentialRecord = {
        secretHash: normalizeSecretHash(secretHash),
        createdAt: existing?.createdAt || now,
        updatedAt: now,
        expiresAt: expiresAt === undefined ? (existing?.expiresAt ?? null) : normalizeExpiresAt(expiresAt),
        allowedIps: allowedIps === undefined ? (existing?.allowedIps ?? []) : normalizeAllowedIpRules(allowedIps),
      };
      await credentialStore.setClientRecord(clientId, record);
    },
    setAllowedIps: async (clientId: string, allowedIps: string[]): Promise<void> => {
      assertClientId(clientId);
      const now = Date.now();
      const existing = await credentialStore.getClientRecord(clientId);
      if (!existing) {
        throw new HmacAuthError("CLIENT_NOT_FOUND", "Cannot set allowedIps: client not found", 404);
      }

      const record: StoredClientCredentialRecord = {
        secretHash: existing.secretHash,
        createdAt: existing.createdAt || now,
        updatedAt: now,
        expiresAt: existing.expiresAt ?? null,
        allowedIps: normalizeAllowedIpRules(allowedIps),
      };

      await credentialStore.setClientRecord(clientId, record);
    },
    getSecretHash: async (clientId: string): Promise<string | null> => {
      assertClientId(clientId);
      return credentialStore.getSecretHash(clientId);
    },
  };

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

  const handleInternalManagementRequest = async (
    input: HmacInternalManagementRequestInput,
  ): Promise<HmacInternalManagementRequestResult> => {
    if (!internalManagementRoute) {
      return {
        handled: false,
        status: 404,
        body: {},
        verifiedAuth: null,
      };
    }

    const normalizedFullPath = normalizePath(input.path);
    const routePath = normalizeRoutePath(normalizedFullPath);
    if (routePath !== internalManagementRoute) {
      return {
        handled: false,
        status: 404,
        body: {},
        verifiedAuth: null,
      };
    }

    const method = input.method.toUpperCase();
    if (!["GET", "POST", "PUT", "DELETE"].includes(method)) {
      return {
        handled: true,
        status: 405,
        body: {
          error: "METHOD_NOT_ALLOWED",
          message: "Supported methods are GET, POST, PUT, DELETE",
        },
        verifiedAuth: null,
      };
    }

    const knownClients = await clients.listClientIds();
    const authRequired = knownClients.length > 0;

    let verifiedAuth: VerifiedHttpRequest | null = null;
    if (authRequired) {
      try {
        verifiedAuth = await verifyHttpSignature({
          method,
          path: normalizedFullPath,
          headers: input.headers,
          rawBody: input.rawBody,
          now: input.now,
          maxSkewMs: input.maxSkewMs,
          onBadSignature: input.onBadSignature,
          metadata: input.metadata,
        });
      } catch {
        return forbiddenInternal("Internal HMAC management authentication failed");
      }
    }

    if (method === "GET") {
      return {
        handled: true,
        status: 200,
        body: {
          ok: true,
          namespace,
          route: internalManagementRoute,
          authRequired,
          clientsCount: knownClients.length,
          authenticatedBy: verifiedAuth?.clientId ?? null,
        },
        verifiedAuth,
      };
    }

    const payload = parseInternalBody(input.rawBody);
    const payloadClientId = normalizeInternalClientId(payload.clientId);
    if (!payloadClientId) {
      return forbiddenInternal("clientId is required");
    }

    if (method === "DELETE") {
      const existing = await clients.get(payloadClientId);
      if (!existing) {
        return forbiddenInternal("Client does not exist");
      }

      await clients.delete(payloadClientId);
      return {
        handled: true,
        status: 201,
        body: {
          ok: true,
          operation: "delete",
          clientId: payloadClientId,
        },
        verifiedAuth,
      };
    }

    let expiresAt: number | null | undefined;
    try {
      expiresAt = parseExpiresAtFromPayload(payload);
    } catch {
      return forbiddenInternal("expiresAt must be a valid timestamp");
    }

    let allowedIps: string[] | undefined;
    try {
      allowedIps = parseAllowedIpsFromPayload(payload);
    } catch {
      return forbiddenInternal("allowedIps must be an array of valid IP/CIDR strings");
    }

    const secret = typeof payload.secret === "string" ? payload.secret : undefined;
    const secretHash = typeof payload.secretHash === "string" ? payload.secretHash : undefined;

    if (!secret && !secretHash) {
      return forbiddenInternal("secret or secretHash is required");
    }

    const existing = await clients.get(payloadClientId);

    if (method === "POST") {
      if (existing) {
        return forbiddenInternal("Client already exists");
      }

      if (secret) {
        await clients.setSecret(payloadClientId, secret, expiresAt, allowedIps);
      } else {
        await clients.setSecretHash(payloadClientId, secretHash as string, expiresAt, allowedIps);
      }

      return {
        handled: true,
        status: 201,
        body: {
          ok: true,
          operation: "create",
          clientId: payloadClientId,
        },
        verifiedAuth,
      };
    }

    if (!existing) {
      return forbiddenInternal("Client does not exist");
    }

    if (secret) {
      await clients.setSecret(payloadClientId, secret, expiresAt, allowedIps);
    } else {
      await clients.setSecretHash(payloadClientId, secretHash as string, expiresAt, allowedIps);
    }

    return {
      handled: true,
      status: 201,
      body: {
        ok: true,
        operation: "update",
        clientId: payloadClientId,
      },
      verifiedAuth,
    };
  };

  const internalManagementMiddlewareFactory = (middlewareOptions?: {
    attachAuthTo?: string;
    maxSkewMs?: number;
    onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
    onBadSignature?: OnBadHttpSignature;
  }) => {
    const attachAuthTo = middlewareOptions?.attachAuthTo ?? "hmacAuth";

    return async (req: any, res: any, next: (error?: unknown) => void) => {
      try {
        const result = await handleInternalManagementRequest({
          method: req.method,
          path: req.originalUrl ?? req.url,
          headers: req.headers,
          rawBody: req.rawBody ?? req.body,
          now: Date.now(),
          maxSkewMs: middlewareOptions?.maxSkewMs ?? maxSkewMs,
          onBadSignature: middlewareOptions?.onBadSignature ?? options.onBadSignature,
          metadata: {
            ip: req?.ip,
            ips: req?.ips,
            remoteAddress: req?.socket?.remoteAddress,
            forwardedFor: req?.headers?.["x-forwarded-for"],
          },
        });

        if (!result.handled) {
          next();
          return;
        }

        if (result.verifiedAuth) {
          req[attachAuthTo] = result.verifiedAuth;
        }

        if (typeof res?.status === "function" && typeof res?.json === "function") {
          res.status(result.status).json(result.body);
          return;
        }

        next();
      } catch (error) {
        const hmacError = toHmacError(error);
        if (middlewareOptions?.onError) {
          middlewareOptions.onError(hmacError, req, res, next);
          return;
        }

        if (typeof res?.status === "function" && typeof res?.json === "function") {
          res.status(hmacError.status).json({
            error: hmacError.code,
            message: hmacError.message,
          });
          return;
        }

        next(hmacError);
      }
    };
  };

  const propagateClientToApis = async (propagateOptions: PropagateHmacClientOptions): Promise<PropagateHmacClientResult[]> => {
    if (!internalManagementRoute) {
      throw new HmacAuthError("INTERNAL_ROUTE_DISABLED", "internalManagementRoute is not configured for this API instance", 400);
    }

    const fetchImpl = propagateOptions.apiFetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new Error("No fetch implementation available");
    }

    if (!Array.isArray(propagateOptions.targets) || propagateOptions.targets.length === 0) {
      throw new Error("targets must contain at least one API URL");
    }

    const operation = propagateOptions.operation;
    const method = operation === "health" ? "GET" : operation === "create" ? "POST" : operation === "update" ? "PUT" : "DELETE";

    if (operation !== "health") {
      assertClientId(propagateOptions.clientId ?? "");
      if (operation !== "delete" && !propagateOptions.secret && !propagateOptions.secretHash) {
        throw new Error("secret or secretHash is required for create/update propagation");
      }
      if ((operation === "create" || operation === "update") && !Array.isArray(propagateOptions.allowedIps)) {
        throw new Error("allowedIps array is required for create/update propagation");
      }
    }

    const payload: Record<string, unknown> = {};
    if (operation !== "health") {
      payload.clientId = propagateOptions.clientId;
      if (propagateOptions.secret !== undefined) {
        payload.secret = propagateOptions.secret;
      }
      if (propagateOptions.secretHash !== undefined) {
        payload.secretHash = propagateOptions.secretHash;
      }
      if (propagateOptions.expiresAt !== undefined) {
        payload.expiresAt = normalizeExpiresAt(propagateOptions.expiresAt);
      }
      if (propagateOptions.allowedIps !== undefined) {
        payload.allowedIps = normalizeAllowedIpRules(propagateOptions.allowedIps);
      }
    }

    const results: PropagateHmacClientResult[] = [];

    for (const target of propagateOptions.targets) {
      try {
        const targetUrl = resolveTargetInternalUrl(target, internalManagementRoute);
        const headers = new Headers(propagateOptions.headers);
        if (method !== "GET") {
          headers.set("content-type", "application/json");
        }

        const response = await fetchImpl(targetUrl, {
          method,
          headers,
          body: method === "GET" ? undefined : JSON.stringify(payload),
        });

        const body = await parseFetchResponseBody(response);
        const accepted = method === "GET" ? response.status === 200 : response.status === 201;

        results.push({
          target,
          url: targetUrl,
          operation,
          status: response.status,
          accepted,
          body,
        });
      } catch (error) {
        results.push({
          target,
          url: target,
          operation,
          status: 0,
          accepted: false,
          body: null,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return results;
  };

  return {
    redis: options.redis,
    namespace,
    maxSkewMs,
    secretToken,
    internalManagementRoute,
    verifyHttpRequest,
    verifyHttpSignature,
    createHttpMiddleware: httpMiddlewareFactory,
    createExpressHttpMiddleware: httpMiddlewareFactory,
    handleInternalManagementRequest,
    createInternalManagementMiddleware: internalManagementMiddlewareFactory,
    createExpressInternalManagementMiddleware: internalManagementMiddlewareFactory,
    propagateClientToApis,
    createHttpSignedFetchClient: (clientOptions) =>
      createHttpSignedFetchClient({
        ...clientOptions,
        hashToken: clientOptions.hashToken ?? secretToken,
      }),
    clients,
  };
}
