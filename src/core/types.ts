import type { SignedHttpFetchClientCallOptions } from "../http/client/signed-fetch.js";
import type { RedisLikeClient } from "../stores/redis.js";

export interface BadHttpSignatureEvent {
  clientId: string;
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  receivedSignature: string;
  expectedSignature: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  metadata?: unknown;
}

export type OnBadHttpSignature = (event: BadHttpSignatureEvent) => void | Promise<void>;

export interface SignInput {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
  secret: string;
}

export interface VerifyHttpSignatureInput {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  redis: RedisLikeClient;
  namespace?: string;
  maxSkewMs?: number;
  now?: number;
  onBadSignature?: OnBadHttpSignature;
  metadata?: unknown;
}

export interface VerifiedRequest {
  clientId: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export type VerifiedHttpRequest = VerifiedRequest;

export interface InitializeHmacHttpAuthOptions {
  redis: RedisLikeClient;
  namespace?: string;
  maxSkewMs?: number;
  defaultSecretLengthBytes?: number;
  secretToken?: string;
  onBadSignature?: OnBadHttpSignature;
  internalManagementRoute?: string;
  /**
   * Optional bridge to the message credential store, used by `propagateClientToApis`
   * when `targetStore: "message"` is requested. Required on both sides:
   *   - source: enables the local Redis fallback to read the message-store secretHash.
   *   - target: lets `handleInternalManagementRequest` route `kind: "message"`
   *             payloads to the message store instead of the HTTP store.
   * When omitted, the lib behaves exactly like 1.0.x (HTTP-only propagation).
   */
  messageAuth?: HmacMessageAuthBridge;
}

/**
 * Minimal view of an InitializedHmacMessageAuth used as a bridge by
 * initializeHmacHttpAuth. Kept structural to avoid an import cycle: any object
 * exposing this shape works (typically the result of initializeHmacMessageAuth).
 */
export interface HmacMessageAuthBridge {
  readonly namespace: string;
  clients: {
    get: (clientId: string) => Promise<HmacClientCredential | null>;
    setSecret: (clientId: string, secret: string, expiresAt?: number | Date | null, allowedIps?: string[]) => Promise<void>;
    setSecretHash: (
      clientId: string,
      secretHash: string,
      expiresAt?: number | Date | null,
      allowedIps?: string[]
    ) => Promise<void>;
    delete: (clientId: string) => Promise<void>;
    listClientIds: () => Promise<string[]>;
  };
}

export interface InitializeHmacMessageAuthOptions {
  redis: RedisLikeClient;
  namespace?: string;
  defaultSecretLengthBytes?: number;
  secretToken?: string;
}

export interface VerifyHttpWithRedisInput {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  now?: number;
  maxSkewMs?: number;
  onBadSignature?: OnBadHttpSignature;
  metadata?: unknown;
}

export interface HmacClientCredential {
  clientId: string;
  secretHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  allowedIps: string[];
}

export interface HmacClientCredentialWithSecret extends HmacClientCredential {
  secret: string;
}

export interface CreateHmacClientOptions {
  clientId: string;
  expiresAt?: number | Date | null;
  secretLengthBytes?: number;
  plainSecret?: string;
  allowedIps?: string[];
}

export interface RegenerateHmacSecretOptions {
  expiresAt?: number | Date | null;
  secretLengthBytes?: number;
  plainSecret?: string;
  preserveExpiresAt?: boolean;
  allowedIps?: string[];
}

export interface SignMessageInput {
  clientId: string;
  message: unknown;
  secret: string;
  secretIsHashed?: boolean;
  hashToken?: string;
}

export interface SignedMessage {
  clientId: string;
  messageHash: string;
  signature: string;
}

export interface VerifyMessageInput extends SignMessageInput {
  signature: string;
}

export interface SignMessageWithRedisInput {
  clientId: string;
  message: unknown;
}

export interface VerifyMessageWithRedisInput extends SignMessageWithRedisInput {
  signature: string;
}

export interface HmacInternalManagementRequestInput {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  now?: number;
  maxSkewMs?: number;
  onBadSignature?: OnBadHttpSignature;
  metadata?: unknown;
}

export interface HmacInternalManagementRequestResult {
  handled: boolean;
  status: number;
  body: Record<string, unknown>;
  verifiedAuth?: VerifiedHttpRequest | null;
}

export type HmacInternalPropagationOperation = "health" | "create" | "update" | "delete";

/**
 * Which credential store the propagation targets on the remote API.
 *   - "http"    (default): write to the HTTP credential store (same as 1.0.x)
 *   - "message"          : write to the message credential store via the same
 *                          internal-management route. Requires `messageAuth`
 *                          to be passed to `initializeHmacHttpAuth` on BOTH
 *                          source (Redis fallback) and target (handler write).
 */
export type HmacPropagateTargetStore = "http" | "message";

export type PropagateApiFetch =
  | ((url: string, options?: SignedHttpFetchClientCallOptions) => Promise<Response>)
  | ((url: string, options: RequestInit) => Promise<Response>);

export interface PropagateHmacClientOptions {
  operation: HmacInternalPropagationOperation;
  targets: string[];
  apiFetch?: PropagateApiFetch;
  headers?: HeadersInit;
  clientId?: string;
  secret?: string;
  secretHash?: string;
  expiresAt?: number | Date | null;
  allowedIps?: string[];
  /** Defaults to "http" - 1.0.x behavior. */
  targetStore?: HmacPropagateTargetStore;
}

export interface PropagateHmacClientResult {
  target: string;
  url: string;
  operation: HmacInternalPropagationOperation;
  status: number;
  accepted: boolean;
  body: unknown;
  error?: string;
}

export type PropagateServiceCreateOptions = {
  propagateClientId: CreateHmacClientOptions["clientId"];
  useClientId?: CreateHmacClientOptions["clientId"];
  targetApis: PropagateHmacClientOptions["targets"];
  plainSecret: NonNullable<PropagateHmacClientOptions["secret"]>;
  allowedIps: NonNullable<PropagateHmacClientOptions["allowedIps"]>;
};

export type PropagateServiceUpdateOptions = {
  propagateClientId: CreateHmacClientOptions["clientId"];
  useClientId?: CreateHmacClientOptions["clientId"];
  targetApis: PropagateHmacClientOptions["targets"];
  plainSecret: NonNullable<PropagateHmacClientOptions["secret"]>;
  allowedIps: NonNullable<PropagateHmacClientOptions["allowedIps"]>;
};

export type PropagateServiceDeleteOptions = {
  propagateClientId: CreateHmacClientOptions["clientId"];
  useClientId?: CreateHmacClientOptions["clientId"];
  targetApis: PropagateHmacClientOptions["targets"];
};

export type PropagateServiceHealthOptions = {
  useClientId: CreateHmacClientOptions["clientId"];
  targetApis: PropagateHmacClientOptions["targets"];
};
