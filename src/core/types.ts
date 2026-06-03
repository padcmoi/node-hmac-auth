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
  /**
   * v1.3.0: when set, requests matched against a credential whose stored
   * `purpose` is `"propagation-only"` are rejected with HTTP 403
   * `PROPAGATION_ONLY_FORBIDDEN` unless `path` equals this exact route. Used
   * by `initializeHmacHttpAuth` to enforce the propagation-key cantonment
   * documented in `docs/wire-contract.md`. When omitted, no purpose check is
   * applied and the credential behaves as `purpose: "any"`.
   */
  internalManagementRoute?: string;
  /**
   * v1.4.0: passed through by `initializeHmacHttpAuth` so direct callers of
   * `verifyHttpSignature` use the same enforcement layer. Defaults to
   * `DEFAULT_PROPAGATION_KEY_CLIENT_ID` when omitted, never to "no lock".
   */
  requireBootstrapClientId?: string;
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
   * v1.4.0: the bootstrap lock is ALWAYS active. This field lets a consumer
   * override the canonical name (`DEFAULT_PROPAGATION_KEY_CLIENT_ID = "self_propagation_signer"`)
   * when they intentionally want their store isolated from the federation:
   * because the management lib only pushes the canonical name, an API that
   * locks behind a different value refuses every credential the federation
   * tries to deliver. Default (omit the field) = the federation-friendly
   * canonical name.
   */
  requireBootstrapClientId?: string;
  /**
   * Optional bridge to the message credential store, used by `propagateClientToApis`
   * when `targetStore: "message"` is requested. Required on both sides:
   *   - source: enables the local Redis fallback to read the message-store secretHash.
   *   - target: lets `handleInternalManagementRequest` route `kind: "message"`
   *             payloads to the message store instead of the HTTP store.
   * When omitted, the lib behaves exactly like 1.0.x (HTTP-only propagation).
   */
  messageAuth?: HmacMessageAuthBridge;
  /**
   * v1.2.0: TTL (seconds) of the `credentials-backup:<clientId>` Redis key
   * created automatically when a credential is rotated with
   * `fromDbSeed: true`. Defaults to 600s (10 min). The backup is used by
   * `clients.revert(clientId)` and by `propagateClientToApis({ operation: "revert" })`
   * to restore the previous secretHash on partial-failure scenarios. Has no
   * effect for credentials whose `fromDbSeed` is false (no backup is written).
   */
  dbSeedBackupTtlSeconds?: number;
}

/**
 * Minimal view of an InitializedHmacMessageAuth used as a bridge by
 * initializeHmacHttpAuth. Kept structural to avoid an import cycle: any object
 * exposing this shape works (typically the result of initializeHmacMessageAuth).
 */
export interface HmacCredentialWriteOptions {
  fromDbSeed?: boolean;
  /**
   * v1.3.0: tag the credential with a usage scope. Default `undefined`
   * keeps 1.2.x semantics ("any" implicit). When set to "propagation-only"
   * on a credential, every signed request matched against it is rejected
   * unless it targets the configured `internalManagementRoute`.
   */
  purpose?: HmacCredentialPurpose;
}

/**
 * v1.3.0: usage-scope marker stored alongside a credential. Optional on
 * every public surface to preserve 1.2.x byte-identical behavior when the
 * field is omitted.
 *   - "any"               : default. The credential authenticates any
 *                           signed request (1.2.x behavior).
 *   - "propagation-only"  : the credential is only valid on the configured
 *                           `internalManagementRoute`. Any other path
 *                           rejected with HTTP 403 `PROPAGATION_ONLY_FORBIDDEN`.
 *                           Message-store equivalents (signMessage /
 *                           verifyMessage) refuse the credential outright.
 */
export type HmacCredentialPurpose = "any" | "propagation-only";

export interface HmacCredentialRevertResult {
  reverted: boolean;
  restoredSecretHash?: string;
}

export interface HmacMessageAuthBridge {
  readonly namespace: string;
  clients: {
    get: (clientId: string) => Promise<HmacClientCredential | null>;
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
    revert: (clientId: string) => Promise<HmacCredentialRevertResult>;
    delete: (clientId: string) => Promise<void>;
    listClientIds: () => Promise<string[]>;
  };
}

export interface InitializeHmacMessageAuthOptions {
  redis: RedisLikeClient;
  namespace?: string;
  defaultSecretLengthBytes?: number;
  secretToken?: string;
  /**
   * v1.2.0: TTL (seconds) of the `credentials-backup:<clientId>` Redis key
   * for the message credential store. Same semantics as the HTTP variant.
   * Default 600s.
   */
  dbSeedBackupTtlSeconds?: number;
  /**
   * v1.4.0: same federation-isolation override as the HTTP track. Defaults
   * to `DEFAULT_PROPAGATION_KEY_CLIENT_ID` when omitted.
   */
  requireBootstrapClientId?: string;
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
  /**
   * v1.4.0: lets the `auth.verifyHttpSignature` caller override the
   * federation-default bootstrap clientId for this specific verify call.
   * Omit to inherit the value resolved by `initializeHmacHttpAuth`.
   */
  requireBootstrapClientId?: string;
}

export interface HmacClientCredential {
  clientId: string;
  secretHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  allowedIps: string[];
  /**
   * v1.2.0 origin marker. Optional on the public type to preserve
   * backward compatibility: consumers built before 1.2.0 that mock or
   * construct an `HmacClientCredential` literal without this field stay
   * type-valid. The lib always populates the field on objects it returns
   * (false by default, true when stored as such on the record).
   */
  fromDbSeed?: boolean;
  /**
   * v1.3.0 usage-scope marker. Optional on the public type to keep
   * 1.0.x/1.1.x/1.2.x literals type-valid. The lib populates the field
   * when reading a record where it was stored ("any" implicit otherwise).
   */
  purpose?: HmacCredentialPurpose;
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
  /**
   * v1.2.0: tag the credential as DB-seed-originated at creation time. The
   * record stores the flag so any subsequent setSecret/setSecretHash that
   * passes `fromDbSeed: true` writes a TTL backup of the previous hash and a
   * `clients.revert(clientId)` becomes meaningful. Default `false` keeps
   * 1.0.x/1.1.x behavior.
   */
  fromDbSeed?: boolean;
  /**
   * v1.3.0: tag the credential with a usage scope at creation time. The
   * record stores the flag so subsequent `verifyHttpSignature` calls
   * enforce the cantonment without re-reading any external source.
   * Default `undefined` keeps 1.0.x/1.1.x/1.2.x record shape unchanged.
   */
  purpose?: HmacCredentialPurpose;
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

export type HmacInternalPropagationOperation = "health" | "create" | "update" | "delete" | "revert";

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
  /**
   * Marks the propagated credential as originating from a dynamic DB-seed
   * pipeline. Default `false`. When `true`, the wire payload carries the flag
   * and the remote target stores it alongside the credential record. Passive
   * marker; reserved for future rotation/backup logic on db-seeded entries.
   */
  fromDbSeed?: boolean;
  /**
   * v1.3.0: propagate a usage-scope marker to the remote credential record.
   * Emitted on the wire only when explicitly set (omitted = legacy 1.0.x
   * payload bytes). The remote stores the value and enforces it on every
   * subsequent signature verification.
   */
  purpose?: HmacCredentialPurpose;
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
