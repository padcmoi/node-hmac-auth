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
