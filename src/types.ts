import type { RedisLikeClient } from "./stores/redis.js";

export interface SignInput {
  method: string;
  path: string;
  timestamp: number;
  nonce: string;
  body: string;
  secret: string;
}

export interface VerifyRequestInput {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  redis: RedisLikeClient;
  namespace?: string;
  maxSkewMs?: number;
  now?: number;
}

export interface VerifiedRequest {
  clientId: string;
  timestamp: number;
  nonce: string;
  signature: string;
}

export interface InitializeHmacAuthOptions {
  redis: RedisLikeClient;
  namespace?: string;
  maxSkewMs?: number;
  defaultSecretLengthBytes?: number;
}

export interface VerifyHmacWithRedisInput {
  method: string;
  path: string;
  headers: Record<string, string | string[] | undefined>;
  rawBody?: unknown;
  now?: number;
  maxSkewMs?: number;
}

export interface HmacClientCredential {
  clientId: string;
  secretHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
}

export interface HmacClientCredentialWithSecret extends HmacClientCredential {
  secret: string;
}

export interface CreateHmacClientOptions {
  clientId: string;
  expiresAt?: number | Date | null;
  secretLengthBytes?: number;
  plainSecret?: string;
}

export interface RegenerateHmacSecretOptions {
  expiresAt?: number | Date | null;
  secretLengthBytes?: number;
  preserveExpiresAt?: boolean;
}
