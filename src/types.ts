import type { RedisLikeClient } from "./stores/redis.js";

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
  plainSecret?: string;
  preserveExpiresAt?: boolean;
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
