export { HmacAuthError } from "./errors.js";
export { buildSigningPayload, hashBody, hashClientSecret, safeEqualHex, signRequest } from "./hmac.js";

export {
  buildHttpSignedHeaders,
  createHttpSignedFetchClient,
  signedHttpFetch,
  type BuildHttpSignedHeadersInput,
  type CreateHttpSignedFetchClientOptions,
  type SignedHttpFetchClientCallOptions,
  type SignedHttpFetchOptions,
} from "./client/signed-fetch.js";
export { initializeHmacHttpAuth, type InitializedHmacHttpAuth } from "./init.js";

export { captureRawBody, createExpressHttpHmacMiddleware, createHttpHmacMiddleware } from "./server/express.js";
export { verifyHttpSignature } from "./server/verify.js";

export {
  buildRedisNamespaceKeys,
  RedisCredentialStore,
  RedisNonceStore,
  resolveNamespace,
  type RedisLikeClient,
} from "./stores/redis.js";

export type {
  CreateHmacClientOptions,
  HmacClientCredential,
  HmacClientCredentialWithSecret,
  InitializeHmacHttpAuthOptions,
  RegenerateHmacSecretOptions,
  SignInput,
  VerifiedHttpRequest,
  VerifiedRequest,
  VerifyHttpSignatureInput,
  VerifyHttpWithRedisInput,
} from "./types.js";
