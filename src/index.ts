export { HmacAuthError } from "./errors.js";
export { buildSigningPayload, hashBody, hashClientSecret, safeEqualHex, signRequest } from "./hmac.js";

export {
  buildSignedHeaders,
  createSignedFetchClient,
  signedFetch,
  type CreateSignedFetchClientOptions,
  type SignedFetchClientCallOptions,
} from "./client/signed-fetch.js";
export { initializeHmacAuth, type InitializedHmacAuth } from "./init.js";

export { captureRawBody, createExpressHmacMiddleware, createHmacMiddleware } from "./server/express.js";
export { verifyHmacRequest } from "./server/verify.js";

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
  InitializeHmacAuthOptions,
  RegenerateHmacSecretOptions,
  SignInput,
  VerifiedRequest,
  VerifyHmacWithRedisInput,
  VerifyRequestInput,
} from "./types.js";
