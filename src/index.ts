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
export { initializeHmacMessageAuth, type InitializedHmacMessageAuth } from "./message/init.js";
export { buildMessageSigningPayload, signMessage, verifyMessage } from "./message/signature.js";

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
  BadHttpSignatureEvent,
  CreateHmacClientOptions,
  HmacClientCredential,
  HmacClientCredentialWithSecret,
  InitializeHmacHttpAuthOptions,
  InitializeHmacMessageAuthOptions,
  OnBadHttpSignature,
  RegenerateHmacSecretOptions,
  SignedMessage,
  SignInput,
  SignMessageInput,
  SignMessageWithRedisInput,
  VerifiedHttpRequest,
  VerifiedRequest,
  VerifyHttpSignatureInput,
  VerifyHttpWithRedisInput,
  VerifyMessageInput,
  VerifyMessageWithRedisInput,
} from "./types.js";
