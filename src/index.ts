export { buildSigningPayload, hashBody, hashClientSecret, safeEqualHex, signRequest } from "./core/crypto.js";
export { HmacAuthError } from "./core/errors.js";

export {
  buildHttpSignedHeaders,
  createHttpSignedFetchClient,
  signedHttpFetch,
  type BuildHttpSignedHeadersInput,
  type CreateHttpSignedFetchClientOptions,
  type SignedHttpFetchClientCallOptions,
  type SignedHttpFetchOptions,
} from "./http/client/signed-fetch.js";
export { initializeHmacHttpAuth, type InitializedHmacHttpAuth } from "./http/init.js";
export { initializeHmacMessageAuth, type InitializedHmacMessageAuth } from "./message/init.js";
export { buildMessageSigningPayload, signMessage, verifyMessage } from "./message/signature.js";
export { createHmacRuntime, type HmacRuntime } from "./runtime/create-runtime.js";

export { captureRawBody, createExpressHttpHmacMiddleware, createHttpHmacMiddleware } from "./http/server/express.js";
export { verifyHttpSignature } from "./http/server/verify.js";

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
  HmacInternalManagementRequestInput,
  HmacInternalManagementRequestResult,
  HmacInternalPropagationOperation,
  InitializeHmacHttpAuthOptions,
  InitializeHmacMessageAuthOptions,
  OnBadHttpSignature,
  PropagateHmacClientOptions,
  PropagateHmacClientResult,
  PropagateServiceCreateOptions,
  PropagateServiceDeleteOptions,
  PropagateServiceHealthOptions,
  PropagateServiceUpdateOptions,
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
} from "./core/types.js";
