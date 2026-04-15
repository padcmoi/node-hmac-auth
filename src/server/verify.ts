import { HmacAuthError } from "../errors.js";
import { safeEqualHex, signRequest } from "../hmac.js";
import { RedisCredentialStore, RedisNonceStore, assertRedisClient, resolveNamespace } from "../stores/redis.js";
import type { BadHttpSignatureEvent, VerifiedHttpRequest, VerifyHttpSignatureInput } from "../types.js";
import { getHeader, normalizePath, toBodyString } from "../utils.js";

const DEFAULT_MAX_SKEW_MS = 5 * 60 * 1000;

async function notifyBadSignature(event: BadHttpSignatureEvent, input: VerifyHttpSignatureInput): Promise<void> {
  if (!input.onBadSignature) {
    return;
  }

  try {
    await input.onBadSignature(event);
  } catch {
    // Never break auth flow if callback fails.
  }
}

export async function verifyHttpSignature(input: VerifyHttpSignatureInput): Promise<VerifiedHttpRequest> {
  assertRedisClient(input.redis);

  const namespace = resolveNamespace(input.namespace);
  const credentialStore = new RedisCredentialStore(input.redis, namespace);
  const nonceStore = new RedisNonceStore(input.redis, namespace);

  const clientId = getHeader(input.headers, "x-client-id")?.trim();
  if (!clientId) {
    throw new HmacAuthError("MISSING_CLIENT_ID", "Missing header x-client-id");
  }

  const signature = getHeader(input.headers, "x-signature");
  if (!signature) {
    throw new HmacAuthError("MISSING_SIGNATURE", "Missing header x-signature");
  }

  const timestampRaw = getHeader(input.headers, "x-timestamp");
  if (!timestampRaw) {
    throw new HmacAuthError("MISSING_TIMESTAMP", "Missing header x-timestamp");
  }

  const nonce = getHeader(input.headers, "x-nonce");
  if (!nonce) {
    throw new HmacAuthError("MISSING_NONCE", "Missing header x-nonce");
  }

  const timestamp = Number(timestampRaw);
  if (!Number.isFinite(timestamp)) {
    throw new HmacAuthError("INVALID_TIMESTAMP", "x-timestamp must be a number");
  }

  const now = input.now ?? Date.now();
  const maxSkewMs = input.maxSkewMs ?? DEFAULT_MAX_SKEW_MS;
  if (Math.abs(now - timestamp) > maxSkewMs) {
    throw new HmacAuthError("TIMESTAMP_SKEW", `Request timestamp skew is too large (> ${maxSkewMs}ms)`);
  }

  const clientRecord = await credentialStore.getClientRecord(clientId);
  if (!clientRecord) {
    throw new HmacAuthError("UNKNOWN_CLIENT", "Unknown client id");
  }

  if (clientRecord.expiresAt != null && now > clientRecord.expiresAt) {
    throw new HmacAuthError("CLIENT_EXPIRED", "Client secret has expired");
  }

  const normalizedPath = normalizePath(input.path);
  const expectedSignature = signRequest({
    method: input.method,
    path: normalizedPath,
    timestamp,
    nonce,
    body: toBodyString(input.rawBody),
    secret: clientRecord.secretHash,
  });

  if (!safeEqualHex(expectedSignature, signature)) {
    await notifyBadSignature(
      {
        clientId,
        method: input.method,
        path: normalizedPath,
        timestamp,
        nonce,
        receivedSignature: signature,
        expectedSignature,
        headers: input.headers,
        rawBody: input.rawBody,
        metadata: input.metadata,
      },
      input,
    );

    throw new HmacAuthError("BAD_SIGNATURE", "Invalid HMAC signature");
  }

  const nonceKey = `${clientId}:${nonce}:${timestamp}`;
  const ok = await nonceStore.consume(nonceKey, Math.max(1, Math.ceil(maxSkewMs / 1000)));
  if (!ok) {
    throw new HmacAuthError("REPLAYED_NONCE", "Nonce already used");
  }

  return { clientId, timestamp, nonce, signature };
}
