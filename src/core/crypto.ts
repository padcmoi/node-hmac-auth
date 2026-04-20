import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import type { SignInput } from "./types.js";
import { normalizePath } from "./utils.js";

export function hashClientSecret(secret: string, secretToken?: string): string {
  if (secretToken != null && secretToken !== "") {
    return createHmac("sha256", secretToken).update(secret).digest("hex");
  }
  return createHash("sha256").update(secret).digest("hex");
}

export function hashBody(body: string): string {
  return createHash("sha256").update(body).digest("hex");
}

export function buildSigningPayload(input: Omit<SignInput, "secret">): string {
  const method = input.method.toUpperCase();
  const path = normalizePath(input.path);
  const bodyDigest = hashBody(input.body);
  return `${method}\n${path}\n${input.timestamp}\n${input.nonce}\n${bodyDigest}`;
}

export function signRequest(input: SignInput): string {
  const payload = buildSigningPayload(input);
  return createHmac("sha256", input.secret).update(payload).digest("hex");
}

export function safeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  const aBuffer = Buffer.from(a, "hex");
  const bBuffer = Buffer.from(b, "hex");
  if (aBuffer.length !== bBuffer.length) {
    return false;
  }
  return timingSafeEqual(aBuffer, bBuffer);
}
