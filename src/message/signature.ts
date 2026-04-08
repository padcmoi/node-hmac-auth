import { createHmac } from "node:crypto";
import { hashBody, hashClientSecret, safeEqualHex } from "../hmac.js";
import type { SignMessageInput, SignedMessage, VerifyMessageInput } from "../types.js";
import { toMessageString } from "../utils.js";

function normalizeClientId(clientId: string): string {
  const normalized = clientId.trim();
  if (!normalized) {
    throw new Error("clientId cannot be empty");
  }
  return normalized;
}

function assertSecret(secret: string): void {
  if (!secret || !secret.trim()) {
    throw new Error("secret cannot be empty");
  }
}

export function buildMessageSigningPayload(input: { clientId: string; messageHash: string }): string {
  return `${normalizeClientId(input.clientId)}\n${input.messageHash}`;
}

export function signMessage(input: SignMessageInput): SignedMessage {
  const clientId = normalizeClientId(input.clientId);
  assertSecret(input.secret);

  const messageHash = hashBody(toMessageString(input.message));
  const signingSecret = input.secretIsHashed ? input.secret : hashClientSecret(input.secret, input.hashToken);
  const signature = createHmac("sha256", signingSecret)
    .update(buildMessageSigningPayload({ clientId, messageHash }))
    .digest("hex");

  return {
    clientId,
    messageHash,
    signature,
  };
}

export function verifyMessage(input: VerifyMessageInput): boolean {
  const signed = signMessage(input);
  return safeEqualHex(signed.signature, input.signature);
}
