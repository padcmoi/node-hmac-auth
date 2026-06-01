import { randomBytes } from "node:crypto";
import { HmacAuthError } from "../core/errors.js";
import { normalizeAllowedIpRules } from "../core/ip.js";
import type { HmacClientCredential, HmacInternalManagementRequestResult } from "../core/types.js";
import { normalizePath, toBodyString } from "../core/utils.js";
import type { StoredClientCredentialRecord } from "../stores/redis.js";

/**
 * Shared helpers used across the HTTP store factory, the internal-management
 * handler and the propagation pipeline. Kept private to `src/http/*` so the
 * public package surface (`src/index.ts`) does not expand.
 */

export function assertClientId(clientId: string): void {
  if (!clientId || !clientId.trim()) {
    throw new HmacAuthError("MISSING_CLIENT_ID", "clientId cannot be empty", 400);
  }
}

export function normalizeSecretHash(secretHash: string): string {
  return secretHash.trim().toLowerCase();
}

export function normalizeExpiresAt(value?: number | Date | null): number | null {
  if (value == null) {
    return null;
  }

  const expiresAt = value instanceof Date ? value.getTime() : Number(value);
  if (!Number.isFinite(expiresAt)) {
    throw new Error("expiresAt must be a valid timestamp or Date");
  }
  return expiresAt;
}

export function assertSecretLength(secretLengthBytes: number): void {
  if (!Number.isInteger(secretLengthBytes) || secretLengthBytes < 16 || secretLengthBytes > 128) {
    throw new Error("secretLengthBytes must be an integer between 16 and 128");
  }
}

export function assertPlainSecret(secret: string): void {
  if (!secret || !secret.trim()) {
    throw new Error("plainSecret cannot be empty");
  }
}

export function mapCredential(clientId: string, record: StoredClientCredentialRecord): HmacClientCredential {
  return {
    clientId,
    secretHash: record.secretHash,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    expiresAt: record.expiresAt,
    allowedIps: record.allowedIps,
    fromDbSeed: record.fromDbSeed,
    purpose: record.purpose,
  };
}

export function generateSecret(secretLengthBytes: number): string {
  assertSecretLength(secretLengthBytes);
  return randomBytes(secretLengthBytes).toString("hex");
}

export function parseInternalBody(rawBody: unknown): Record<string, unknown> {
  if (rawBody == null) {
    return {};
  }

  if (typeof rawBody === "object" && !Buffer.isBuffer(rawBody) && !(rawBody instanceof Uint8Array)) {
    return rawBody as Record<string, unknown>;
  }

  const asString = toBodyString(rawBody).trim();
  if (!asString) {
    return {};
  }

  try {
    const parsed = JSON.parse(asString) as unknown;
    if (parsed && typeof parsed === "object") {
      return parsed as Record<string, unknown>;
    }
    return {};
  } catch {
    return {};
  }
}

export function normalizeRoutePath(pathOrUrl: string): string {
  const normalized = normalizePath(pathOrUrl);
  const [pathOnly] = normalized.split("?");
  if (!pathOnly || pathOnly === "") {
    return "/";
  }
  if (pathOnly.length > 1 && pathOnly.endsWith("/")) {
    return pathOnly.slice(0, -1);
  }
  return pathOnly;
}

export function parseExpiresAtFromPayload(payload: Record<string, unknown>): number | null | undefined {
  if (!("expiresAt" in payload)) {
    return undefined;
  }

  const raw = payload.expiresAt;
  if (raw == null) {
    return null;
  }

  const numeric = Number(raw);
  if (!Number.isFinite(numeric)) {
    throw new Error("expiresAt must be a valid timestamp");
  }
  return numeric;
}

export function parsePurposeFromPayload(payload: Record<string, unknown>): "any" | "propagation-only" | undefined {
  if (!("purpose" in payload)) {
    return undefined;
  }
  const raw = payload.purpose;
  if (raw === "any" || raw === "propagation-only") {
    return raw;
  }
  // Unknown / missing value -> treat as no opinion (consistent with how
  // 1.0.x/1.1.x/1.2.x targets ignore the field entirely).
  return undefined;
}

export function parseAllowedIpsFromPayload(payload: Record<string, unknown>): string[] | undefined {
  if (!("allowedIps" in payload)) {
    return undefined;
  }

  if (payload.allowedIps == null) {
    return [];
  }

  if (!Array.isArray(payload.allowedIps)) {
    throw new Error("allowedIps must be an array of IP/CIDR strings");
  }

  return normalizeAllowedIpRules(payload.allowedIps as string[]);
}

export function resolveTargetInternalUrl(target: string, routePath: string): string {
  const url = new URL(target);
  if (!url.pathname || url.pathname === "/") {
    url.pathname = routePath;
    url.search = "";
  }
  return url.toString();
}

export async function parseFetchResponseBody(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    try {
      return await response.text();
    } catch {
      return null;
    }
  }
}

export function normalizeInternalClientId(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

export function toHmacError(error: unknown): HmacAuthError {
  if (error instanceof HmacAuthError) {
    return error;
  }

  if (error instanceof Error) {
    return new HmacAuthError("INTERNAL_ERROR", error.message, 500);
  }

  return new HmacAuthError("INTERNAL_ERROR", "Internal auth error", 500);
}

export function forbiddenInternal(message: string): HmacInternalManagementRequestResult {
  return {
    handled: true,
    status: 403,
    body: {
      error: "FORBIDDEN",
      message,
    },
    verifiedAuth: null,
  };
}
