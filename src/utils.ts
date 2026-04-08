import { randomBytes } from "node:crypto";

export function normalizePath(pathOrUrl: string): string {
  const parsed = new URL(pathOrUrl, "http://localhost");
  return `${parsed.pathname}${parsed.search || ""}` || "/";
}

export function getHeader(headers: Record<string, string | string[] | undefined>, name: string): string | undefined {
  const target = name.toLowerCase();

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== target) {
      continue;
    }
    if (Array.isArray(value)) {
      return value[0];
    }
    return value;
  }

  return undefined;
}

export function generateNonce(bytes = 16): string {
  return randomBytes(bytes).toString("hex");
}

export function toBodyString(rawBody: unknown): string {
  if (rawBody == null) {
    return "";
  }

  if (typeof rawBody === "string") {
    return rawBody;
  }

  if (Buffer.isBuffer(rawBody)) {
    return rawBody.toString("utf8");
  }

  if (rawBody instanceof Uint8Array) {
    return Buffer.from(rawBody).toString("utf8");
  }

  if (rawBody instanceof URLSearchParams) {
    return rawBody.toString();
  }

  if (typeof rawBody === "object") {
    return JSON.stringify(rawBody);
  }

  return String(rawBody);
}

export function isJsonObjectBody(value: unknown): value is Record<string, unknown> {
  if (value == null || typeof value !== "object") {
    return false;
  }

  if (Buffer.isBuffer(value)) {
    return false;
  }

  if (value instanceof Uint8Array) {
    return false;
  }

  if (value instanceof URLSearchParams) {
    return false;
  }

  if (typeof FormData !== "undefined" && value instanceof FormData) {
    return false;
  }

  if (typeof Blob !== "undefined" && value instanceof Blob) {
    return false;
  }

  if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
    return false;
  }

  return true;
}
