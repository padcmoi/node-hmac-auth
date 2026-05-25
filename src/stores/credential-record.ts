import { sanitizeAllowedIpRules } from "../core/ip.js";

/**
 * Serialized credential record stored under `<namespace>:clients[<clientId>]`.
 * The lib serializes this as JSON. A legacy fallback in `parseStoredClientRecord`
 * accepts records that contain only the secretHash (pre-record format), so
 * upgrades from very old data stay transparent.
 */
export interface StoredClientCredentialRecord {
  secretHash: string;
  createdAt: number;
  updatedAt: number;
  expiresAt: number | null;
  allowedIps: string[];
  fromDbSeed: boolean;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function parseStoredClientRecord(rawValue: string): StoredClientCredentialRecord {
  try {
    const parsed = JSON.parse(rawValue) as Partial<StoredClientCredentialRecord>;
    if (typeof parsed?.secretHash === "string") {
      return {
        secretHash: parsed.secretHash,
        createdAt: isFiniteNumber(parsed.createdAt) ? parsed.createdAt : 0,
        updatedAt: isFiniteNumber(parsed.updatedAt) ? parsed.updatedAt : 0,
        expiresAt: isFiniteNumber(parsed.expiresAt) ? parsed.expiresAt : null,
        allowedIps: sanitizeAllowedIpRules(parsed.allowedIps),
        fromDbSeed: parsed.fromDbSeed === true,
      };
    }
  } catch {
    // Backward compatibility: old format stored only the secret hash
  }

  return {
    secretHash: rawValue,
    createdAt: 0,
    updatedAt: 0,
    expiresAt: null,
    allowedIps: [],
    fromDbSeed: false,
  };
}
