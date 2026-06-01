import { sanitizeAllowedIpRules } from "../core/ip.js";
import type { HmacCredentialPurpose } from "../core/types.js";

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
  /**
   * v1.3.0: usage-scope marker. Optional on the stored record so 1.0.x
   * through 1.2.x records (which never wrote this field) parse cleanly.
   * Absent = "any" implicit (legacy behavior).
   */
  purpose?: HmacCredentialPurpose;
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function parseStoredPurpose(value: unknown): HmacCredentialPurpose | undefined {
  return value === "propagation-only" || value === "any" ? value : undefined;
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
        purpose: parseStoredPurpose(parsed.purpose),
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
