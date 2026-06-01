import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { hashClientSecret, signRequest } from "../src/index.js";

/**
 * Golden test vectors for the wire contract. The JSON files under
 * test/vectors/ are the source of truth for cross-language ports:
 *
 *   - hash-client-secret.json  : every case of hashClientSecret(secret, token)
 *   - sign-request.json        : every case of signRequest({...})
 *
 * Any change here that shifts an expectedHex is a wire break. The test
 * suite is the bouncer: if a v1.x.x lib stops matching a vector, the
 * release is invalid until either the vector is intentionally rev'd in a
 * major bump or the regression is fixed.
 */
const here = dirname(fileURLToPath(import.meta.url));
const hashVectors = JSON.parse(readFileSync(resolve(here, "vectors", "hash-client-secret.json"), "utf8")) as {
  cases: Array<{ id: string; secretToken: string; secret: string; expectedHex: string }>;
};
const signVectors = JSON.parse(readFileSync(resolve(here, "vectors", "sign-request.json"), "utf8")) as {
  cases: Array<{
    id: string;
    method: string;
    path: string;
    timestamp: number;
    nonce: string;
    body: string;
    secret: string;
    expectedHex: string;
  }>;
};

describe("wire contract - hashClientSecret vectors", () => {
  for (const vector of hashVectors.cases) {
    it(`${vector.id} matches expectedHex`, () => {
      const actual = hashClientSecret(vector.secret, vector.secretToken || undefined);
      expect(actual).toBe(vector.expectedHex);
    });
  }
});

describe("wire contract - signRequest vectors", () => {
  for (const vector of signVectors.cases) {
    it(`${vector.id} matches expectedHex`, () => {
      const actual = signRequest({
        method: vector.method,
        path: vector.path,
        timestamp: vector.timestamp,
        nonce: vector.nonce,
        body: vector.body,
        secret: vector.secret,
      });
      expect(actual).toBe(vector.expectedHex);
    });
  }
});
