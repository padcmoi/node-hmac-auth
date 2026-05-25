import { hashClientSecret } from "../core/crypto.js";
import { HmacAuthError } from "../core/errors.js";
import { normalizeAllowedIpRules } from "../core/ip.js";
import type { HmacMessageAuthBridge, PropagateHmacClientOptions, PropagateHmacClientResult } from "../core/types.js";
import type { RedisCredentialStore } from "../stores/redis.js";
import { assertClientId, normalizeExpiresAt, parseFetchResponseBody, resolveTargetInternalUrl } from "./internal-helpers.js";

/**
 * `propagateClientToApis` factory.
 *
 * Builds the function that fans a credential operation out across a list of
 * sister APIs by hitting their `internalManagementRoute`. The HTTP verb is
 * picked from `propagateOptions.operation`:
 *
 *   "health" -> GET    (probe, no body)
 *   "create" -> POST   (create credential)
 *   "update" -> PUT    (rotate credential)
 *   "delete" -> DELETE (drop credential)
 *   "revert" -> PATCH  (restore previous secretHash from TTL backup, v1.2.0)
 *
 * The payload always carries the locally-computed `secretHash` (never the
 * plain `secret`) so source and target Redis end up with byte-identical
 * hashes and signed requests verify cross-token. For revert, the payload
 * carries only `{ clientId, kind? }`.
 */
export interface CreatePropagateClientToApisDeps {
  internalManagementRoute: string | undefined;
  credentialStore: RedisCredentialStore;
  messageAuth: HmacMessageAuthBridge | undefined;
  secretToken: string | undefined;
}

export function createPropagateClientToApis(
  deps: CreatePropagateClientToApisDeps
): (options: PropagateHmacClientOptions) => Promise<PropagateHmacClientResult[]> {
  const { internalManagementRoute, credentialStore, messageAuth, secretToken } = deps;

  return async (propagateOptions) => {
    if (!internalManagementRoute) {
      throw new HmacAuthError("INTERNAL_ROUTE_DISABLED", "internalManagementRoute is not configured for this API instance", 400);
    }

    const fetchImpl = propagateOptions.apiFetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new Error("No fetch implementation available");
    }

    if (!Array.isArray(propagateOptions.targets) || propagateOptions.targets.length === 0) {
      throw new Error("targets must contain at least one API URL");
    }

    const operation = propagateOptions.operation;
    const method =
      operation === "health"
        ? "GET"
        : operation === "create"
          ? "POST"
          : operation === "update"
            ? "PUT"
            : operation === "revert"
              ? "PATCH"
              : "DELETE";

    // v1.1.0: pick the target credential store. Default "http" (1.0.x behavior).
    const targetStore: "http" | "message" = propagateOptions.targetStore ?? "http";
    if (targetStore === "message" && !messageAuth) {
      throw new Error(
        "propagateClientToApis: targetStore='message' requires messageAuth to be passed to initializeHmacHttpAuth (used for the local Redis fallback)"
      );
    }

    // Local Redis fallback: when neither `secret` nor `secretHash` is provided
    // for create/update propagation, look up the clientId in the local store
    // (HTTP or message, depending on targetStore) and reuse its stored
    // secretHash. Lets a caller declare a clientId only once locally and
    // reference it from a propagation plan without duplicating the plain
    // secret.
    let resolvedSecretHash = propagateOptions.secretHash;
    if (
      operation !== "health" &&
      operation !== "delete" &&
      operation !== "revert" &&
      resolvedSecretHash === undefined &&
      propagateOptions.secret === undefined
    ) {
      if (targetStore === "http") {
        const localRecord = await credentialStore.getClientRecord(propagateOptions.clientId ?? "");
        if (localRecord) {
          resolvedSecretHash = localRecord.secretHash;
        }
      } else {
        const localRecord = await (messageAuth as HmacMessageAuthBridge).clients.get(propagateOptions.clientId ?? "");
        if (localRecord) {
          resolvedSecretHash = localRecord.secretHash;
        }
      }
    }

    if (operation !== "health") {
      assertClientId(propagateOptions.clientId ?? "");
      if (operation !== "delete" && operation !== "revert" && !propagateOptions.secret && !resolvedSecretHash) {
        throw new Error("secret or secretHash is required for create/update propagation (or clientId must exist locally)");
      }
      if ((operation === "create" || operation === "update") && !Array.isArray(propagateOptions.allowedIps)) {
        throw new Error("allowedIps array is required for create/update propagation");
      }
    }

    const payload: Record<string, unknown> = {};
    if (operation !== "health") {
      payload.clientId = propagateOptions.clientId;
      if (operation === "revert") {
        // PATCH carries only `clientId` (+ optional `kind`). The remote
        // restores the previous secretHash from its TTL backup. No secret,
        // no allowedIps, no expiresAt - this operation is purely a state
        // rollback on the target side.
        if (targetStore !== "http") {
          payload.kind = targetStore;
        }
      } else {
        // Propagation always carries the locally-computed secretHash, never the
        // plain secret. The target API stores the hash as-is via setSecretHash,
        // so both sides end up with byte-identical hashes and signed requests
        // verify even when the two APIs do not share the same HMAC_SECRET_TOKEN.
        // Priority: explicit caller secretHash > local Redis lookup > hash of
        // the caller-provided plain secret.
        if (resolvedSecretHash !== undefined) {
          payload.secretHash = resolvedSecretHash;
        } else if (propagateOptions.secret !== undefined) {
          payload.secretHash = hashClientSecret(propagateOptions.secret, secretToken);
        }
        if (propagateOptions.expiresAt !== undefined) {
          payload.expiresAt = normalizeExpiresAt(propagateOptions.expiresAt);
        }
        if (propagateOptions.allowedIps !== undefined) {
          payload.allowedIps = normalizeAllowedIpRules(propagateOptions.allowedIps);
        }
        // v1.1.0: include the target store kind so the remote routes the write
        // to the right credential store. Omitted when "http" to keep the wire
        // bytes-identical to 1.0.x for the default path.
        if (targetStore !== "http") {
          payload.kind = targetStore;
        }
        // v1.2.0: marker propagated to the remote credential record. Only
        // emitted when explicitly true to keep the default wire 1.0.x-compatible.
        if (propagateOptions.fromDbSeed === true) {
          payload.fromDbSeed = true;
        }
      }
    }

    const results: PropagateHmacClientResult[] = [];

    for (const target of propagateOptions.targets) {
      try {
        const targetUrl = resolveTargetInternalUrl(target, internalManagementRoute);
        const headers = new Headers(propagateOptions.headers);
        if (method !== "GET") {
          headers.set("content-type", "application/json");
        }

        const response = await fetchImpl(targetUrl, {
          method,
          headers,
          body: method === "GET" ? undefined : JSON.stringify(payload),
        });

        const body = await parseFetchResponseBody(response);
        const accepted = method === "GET" ? response.status === 200 : response.status === 201;

        results.push({
          target,
          url: targetUrl,
          operation,
          status: response.status,
          accepted,
          body,
        });
      } catch (error) {
        results.push({
          target,
          url: target,
          operation,
          status: 0,
          accepted: false,
          body: null,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return results;
  };
}
