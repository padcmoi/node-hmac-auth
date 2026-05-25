import type {
  HmacInternalManagementRequestInput,
  HmacInternalManagementRequestResult,
  HmacMessageAuthBridge,
  VerifiedHttpRequest,
  VerifyHttpWithRedisInput,
} from "../core/types.js";
import { normalizePath } from "../core/utils.js";
import type { HmacCredentialsStoreClients } from "../stores/credentials-clients-factory.js";
import {
  forbiddenInternal,
  normalizeInternalClientId,
  normalizeRoutePath,
  parseAllowedIpsFromPayload,
  parseExpiresAtFromPayload,
  parseInternalBody,
} from "./internal-helpers.js";

/**
 * Handler for the lib-managed internal management route.
 *
 * Verbs handled, dispatched on the same `internalManagementRoute`:
 *
 *   GET    -> health probe (no side-effect, returns clientsCount + authRequired flag)
 *   POST   -> create credential
 *   PUT    -> update credential
 *   PATCH  -> revert credential to its TTL-backed previous secretHash (v1.2.0)
 *   DELETE -> delete credential
 *
 * Routing on `payload.kind`:
 *
 *   omitted / "http" -> HTTP credential store (default, 1.0.x behavior)
 *   "message"        -> message credential store (requires `messageAuth` bridge)
 *
 * Bootstrap-then-auth: when the local Redis holds zero credentials, the first
 * incoming request is accepted without signature verification (initial seed).
 * Once at least one credential exists, every request must carry a valid HMAC
 * signature signed by an already-known clientId.
 */
export interface CreateInternalManagementHandlerDeps {
  clients: HmacCredentialsStoreClients;
  messageAuth: HmacMessageAuthBridge | undefined;
  internalManagementRoute: string | undefined;
  namespace: string;
  verifyHttpSignature: (input: VerifyHttpWithRedisInput) => Promise<VerifiedHttpRequest>;
}

export function createInternalManagementHandler(
  deps: CreateInternalManagementHandlerDeps
): (input: HmacInternalManagementRequestInput) => Promise<HmacInternalManagementRequestResult> {
  const { clients, messageAuth, internalManagementRoute, namespace, verifyHttpSignature } = deps;

  return async (input) => {
    if (!internalManagementRoute) {
      return {
        handled: false,
        status: 404,
        body: {},
        verifiedAuth: null,
      };
    }

    const normalizedFullPath = normalizePath(input.path);
    const routePath = normalizeRoutePath(normalizedFullPath);
    if (routePath !== internalManagementRoute) {
      return {
        handled: false,
        status: 404,
        body: {},
        verifiedAuth: null,
      };
    }

    const method = input.method.toUpperCase();
    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      return {
        handled: true,
        status: 405,
        body: {
          error: "METHOD_NOT_ALLOWED",
          message: "Supported methods are GET, POST, PUT, PATCH, DELETE",
        },
        verifiedAuth: null,
      };
    }

    const knownClients = await clients.listClientIds();
    const authRequired = knownClients.length > 0;

    let verifiedAuth: VerifiedHttpRequest | null = null;
    if (authRequired) {
      try {
        verifiedAuth = await verifyHttpSignature({
          method,
          path: normalizedFullPath,
          headers: input.headers,
          rawBody: input.rawBody,
          now: input.now,
          maxSkewMs: input.maxSkewMs,
          onBadSignature: input.onBadSignature,
          metadata: input.metadata,
        });
      } catch {
        return forbiddenInternal("Internal HMAC management authentication failed");
      }
    }

    if (method === "GET") {
      return {
        handled: true,
        status: 200,
        body: {
          ok: true,
          namespace,
          route: internalManagementRoute,
          authRequired,
          clientsCount: knownClients.length,
          authenticatedBy: verifiedAuth?.clientId ?? null,
        },
        verifiedAuth,
      };
    }

    const payload = parseInternalBody(input.rawBody);
    const payloadClientId = normalizeInternalClientId(payload.clientId);
    if (!payloadClientId) {
      return forbiddenInternal("clientId is required");
    }

    if (method === "DELETE") {
      const existing = await clients.get(payloadClientId);
      if (!existing) {
        return forbiddenInternal("Client does not exist");
      }

      await clients.delete(payloadClientId);
      return {
        handled: true,
        status: 201,
        body: {
          ok: true,
          operation: "delete",
          clientId: payloadClientId,
        },
        verifiedAuth,
      };
    }

    if (method === "PATCH") {
      // v1.2.0: revert a db-seeded credential to its previous secretHash from
      // the TTL backup written automatically on the last rotation. Only works
      // when the target stored a `credentials-backup:<clientId>` key and it
      // has not yet expired. Static credentials (fromDbSeed=false) never have
      // a backup, so PATCH on them always returns reverted=false.
      const patchPayloadKind = typeof payload.kind === "string" ? payload.kind : "http";
      if (patchPayloadKind !== "http" && patchPayloadKind !== "message") {
        return forbiddenInternal(`Unsupported revert kind '${patchPayloadKind}'`);
      }
      if (patchPayloadKind === "message" && !messageAuth) {
        return forbiddenInternal("Message store not configured on this API (pass messageAuth to initializeHmacHttpAuth)");
      }
      const revertTargetClients = patchPayloadKind === "message" ? (messageAuth as HmacMessageAuthBridge).clients : clients;
      const revertResult = await revertTargetClients.revert(payloadClientId);
      return {
        handled: true,
        status: 201,
        body: {
          ok: true,
          operation: "revert",
          clientId: payloadClientId,
          kind: patchPayloadKind,
          reverted: revertResult.reverted,
        },
        verifiedAuth,
      };
    }

    let expiresAt: number | null | undefined;
    try {
      expiresAt = parseExpiresAtFromPayload(payload);
    } catch {
      return forbiddenInternal("expiresAt must be a valid timestamp");
    }

    let allowedIps: string[] | undefined;
    try {
      allowedIps = parseAllowedIpsFromPayload(payload);
    } catch {
      return forbiddenInternal("allowedIps must be an array of valid IP/CIDR strings");
    }

    const secret = typeof payload.secret === "string" ? payload.secret : undefined;
    const secretHash = typeof payload.secretHash === "string" ? payload.secretHash : undefined;
    // v1.2.0: `fromDbSeed` marks the credential as originating from a dynamic
    // DB-seed pipeline. Omitted / falsy => static origin (default).
    const fromDbSeed = payload.fromDbSeed === true;
    const writeOptions = { fromDbSeed };

    // v1.1.0: `kind` in the payload selects the target credential store on
    // the remote. Defaults to "http" to keep 1.0.x callers unchanged.
    const payloadKind = typeof payload.kind === "string" ? payload.kind : "http";
    if (payloadKind !== "http" && payloadKind !== "message") {
      return forbiddenInternal(`Unsupported propagation kind '${payloadKind}'`);
    }
    if (payloadKind === "message" && !messageAuth) {
      return forbiddenInternal("Message store not configured on this API (pass messageAuth to initializeHmacHttpAuth)");
    }
    const targetClients = payloadKind === "message" ? (messageAuth as HmacMessageAuthBridge).clients : clients;

    if (!secret && !secretHash) {
      return forbiddenInternal("secret or secretHash is required");
    }

    const existing = await targetClients.get(payloadClientId);

    if (method === "POST") {
      if (existing) {
        return forbiddenInternal("Client already exists");
      }

      if (secret) {
        await targetClients.setSecret(payloadClientId, secret, expiresAt, allowedIps, writeOptions);
      } else {
        await targetClients.setSecretHash(payloadClientId, secretHash as string, expiresAt, allowedIps, writeOptions);
      }

      return {
        handled: true,
        status: 201,
        body: {
          ok: true,
          operation: "create",
          clientId: payloadClientId,
          kind: payloadKind,
        },
        verifiedAuth,
      };
    }

    if (!existing) {
      return forbiddenInternal("Client does not exist");
    }

    if (secret) {
      await targetClients.setSecret(payloadClientId, secret, expiresAt, allowedIps, writeOptions);
    } else {
      await targetClients.setSecretHash(payloadClientId, secretHash as string, expiresAt, allowedIps, writeOptions);
    }

    return {
      handled: true,
      status: 201,
      body: {
        ok: true,
        operation: "update",
        clientId: payloadClientId,
        kind: payloadKind,
      },
      verifiedAuth,
    };
  };
}
