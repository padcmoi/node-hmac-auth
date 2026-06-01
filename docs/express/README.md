# Express Guide

This guide shows a minimal, production-oriented setup for using `@naskot/node-hmac-auth` with Express.

## 1) Install

```bash
npm install @naskot/node-hmac-auth express redis
```

## 2) Initialize Redis + HMAC

```ts
import { createClient } from "redis";
import { initializeHmacHttpAuth } from "@naskot/node-hmac-auth";

const redis = createClient({
  url: process.env.REDIS_URL, // ex: redis://user:password@127.0.0.1:6379
});

await redis.connect();

const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: "my-api-prod",
  maxSkewMs: 5 * 60 * 1000,
  defaultSecretLengthBytes: 32,
  secretToken: process.env.HMAC_SECRET_TOKEN, // strongly recommended
  dbSeedBackupTtlSeconds: 600, // v1.2.0, TTL of credentials-backup keys; default 600
  requireBootstrapClientId: "self_propagation_signer", // v1.3.0, optional - see §11
  onBadSignature: async (event) => {
    const meta = (event.metadata ?? {}) as {
      ip?: string;
      remoteAddress?: string;
      forwardedFor?: string | string[];
    };

    const forwarded = Array.isArray(meta.forwardedFor) ? meta.forwardedFor[0] : meta.forwardedFor;
    const ipFromForwarded = forwarded?.split(",")[0]?.trim();
    const ip = ipFromForwarded || meta.ip || meta.remoteAddress || "unknown";

    console.warn("BAD_SIGNATURE", {
      ip,
      clientId: event.clientId,
      path: event.path,
      nonce: event.nonce,
      timestamp: event.timestamp,
    });

    // Example anti-bruteforce / ban pipeline:
    // await redis.incr(`ban:hmac:${ip}`);
    // await redis.expire(`ban:hmac:${ip}`, 60);
  },
});
```

## 3) Seed a Client Credential (once)

```ts
const existing = await hmacAuth.clients.get("client_mobile");
if (!existing) {
  await hmacAuth.clients.create({
    clientId: "client_mobile",
    plainSecret: "superSharedSecret", // use a secure secret manager in real systems
    expiresAt: null, // optional
    allowedIps: ["195.7.8.9", "195.7.8.0/24"], // optional IP/CIDR allowlist for this clientId
    fromDbSeed: false, // v1.2.0, opt-in marker for dynamic DB-seed origin (default false)
    purpose: "any", // v1.3.0, "any" (default) or "propagation-only" - see §11
  });
}
```

## 4) Express App Setup

Important: attach `captureRawBody` to `express.json(...)` so signature verification uses the exact raw payload.

```ts
import express from "express";
import { captureRawBody } from "@naskot/node-hmac-auth";

const app = express();

// If behind a reverse proxy/load balancer, keep client IP from X-Forwarded-For.
app.set("trust proxy", true);

app.use(
  express.json({
    verify: (req, res, buf) => captureRawBody(req as any, res, buf),
  })
);
```

## 5) Protect Routes With HMAC Middleware

```ts
app.use("/secure", hmacAuth.verifyHttpRequest);

app.get("/secure/get", (req, res) => {
  res.json({
    ok: true,
    method: "GET",
    auth: (req as any).hmacAuth ?? null,
  });
});

app.post("/secure/post", (req, res) => {
  res.json({
    ok: true,
    method: "POST",
    body: req.body ?? null,
    auth: (req as any).hmacAuth ?? null,
  });
});
```

## 6) Public Route Calling a Secure Peer Route

Read signing material from Redis (`secretHash`) at call time, then use `createHttpSignedFetchClient`.

```ts
const PEER_BASE_URL = process.env.PEER_BASE_URL ?? "http://127.0.0.1:3002";
const CLIENT_ID = "client_mobile";

async function callPeer(url: string, options: any = {}) {
  const client = await hmacAuth.clients.get(CLIENT_ID);
  if (!client) {
    throw new Error(`${CLIENT_ID} not found in Redis`);
  }

  const peerFetch = hmacAuth.createHttpSignedFetchClient({
    clientId: CLIENT_ID,
    secret: client.secretHash,
    secretIsHashed: true,
  });

  return peerFetch(url, options);
}

app.get("/public/call-peer-get", async (_req, res) => {
  const response = await callPeer(`${PEER_BASE_URL}/secure/get?from=api_1`, {
    method: "GET",
  });
  const body = await response.json();
  res.status(response.status).json({
    ok: response.ok,
    upstreamStatus: response.status,
    upstreamBody: body,
  });
});
```

## 7) Behavior Summary

- Missing `x-client-id` -> `401`
- Unknown `clientId` -> `401`
- Missing source IP while `allowedIps` is configured -> `403`
- Source IP not allowed by `allowedIps` -> `403`
- Bad signature -> `401`
- Expired client secret -> `401`
- Replayed nonce -> `401`
- `BOOTSTRAP_LOCKED` (v1.3.0) -> `403` when `requireBootstrapClientId` is configured and the named credential is not yet stored
- `PROPAGATION_ONLY_FORBIDDEN` (v1.3.0) -> `403` when the matched credential has `purpose: "propagation-only"` and the request path is not the configured `internalManagementRoute`

Headers used by verifier:

- `x-client-id`
- `x-timestamp`
- `x-nonce`
- `x-signature`

Note: `createExpressHttpMiddleware()` is available as explicit Express middleware naming.

The full wire specification (cryptographic primitives, payload shapes, every error code, certification test vectors) is in [docs/wire-contract.md](../wire-contract.md).

## 8) Sign and Verify Messages

For async message transports (queues/events), use message helpers instead of HTTP helpers.

```ts
import { initializeHmacMessageAuth } from "@naskot/node-hmac-auth";

const hmacMessageAuth = initializeHmacMessageAuth({
  redis,
  namespace: "my-api-prod-messages",
  secretToken: process.env.HMAC_SECRET_TOKEN,
});

const signed = await hmacMessageAuth.signMessage({
  clientId: "client_mobile",
  message: { event: "order.created", id: 42 },
});

await hmacMessageAuth.verifyMessage({
  clientId: "client_mobile",
  message: { event: "order.created", id: 42 },
  signature: signed.signature,
});
```

Message verification intentionally does not enforce timestamp skew checks or anti-replay.

## 9) Internal HMAC Key Management Route (optional)

You can enable a dedicated internal route used to bootstrap and propagate credentials between APIs.

```ts
const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: "my-api-prod",
  secretToken: process.env.HMAC_SECRET_TOKEN,
  internalManagementRoute: "/api/internal/hmac",
});

app.use(hmacAuth.createInternalManagementMiddleware());
```

Supported methods on `/api/internal/hmac`:

- `GET`: healthcheck (v1.3.0+ also exposes `bootstrapLocked: boolean` in the body)
- `POST`: create/propagate a credential
- `PUT`: update a credential secret
- `PATCH` (v1.2.0): revert a credential to its previous `secretHash` from the TTL backup
- `DELETE`: delete a credential

For `POST` / `PUT` / `PATCH` / `DELETE`, target APIs return:

- `201` when accepted
- `403` when refused

Security behavior:

- If at least one client already exists in Redis, route requires valid HMAC auth.
- If no client exists yet, first credential bootstrap is accepted without HMAC auth.
- v1.3.0: when `requireBootstrapClientId` is set, only `POST` for the named clientId is accepted while the bootstrap-lock is active; `PUT` / `PATCH` / `DELETE` and any other `POST` are refused with HTTP 403 `BOOTSTRAP_LOCKED`.

### Propagate to one or many APIs

Use a signed `apiFetch` (created from an existing key) when target APIs already require authentication.

```ts
const signer = hmacAuth.createHttpSignedFetchClient({
  clientId: "internal_sync",
  secret: "internal_sync_secret",
});

const results = await hmacAuth.propagateClientToApis({
  operation: "create",
  targets: ["https://api-a.example.com", "https://api-b.example.com"],
  clientId: "client_mobile",
  secret: "superSharedSecret",
  allowedIps: ["195.7.8.9", "195.7.8.0/24"], // required for create/update propagation
  apiFetch: signer,
});

// Each result includes status and accepted boolean (201/403)
console.log(results);
```

Behavior changes around `propagateClientToApis` are documented in the dedicated release notes:

- 1.3.0 — optional `purpose` field on the wire payload, new `operation` semantics unchanged (still `create`/`update`/`delete`/`revert`/`health`); see [docs/release-notes/1.3.0.md](../release-notes/1.3.0.md).
- 1.2.0 — new `operation: "revert"` (PATCH) restores the previous `secretHash` from the v1.2.0 TTL backup, and `fromDbSeed: true` on the payload activates that backup on rotation. See [docs/release-notes/1.2.0.md](../release-notes/1.2.0.md).
- 1.1.1 — `HmacPropagateTargetStore` + `HmacMessageAuthBridge` are now re-exported from the package index (fix omitted in 1.1.0). See [docs/release-notes/1.1.1.md](../release-notes/1.1.1.md).
- 1.1.0 — propagation can also target the message credential store via `targetStore: "message"` (optional `messageAuth` bridge in `initializeHmacHttpAuth`). See [docs/release-notes/1.1.0.md](../release-notes/1.1.0.md).
- 1.0.0 — propagation transports the `secretHash` on the wire + Redis fallback when `secret`/`secretHash` are omitted. See [docs/release-notes/1.0.0.md](../release-notes/1.0.0.md).

### Revert a rotation (v1.2.0)

`clients.revert(clientId)` restores the previous `secretHash` from the local `credentials-backup:<clientId>` key (written automatically when a `fromDbSeed: true` rotation overwrites a record). Pair it with `propagateClientToApis({ operation: "revert", ... })` to roll back the same `clientId` on every target that already accepted the new hash.

```ts
const localRevert = await hmacAuth.clients.revert("bizClient");
console.log(localRevert.reverted, localRevert.restoredSecretHash);

const targetRevert = await hmacAuth.propagateClientToApis({
  operation: "revert",
  clientId: "bizClient",
  targets: acceptedTargets,
  apiFetch: signer,
});
```

## 10) Bootstrap lock + propagation-only credentials (v1.3.0)

Two opt-in hardenings designed to be combined when an API delegates its credential lifecycle to an orchestrator (e.g. [`@naskot/node-hmac-auth-management`](https://github.com/padcmoi/node-hmac-auth)). Both are off by default; setting them changes only the bootstrap window and the per-credential cantonment.

```ts
const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: "my-api-prod",
  secretToken: process.env.HMAC_SECRET_TOKEN,
  internalManagementRoute: "/api/internal/hmac",
  // F2 — lock the API until the named credential is stored locally:
  requireBootstrapClientId: "self_propagation_signer",
});

// F1 — store a credential that can only sign management-route requests:
await hmacAuth.clients.create({
  clientId: "self_propagation_signer",
  plainSecret: process.env.PROPAGATION_SECRET,
  purpose: "propagation-only",
});
```

While the bootstrap-lock is active:

- `verifyHttpSignature` refuses every signed business request with HTTP 403 `BOOTSTRAP_LOCKED`.
- `handleInternalManagementRequest` keeps `GET` open (and returns `bootstrapLocked: true` in the body so external orchestrators can detect the state), accepts `POST` only when `payload.clientId === requireBootstrapClientId`, and refuses `PUT`/`PATCH`/`DELETE` with `BOOTSTRAP_LOCKED`.

After the named credential is stored:

- The lock auto-releases. Subsequent requests behave exactly like v1.2.x.
- Manually deleting the bootstrap credential re-locks the API on the next request, so an operator-driven restore is recoverable.

When a credential carries `purpose: "propagation-only"`:

- It can sign requests on the configured `internalManagementRoute` (typically used by an orchestrator to push other credentials).
- Any signed request on a different path is refused with HTTP 403 `PROPAGATION_ONLY_FORBIDDEN`, even when the signature is otherwise valid.
- On the message track, `signMessage` and `verifyMessage` refuse the credential outright with the same code (messages have no path concept).

Combining both: declare the bootstrap credential with `purpose: "propagation-only"` and even if the secret leaks, the attacker can only push other (auditable) credentials. Business routes stay closed.

The full wire specification (cryptographic primitives, header names, Redis layout, every error code, certification test vectors) is in [docs/wire-contract.md](../wire-contract.md).

## 11) Complete Shared Service Example

This service is framework-agnostic at code level

```ts
import { createClient } from "redis";
import { createHmacRuntime, initializeHmacHttpAuth, initializeHmacMessageAuth } from "@naskot/node-hmac-auth";
import type {
  CreateHmacClientOptions,
  PropagateServiceCreateOptions,
  PropagateServiceDeleteOptions,
  PropagateServiceHealthOptions,
  PropagateServiceUpdateOptions,
  SignedHttpFetchClientCallOptions,
} from "@naskot/node-hmac-auth";

const redis = createClient({
  url: process.env.REDIS_URL, // ex: redis://user:password@127.0.0.1:6379
});

await redis.connect();

const HMAC_NAMESPACE = process.env.HMAC_NAMESPACE ?? "my-api-prod";

export const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: HMAC_NAMESPACE,
  maxSkewMs: 5 * 60 * 1000,
  defaultSecretLengthBytes: 32,
  secretToken: process.env.HMAC_SECRET_TOKEN, // strongly recommended
  internalManagementRoute: process.env.INTERNAL_MANAGEMENT_ROUTE ?? "/api/internal/hmac-auth", // optional: clientId propagation between APIs
  dbSeedBackupTtlSeconds: 600, // v1.2.0, TTL of credentials-backup keys; default 600
  requireBootstrapClientId: process.env.HMAC_BOOTSTRAP_CLIENT_ID, // v1.3.0, optional (see §10)
  onBadSignature: async (event) => {
    const meta = (event.metadata ?? {}) as {
      ip?: string;
      remoteAddress?: string;
      forwardedFor?: string | string[];
    };

    const forwarded = Array.isArray(meta.forwardedFor) ? meta.forwardedFor[0] : meta.forwardedFor;
    const ipFromForwarded = forwarded?.split(",")[0]?.trim();
    const ip = ipFromForwarded || meta.ip || meta.remoteAddress || "unknown";

    console.warn("BAD_SIGNATURE", {
      ip,
      clientId: event.clientId,
      path: event.path,
      nonce: event.nonce,
      timestamp: event.timestamp,
    });
  },
});

export const hmacMessageAuth = initializeHmacMessageAuth({
  redis,
  namespace: `${HMAC_NAMESPACE}-messages`,
  secretToken: process.env.HMAC_SECRET_TOKEN,
});

const { createSignedFetchFromClientId, signedFetchWithClientId, hmacHttpMiddleware } = createHmacRuntime(hmacAuth);

export const credential = {
  /**
   * Read one client credential by clientId.
   *
   * Usage:
   * const client = await credential.get("client_mobile");
   */
  get: async (clientId: string) => {
    return await hmacAuth.clients.get(clientId);
  },

  /**
   * Create a client credential only if it does not already exist.
   *
   * Usage:
   * await credential.create({
   *   clientId: "client_mobile",
   *   plainSecret: "superSharedSecret",
   *   expiresAt: null,
   * });
   */
  create: async (opts: CreateHmacClientOptions) => {
    if (await credential.get(opts.clientId)) {
      return { status: false as const, error: `Cannot create credential: clientId '${opts.clientId}' already exists.` };
    }

    return await hmacAuth.clients.create(opts);
  },

  /**
   * Regenerate an existing client secret using a required plainSecret.
   *
   * Usage:
   * await credential.regenerateSecret("client_mobile", "newSuperSecret");
   */
  regenerateSecret: async (clientId: string, plainSecret: string) => {
    if (!(await credential.get(clientId))) {
      return { status: false as const, error: `Cannot regenerate credential: clientId '${clientId}' does not exist.` };
    }

    return await hmacAuth.clients.regenerateSecret(clientId, { plainSecret });
  },

  /**
   * Revoke (delete) an existing client credential.
   *
   * Usage:
   * await credential.revoke("client_mobile");
   */
  revoke: async (clientId: string) => {
    if (!(await credential.get(clientId))) {
      return { status: false as const, error: `Cannot revoke credential: clientId '${clientId}' does not exist.` };
    }

    await hmacAuth.clients.delete(clientId);
    return { status: true as const, clientId };
  },
};

export const http = {
  /**
   * Set one or more candidate clientIds for a signed fetch context.
   * The first non-empty clientId is always used.
   *
   * Usage:
   * await http.use("svc-a").fetch("https://api.example.com/secure", { method: "POST" });
   * await http.useClientIds("svc-a").fetch("https://api.example.com/secure", { method: "POST" });
   *
   * app.use("/secure", http.useClientIds().middleware);
   * app.use("/secure", http.useClientIds("svc-a", "svc-b").middleware);
   */
  use: (...clientIds: string[]) => http.useClientIds(...clientIds),
  useClientIds: (...clientIds: string[]) => {
    const firstClientId = clientIds.find((value) => typeof value === "string" && value.trim());

    return {
      fetch: (input: string, options?: SignedHttpFetchClientCallOptions) => {
        if (!firstClientId) {
          throw new Error(
            "Forbidden: signed fetch requires at least one clientId. Use http.useClientIds('svc-a').fetch(url, options)."
          );
        }
        return signedFetchWithClientId(input, firstClientId, options);
      },
      middleware: hmacHttpMiddleware(...clientIds),
    };
  },
};

export const interApi = {
  /**
   * Internal management middleware for inter-API clientId propagation route.
   *
   * Usage:
   * app.use(interApi.middleware);
   */
  middleware: hmacAuth.createInternalManagementMiddleware(),

  propagate: {
    create: async (opts: PropagateServiceCreateOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "create",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        secret: opts.plainSecret,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    update: async (opts: PropagateServiceUpdateOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "update",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        secret: opts.plainSecret,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    delete: async (opts: PropagateServiceDeleteOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "delete",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    /**
     * v1.2.0: revert a previously rotated credential on the target APIs that
     * already accepted the new hash. Restores each target's previous
     * secretHash from the TTL backup written automatically when the rotation
     * was tagged `fromDbSeed: true`. Pair with `hmacAuth.clients.revert` on
     * the source to keep the federation consistent.
     */
    revert: async (opts: PropagateServiceDeleteOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "revert",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    health: async (opts: PropagateServiceHealthOptions) => {
      const results = await hmacAuth.propagateClientToApis({
        operation: "health",
        targets: opts.targetApis,
        apiFetch: await createSignedFetchFromClientId(opts.useClientId),
      });

      return results;
    },
  },
};

export const message = {
  /**
   * Sign an async message payload with a clientId (queue/event use case).
   *
   * Usage:
   * const signed = await message.sign("client_mobile", { event: "order.created", id: 42 });
   */
  sign: async (clientId: string, payload: unknown) => {
    return hmacMessageAuth.signMessage({ clientId, message: payload });
  },

  /**
   * Verify an async message signature with a clientId.
   *
   * Usage:
   * await message.verify("client_mobile", { event: "order.created", id: 42 }, signature);
   */
  verify: async (clientId: string, payload: unknown, signature: string) => {
    return hmacMessageAuth.verifyMessage({ clientId, message: payload, signature });
  },
};
```
