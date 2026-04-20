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

Headers used by verifier:

- `x-client-id`
- `x-timestamp`
- `x-nonce`
- `x-signature`

Note: `createExpressHttpMiddleware()` is available as explicit Express middleware naming.

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

- `GET`: healthcheck
- `POST`: create/propagate a credential
- `PUT`: update a credential secret
- `DELETE`: delete a credential

For `POST` / `PUT` / `DELETE`, target APIs return:

- `201` when accepted
- `403` when refused

Security behavior:

- If at least one client already exists in Redis, route requires valid HMAC auth.
- If no client exists yet, first credential bootstrap is accepted without HMAC auth.

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

## 10) Complete Shared Service Example

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
