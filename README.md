# node-hmac-auth

Simple, reusable HMAC authentication for Node.js APIs.

Redis is mandatory.  
`clientId` is read automatically from request headers by the middleware/verifier.

## What This Library Does

- Validates HMAC requests using `x-client-id`, `x-timestamp`, `x-nonce`, `x-signature`
- Loads client credentials from Redis
- Supports a custom Redis namespace at initialization
- Provides an Express middleware
- Provides HMAC fetch helpers for outbound calls
- Supports optional credential expiration (`expiresAt`)
- If `expiresAt` is not set, credential is lifetime (no expiry)

## Installation

```bash
npm install @naskot/node-hmac-auth
```

## 1) Initialize With Redis Config + Custom Namespace

```ts
import { createClient } from "redis";
import { initializeHmacAuth } from "@naskot/node-hmac-auth";

const redis = createClient({
  url: process.env.REDIS_URL,
  username: process.env.REDIS_USERNAME, // optional
  password: process.env.REDIS_PASSWORD, // optional
});

await redis.connect();

const hmacAuth = initializeHmacAuth({
  redis,
  namespace: "my_company_prod", // choose any namespace you want
  maxSkewMs: 5 * 60 * 1000, // optional
  defaultSecretLengthBytes: 32, // optional
});
```

Redis keys used for that namespace:

- `my_company_prod:clients` (hash of client credentials)
- `my_company_prod:nonce:*` (anti-replay nonce keys)

## 2) Use As Express Middleware (clientId Auto-detected In Headers)

The middleware automatically reads:

- `x-client-id`
- `x-timestamp`
- `x-nonce`
- `x-signature`

If `x-client-id` is missing -> `401`  
If client does not exist in Redis -> `401`  
If signature does not match -> `401`

```ts
import express from "express";
import { captureRawBody } from "@naskot/node-hmac-auth";

const app = express();
app.use(express.json({ verify: captureRawBody }));

app.use(hmacAuth.createExpressMiddleware());

app.get("/secure", (req, res) => {
  const auth = (req as any).hmacAuth;
  res.json({ ok: true, clientId: auth.clientId });
});
```

## 3) Use HMAC Fetch Helpers

Important for production:

- Do not hardcode a plain secret in app code.
- Read client material from Redis and sign with `secretHash` (`secretIsHashed: true`).

### `signedFetch` (Redis-backed signing material)

```ts
import { signedFetch } from "@naskot/node-hmac-auth";

const client = await hmacAuth.clients.get("client_mobile");
if (!client) {
  throw new Error("client_mobile not found in Redis");
}

await signedFetch("https://remote-api.example.com/orders", {
  method: "POST",
  body: { amount: 100 },
  clientId: "client_mobile",
  secret: client.secretHash,
  secretIsHashed: true,
});
```

### `createSignedFetchClient` (Redis-backed preconfigured fetch)

```ts
const CLIENT_ID = "client_mobile";

async function callPeer(url: string, options: any = {}) {
  // Read signing material from Redis for each call
  // so key rotations / admin changes are picked up immediately.
  const client = await hmacAuth.clients.get(CLIENT_ID);
  if (!client) {
    throw new Error(`${CLIENT_ID} not found in Redis`);
  }

  const apiFetch = hmacAuth.createSignedFetchClient({
    clientId: CLIENT_ID,
    secret: client.secretHash,
    secretIsHashed: true,
  });

  return apiFetch(url, options);
}

await callPeer("https://remote-api.example.com/orders", { method: "GET" });
```

This preconfigured fetch automatically injects `x-client-id` and computes signature from Redis-backed credential data.

## 3.1) Two-API Usage Example (Express)

A common setup is two APIs with separate Redis namespaces:

- `api_1` uses `hmac-lab-api1`
- `api_2` uses `hmac-lab-api2`

Each API can expose:

- public route: `/public/call-peer-post`
- protected route: `/secure/post`

The public route signs and forwards to the peer protected route, then returns:

```json
{
  "ok": true,
  "caller": "api_1",
  "upstreamStatus": 200,
  "upstreamBody": {
    "ok": true,
    "api": "api_2",
    "mode": "secure"
  }
}
```

`upstreamBody` is the response body returned by the peer API.

If signatures do not match, the peer protected route returns `401` (for example `BAD_SIGNATURE` or `UNKNOWN_CLIENT`).

## Optional Expiration (Default = Lifetime)

Each client credential can have an optional `expiresAt` timestamp.

- No `expiresAt` => credential is lifetime
- With `expiresAt` => credential expires at that date/time and verification returns `401` after expiry

## 4 Required Client Helpers (Admin)

The library exposes 4 helpers for client lifecycle:

1. `create` (create HMAC credentials and return full info)
2. `listClientIds` (list all client IDs in API namespace)
3. `delete` (remove one client ID)
4. `regenerateSecret` (rotate/regenerate one client secret)

### 1. Create HMAC Credentials (returns details)

```ts
const created = await hmacAuth.clients.create({
  clientId: "partner_a",
  expiresAt: null, // optional, null/undefined = lifetime
});

console.log(created);
// {
//   clientId,
//   secret,      <-- plain secret (show once, store securely)
//   secretHash,
//   createdAt,
//   updatedAt,
//   expiresAt
// }
```

### 2. See All API clientIds

```ts
const ids = await hmacAuth.clients.listClientIds();
console.log(ids);
```

### 3. Delete One clientId

```ts
await hmacAuth.clients.delete("partner_a");
```

### 4. Regenerate Secret For a clientId

```ts
const rotated = await hmacAuth.clients.regenerateSecret("partner_a", {
  // optional:
  // expiresAt: Date.now() + 24 * 60 * 60 * 1000,
  // preserveExpiresAt: true
});

console.log(rotated.secret); // new plain secret (show once, store securely)
```

## Low-level Verify (Non-Express)

```ts
const verified = await hmacAuth.verifyHmacRequest({
  method,
  path,
  headers,
  rawBody,
});
```

## Signature Payload

```txt
METHOD\n
PATH_WITH_QUERY\n
TIMESTAMP_MS\n
NONCE\n
SHA256(BODY)
```
