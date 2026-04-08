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
  });
}
```

## 4) Express App Setup

Important: attach `captureRawBody` to `express.json(...)` so signature verification uses the exact raw payload.

```ts
import express from "express";
import { captureRawBody } from "@naskot/node-hmac-auth";

const app = express();

app.use(
  express.json({
    verify: (req, res, buf) => captureRawBody(req as any, res, buf),
  }),
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
- Bad signature -> `401`
- Expired client secret -> `401`
- Replayed nonce -> `401`

Headers used by verifier:

- `x-client-id`
- `x-timestamp`
- `x-nonce`
- `x-signature`

Note: `createExpressHttpMiddleware()` is available as explicit Express middleware naming.
