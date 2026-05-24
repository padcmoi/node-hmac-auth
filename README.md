# node-hmac-auth

Simple, reusable HMAC authentication for Node.js APIs and microservices.

Redis is mandatory.

[![npm version](https://img.shields.io/npm/v/%40naskot%2Fnode-hmac-auth)](https://www.npmjs.com/package/@naskot/node-hmac-auth)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

## Documentation

- Install, config, and usage guide (Express): [docs/express/README.md](./docs/express/README.md)
- Install, config, and usage guide (NestJS): [docs/nestjs/README.md](./docs/nestjs/README.md)
- Docker POC (Nest + Express + Redis, key propagation): [poc/README.md](./poc/README.md)
- Changelog: [CHANGELOG.md](./CHANGELOG.md)

## Compatibility

- TypeScript: native typings included (`dist/index.d.ts`)
- JavaScript runtimes: Node.js `>= 18`
- Module formats: ESM + CommonJS
- Framework support: framework-agnostic core + Express adapter
- Storage: Redis required

## Redis Key Glossary

For namespace `my_company_prod`:

- `my_company_prod:clients` (hash map of client credentials)
- `my_company_prod:nonce:*` (anti-replay nonce keys)

## Header Glossary

Incoming signed requests are validated with:

- `x-client-id`
- `x-timestamp` (epoch ms)
- `x-nonce`
- `x-signature`

## Signature Glossary

Signing payload:

```txt
METHOD\n
PATH_WITH_QUERY\n
TIMESTAMP_MS\n
NONCE\n
SHA256(BODY)
```

## API Glossary

### Initialization

- `initializeHmacHttpAuth(options)` (recommended for HTTP routes + signed fetch)
  - `options.redis` (required)
  - `options.namespace?`
  - `options.maxSkewMs?`
  - `options.defaultSecretLengthBytes?`
  - `options.secretToken?`
  - `options.onBadSignature?(event)`
  - `options.internalManagementRoute?` (ex: `/api/internal/hmac`)

`event` contains `clientId`, `method`, `path`, `timestamp`, `nonce`, `receivedSignature`, `expectedSignature`, `headers`, `rawBody`, and optional `metadata`.

- `initializeHmacMessageAuth(options)` (recommended for message signing + verification)
  - `options.redis` (required)
  - `options.namespace?`
  - `options.defaultSecretLengthBytes?`
  - `options.secretToken?`

### Verify helpers

- `verifyHttpRequest(req, res, next)`: middleware usage (default middleware signature)
- `verifyHttpSignature(input)`: low-level verifier usage (framework-agnostic input object)
- `createHttpMiddleware(options?)`: generic middleware factory (recommended name)
- `createExpressHttpMiddleware(options?)`: alias kept for backward compatibility

Middleware example:

```ts
app.use("/secure", hmacAuth.verifyHttpRequest);
```

### Fetch helpers

- `buildHttpSignedHeaders(input)`
- `signedHttpFetch(url, options)`
- `createHttpSignedFetchClient(options)`

### Internal HTTP key-management helpers

Enabled only when `internalManagementRoute` is configured.

- `handleInternalManagementRequest(input)`
- `createInternalManagementMiddleware(options?)`
- `createExpressInternalManagementMiddleware(options?)`
- `propagateClientToApis(options)`

Route behavior for `internalManagementRoute`:

- `GET`: healthcheck
- `POST`: create/propagate client (`201` accepted, `403` refused)
- `PUT`: update secret (`201` accepted, `403` refused)
- `DELETE`: delete client (`201` accepted, `403` refused)

Security rule:

- If at least one client exists, route requires valid HMAC auth.
- If no client exists yet, bootstrap creation is allowed (first key).

## Release notes

- 1.0.0 — propagation: hash-on-the-wire + Redis fallback ([docs/release-notes/1.0.0.md](./docs/release-notes/1.0.0.md))

### Message helpers

- `signMessage(input)`: low-level message signer (with explicit secret)
- `verifyMessage(input)`: low-level message signature verifier
- `hmacMessageAuth.signMessage({ clientId, message })`: Redis-backed message signer
- `hmacMessageAuth.verifyMessage({ clientId, message, signature })`: Redis-backed message verifier

Message helpers intentionally do not enforce timestamp skew checks or anti-replay.

### Credential helpers

- `clients.create({ clientId, plainSecret?, expiresAt?, secretLengthBytes?, allowedIps? })`
- `clients.listClientIds()`
- `clients.get(clientId)`
- `clients.delete(clientId)`
- `clients.regenerateSecret(clientId, { plainSecret?, secretLengthBytes?, expiresAt?, preserveExpiresAt?, allowedIps? })`
- `clients.setSecret(clientId, plainSecret, expiresAt?, allowedIps?)`
- `clients.setSecretHash(clientId, secretHash, expiresAt?, allowedIps?)`
- `clients.setAllowedIps(clientId, allowedIps)`
- `clients.getSecretHash(clientId)`

`allowedIps` supports IPv4/IPv6 exact IP and CIDR strings (examples: `195.7.8.9`, `195.7.8.0/24`).
If empty (or omitted), any source IP is accepted.
