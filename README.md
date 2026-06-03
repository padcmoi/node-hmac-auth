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
- Wire contract (canonical spec for cross-language ports, v1.3.0+): [docs/wire-contract.md](./docs/wire-contract.md)
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
- `my_company_prod:credentials-backup:*` (v1.2.0, written only when a credential with `fromDbSeed=true` is rotated; native TTL, used by `clients.revert(clientId)` and the PATCH revert operation)

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
  - `options.dbSeedBackupTtlSeconds?` (v1.2.0, default 600)
  - `options.requireBootstrapClientId?` (default `"self_propagation_signer"` since v1.4.0; the bootstrap-window lock is always active and refuses every signed request + every non-named management write until the resolved clientId is stored locally — see [docs/wire-contract.md](./docs/wire-contract.md))

`event` contains `clientId`, `method`, `path`, `timestamp`, `nonce`, `receivedSignature`, `expectedSignature`, `headers`, `rawBody`, and optional `metadata`.

- `initializeHmacMessageAuth(options)` (recommended for message signing + verification)
  - `options.redis` (required)
  - `options.namespace?`
  - `options.defaultSecretLengthBytes?`
  - `options.secretToken?`
  - `options.dbSeedBackupTtlSeconds?` (v1.2.0, default 600)
  - `options.requireBootstrapClientId?` (default `"self_propagation_signer"` since v1.4.0; same semantics as the HTTP variant)

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

- `GET`: healthcheck (always open; the body emits `bootstrapLocked: true` as long as the federation-default clientId is not stored)
- `POST`: create/propagate client (`201` accepted, `403` refused)
- `PUT`: update secret (`201` accepted, `403` refused)
- `PATCH`: revert credential to the previous secretHash from the v1.2.0 TTL backup (`201` accepted, `403` refused)
- `DELETE`: delete client (`201` accepted, `403` refused)

Security rule:

- If at least one client exists, route requires valid HMAC auth.
- While locked (the federation-default propagation clientId is not yet stored locally), only `POST` for that exact clientId is accepted; `PUT` / `PATCH` / `DELETE` and `POST` for any other clientId are refused with HTTP 403 `BOOTSTRAP_LOCKED`. The lock auto-releases the moment the propagation credential is written.

## Release notes

- 1.4.0 — security release; closes a bootstrap-window gap present in 1.0.0-1.3.0 where the credential store accepted any first writer. `requireBootstrapClientId` now resolves to `"self_propagation_signer"` by default so a fresh install joins the federation safely. Versions 1.0.0-1.3.0 are deprecated. ([docs/release-notes/1.4.0.md](./docs/release-notes/1.4.0.md))
- 1.3.0 — `purpose: "propagation-only"` credential cantonment + `requireBootstrapClientId` bootstrap-window lock + canonical wire contract & test vectors ([docs/release-notes/1.3.0.md](./docs/release-notes/1.3.0.md))
- 1.2.0 — dynamic DB-seed origin marker, TTL backup, REVERT operation ([docs/release-notes/1.2.0.md](./docs/release-notes/1.2.0.md))
- 1.1.1 — re-export `HmacPropagateTargetStore` + `HmacMessageAuthBridge` from the index (fix omitted in 1.1.0) ([docs/release-notes/1.1.1.md](./docs/release-notes/1.1.1.md))
- 1.1.0 — propagation can also target the message credential store ([docs/release-notes/1.1.0.md](./docs/release-notes/1.1.0.md))
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
