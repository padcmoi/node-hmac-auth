# Architecture (Contributors)

This document describes the internal source layout of `@naskot/node-hmac-auth` and the contract each domain holds. It is meant for contributors and reviewers; consumer documentation lives in [docs/express/README.md](./express/README.md), [docs/nestjs/README.md](./nestjs/README.md), and [docs/release-notes/](./release-notes/).

## Goals

- Keep one stable public entrypoint: `src/index.ts`.
- Group implementation by domain (`core`, `http`, `message`, `runtime`, `stores`).
- Keep framework adapters separate from reusable core logic.
- Make Redis the only required external dependency.

## Source layout

```txt
src/
  index.ts                       # single public entrypoint - all exports go through here
  core/
    crypto.ts                    # hashClientSecret, signRequest, buildSigningPayload, safeEqualHex
    errors.ts                    # HmacAuthError + 15 typed error codes
    ip.ts                        # IPv4/IPv6 + CIDR parsing, normalizeAllowedIpRules, isClientIpAllowed
    types.ts                     # all public TypeScript types
    utils.ts                     # normalizePath, getHeader, generateNonce, toBodyString, toMessageString (deep-sort)
  http/
    init.ts                      # initializeHmacHttpAuth (clients CRUD + internal management + propagation)
    client/
      signed-fetch.ts            # buildHttpSignedHeaders, signedHttpFetch, createHttpSignedFetchClient
    server/
      express.ts                 # captureRawBody, createExpressHttpHmacMiddleware, createHttpHmacMiddleware
      verify.ts                  # verifyHttpSignature (skew, allowedIps, nonce replay, signature compare)
  message/
    init.ts                      # initializeHmacMessageAuth (clients CRUD + sign/verify)
    signature.ts                 # signMessage, verifyMessage (no skew, no replay - intentional)
  runtime/
    create-runtime.ts            # high-level wrappers: createSignedFetchFromClientId, signedFetchWithClientId, hmacHttpMiddleware
  stores/
    redis.ts                     # RedisCredentialStore, RedisNonceStore + RedisLikeClient adapter
```

## Responsibilities

- **`core`**: shared primitives. Pure functions, no Redis, no I/O. The dependency floor of every other domain.
- **`http`**: HTTP authentication orchestration.
  - `init.ts` is the orchestrator: it wires `core/crypto` + `stores/redis` into a coherent `InitializedHmacHttpAuth` object exposing `clients` CRUD, the internal-management route (`handleInternalManagementRequest` + middlewares), and `propagateClientToApis`.
  - `server/verify.ts` is the entry point on the receiving side: enforces missing-header, skew, unknown client, expired client, allowed-IP filter, signature compare, nonce-replay.
  - `server/express.ts` adapts the verifier to the Express middleware signature (also reused by NestJS via the platform-express adapter).
  - `client/signed-fetch.ts` produces signed outbound calls, ready for cross-service invocations.
- **`message`**: message signing/verification for async transports (RabbitMQ, Kafka, SQS, ...). The canonical serialization in `core/utils.ts` (`toMessageString`) deep-sorts object keys so producers and consumers compute the same string regardless of property order. No anti-replay and no timestamp skew - those guarantees are intentionally delegated to the transport.
- **`runtime`**: optional high-level helpers built on top of an already-initialized `InitializedHmacHttpAuth`. Wraps the common patterns "sign a fetch using a clientId stored in Redis" and "Express middleware with a clientId allowlist".
- **`stores`**: Redis persistence layer.
  - `RedisCredentialStore` reads/writes the JSON record `{secretHash, createdAt, updatedAt, expiresAt, allowedIps}` under the hash key `<namespace>:clients`.
  - `RedisNonceStore` reserves `SET NX EX` keys under `<namespace>:nonce:*` to enforce single-use nonces within `maxSkewMs`.
  - The `RedisLikeClient` interface accepts both the camelCase API (node-redis style: `hGet`, `hSet`, ...) and the lowercase API (ioredis style: `hget`, `hset`, ...).

## Cross-cutting contracts

### Hashing pipeline

- `hashClientSecret(secret, secretToken?)` is the **only** hashing primitive. If `secretToken` is empty it falls back to `sha256(secret)`; otherwise it returns `hmac-sha256(secretToken, secret)`. This is what HMAC_SECRET_TOKEN does in practice.
- Stored credentials never contain the plain secret - only the hash. The plain secret is held in memory exactly long enough to be hashed and forwarded to Redis.

### Signing pipeline

- `buildSigningPayload({method, path, timestamp, nonce, body})` returns the canonical string:
  ```
  METHOD\n
  PATH_WITH_QUERY\n
  TIMESTAMP_MS\n
  NONCE\n
  SHA256(BODY)
  ```
- `signRequest(input)` computes `hmac-sha256(secret, buildSigningPayload(input))`. The "secret" here is either the stored `secretHash` (when `secretIsHashed: true`, the typical case on both sides) or the plain secret pre-hashed locally.
- Verification on the server side calls `signRequest` with the stored `secretHash` and compares with `safeEqualHex` (constant-time). Identical hashes on both sides means identical signatures.

### Propagation contract (since 1.0.0)

`propagateClientToApis` resolves the `secretHash` shipped on the wire from three possible sources, in this order:

1. Explicit `secretHash` from the caller (override).
2. Local Redis lookup on `clientId` (when both `secret` and `secretHash` are omitted).
3. `hashClientSecret(secret, localSecretToken)` from the caller-provided plain `secret`.

The payload sent to the target carries `secretHash` (never `secret`). The target's `handleInternalManagementRequest` stores the value as-is via `clients.setSecretHash`. Source and target Redis end up with byte-identical hashes, so signed HTTP requests verify across services that do NOT share the same `HMAC_SECRET_TOKEN`. Full description and diagrams are in [docs/release-notes/1.0.0.md](./release-notes/1.0.0.md) and [docs/diagrams/seq-propagation.puml](./diagrams/seq-propagation.puml).

The bootstrap-then-auth rule on the internal-management route is unchanged: when target Redis has zero clients, the first POST is accepted without signature. Beyond that, the verifier in `server/verify.ts` runs to completion.

## Public API rule

- Export public symbols only from `src/index.ts`.
- Internal files can move, but public exports must stay stable unless intentionally released as a breaking change. Major version bumps document any such break in [CHANGELOG.md](../CHANGELOG.md).

## Import conventions

- Prefer imports by domain path (for example `../core/types.js`).
- Avoid circular dependencies between domains.
- `core` should stay dependency-light and reusable by every other domain. It depends only on Node built-ins (`node:crypto`, `node:net`).
- Domains may import from `core` freely. Cross-imports between `http`, `message`, `runtime`, `stores` should go through a clearly identified seam (typically `http/init.ts` is the orchestrator that pulls everything together).

## Change workflow

- Add or modify code in the relevant domain folder. Keep `core/` reusable; everything that touches Redis or a framework adapter belongs in `http/`, `message/`, `runtime/`, or `stores/`.
- Re-export intentionally public additions in `src/index.ts`. If a type is purely internal (helper, narrow wrapper), keep it unexported.
- Validate with:
  - `npm run check` - `tsc --noEmit` over the source.
  - `npm test` - vitest suite under `test/`. Add a focused case in the matching `test/<domain>.test.ts` file. The propagation contract is covered by `test/propagation.test.ts`.
  - `npm run lint` - ESLint over `src/**/*.ts`.
  - `npm run build` - tsup produces `dist/index.{js,cjs,d.ts,d.cts}`. Required before any release.
- `npm run prepublishOnly` chains check + test + build. This is the gate before publishing a tag.
- Run the POC (`poc/docker-compose.yml`) when changing anything that affects the wire format, the internal-management route, or the propagation flow. The POC ships with distinct `HMAC_SECRET_TOKEN` values across `nest_source` / `nest_target` / `express_target` so cross-token behavior is exercised end-to-end at every change.

## Related documentation

- Consumer guides: [docs/express/README.md](./express/README.md), [docs/nestjs/README.md](./nestjs/README.md).
- Release notes (current version): [docs/release-notes/1.0.0.md](./release-notes/1.0.0.md).
- Sequence and component diagrams: [docs/diagrams/](./diagrams/).
- POC playground: [poc/README.md](../poc/README.md).
