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
  index.ts                              # single public entrypoint - all exports go through here
  core/
    crypto.ts                           # hashClientSecret, signRequest, buildSigningPayload, safeEqualHex
    errors.ts                           # HmacAuthError + 15 typed error codes
    ip.ts                               # IPv4/IPv6 + CIDR parsing, normalizeAllowedIpRules, isClientIpAllowed
    types.ts                            # all public TypeScript types
    utils.ts                            # normalizePath, getHeader, generateNonce, toBodyString, toMessageString (deep-sort)
  http/
    init.ts                             # initializeHmacHttpAuth orchestration only (wires every unit below)
    constants.ts                        # DEFAULT_MAX_SKEW_MS, DEFAULT_SECRET_LENGTH_BYTES, DEFAULT_DB_SEED_BACKUP_TTL_SECONDS
    internal-helpers.ts                 # parsing payload, route-path normalization, asserts, error mapping
    internal-management.ts              # createInternalManagementHandler (GET / POST / PUT / PATCH / DELETE on the management route)
    middlewares.ts                      # createHttpMiddlewareFactory + createInternalManagementMiddlewareFactory (Express)
    propagate.ts                        # createPropagateClientToApis (fans create/update/delete/health/revert across targets)
    client/
      signed-fetch.ts                   # buildHttpSignedHeaders, signedHttpFetch, createHttpSignedFetchClient
    server/
      express.ts                        # captureRawBody, createExpressHttpHmacMiddleware, createHttpHmacMiddleware
      verify.ts                         # verifyHttpSignature (skew, allowedIps, nonce replay, signature compare)
  message/
    init.ts                             # initializeHmacMessageAuth (sign/verify + clients via shared factory)
    signature.ts                        # signMessage, verifyMessage (no skew, no replay - intentional)
  runtime/
    create-runtime.ts                   # high-level wrappers: createSignedFetchFromClientId, signedFetchWithClientId, hmacHttpMiddleware
  stores/
    redis.ts                            # public façade re-exporting every store symbol below
    redis-client.ts                     # RedisLikeClient + assertRedisClient + low-level command wrappers
    namespace.ts                        # resolveNamespace + buildRedisNamespaceKeys
    credential-record.ts                # StoredClientCredentialRecord + parseStoredClientRecord (legacy-tolerant)
    credential-store.ts                 # RedisCredentialStore (clients hash + credentials-backup TTL keys, v1.2.0)
    nonce-store.ts                      # RedisNonceStore (single-use replay protection)
    credentials-clients-factory.ts      # createCredentialsClientsFactory shared by HTTP + message init (create/regen/setSecret/setSecretHash/setAllowedIps/get/list/delete/revert)
```

## Responsibilities

- **`core`**: shared primitives. Pure functions, no Redis, no I/O. The dependency floor of every other domain.
- **`http`**: HTTP authentication orchestration. Split per business-logic concern; `init.ts` only wires the units together.
  - `init.ts` returns `InitializedHmacHttpAuth` by composing the units below into a single object exposing `clients`, the management handler, both middleware factories, and `propagateClientToApis`. Kept short on purpose.
  - `internal-management.ts` is the route handler. Dispatches GET (health) / POST (create) / PUT (update) / PATCH (revert, v1.2.0) / DELETE (delete), and routes write ops to the HTTP store or the message-bridge store based on `payload.kind`.
  - `propagate.ts` is the source-side fan-out. Builds the wire payload (secretHash, never the plain secret), picks the HTTP verb from `operation`, and posts to every target.
  - `middlewares.ts` adapts the management handler and the request verifier to Express, with consumer-overridable error handler and bad-signature hook.
  - `internal-helpers.ts` + `constants.ts` hold the parsing, normalization, asserts and default values shared by the units above.
  - `server/verify.ts` is the entry point on the receiving side: enforces missing-header, skew, unknown client, expired client, allowed-IP filter, signature compare, nonce-replay.
  - `server/express.ts` adapts the verifier to the Express middleware signature (also reused by NestJS via the platform-express adapter).
  - `client/signed-fetch.ts` produces signed outbound calls, ready for cross-service invocations.
- **`message`**: message signing/verification for async transports (RabbitMQ, Kafka, SQS, ...). The canonical serialization in `core/utils.ts` (`toMessageString`) deep-sorts object keys so producers and consumers compute the same string regardless of property order. No anti-replay and no timestamp skew - those guarantees are intentionally delegated to the transport.
- **`runtime`**: optional high-level helpers built on top of an already-initialized `InitializedHmacHttpAuth`. Wraps the common patterns "sign a fetch using a clientId stored in Redis" and "Express middleware with a clientId allowlist".
- **`stores`**: Redis persistence layer. Decomposed by concern; `redis.ts` is the public façade that re-exports every symbol below for back-compat.
  - `redis-client.ts` holds the `RedisLikeClient` interface, `assertRedisClient`, and the low-level command wrappers (`redisHGet`, `redisHSet`, `redisHDel`, `redisHKeys`, `redisGet`, `redisSet*`, `redisDel`) that paper over the camelCase (node-redis) vs lowercase (ioredis) split.
  - `namespace.ts` exposes `resolveNamespace` and `buildRedisNamespaceKeys` so every store derives the exact same `<namespace>:clients`, `<namespace>:nonce`, `<namespace>:credentials-backup` prefixes.
  - `credential-record.ts` defines `StoredClientCredentialRecord` and `parseStoredClientRecord` with a legacy-tolerant fallback (records that contain only the secretHash as a bare string still parse cleanly, so pre-record-format data stays readable on upgrade).
  - `credential-store.ts` exposes `RedisCredentialStore`: reads/writes the JSON record `{secretHash, createdAt, updatedAt, expiresAt, allowedIps, fromDbSeed}` under `<namespace>:clients`, plus the v1.2.0 backup keys at `<namespace>:credentials-backup:<clientId>` with native Redis TTL.
  - `nonce-store.ts` exposes `RedisNonceStore`: reserves `SET NX EX` keys under `<namespace>:nonce:*` to enforce single-use nonces within `maxSkewMs`.
  - `credentials-clients-factory.ts` exposes `createCredentialsClientsFactory`: the shared CRUD + revert factory that both `initializeHmacHttpAuth` and `initializeHmacMessageAuth` consume on top of a `RedisCredentialStore`. Centralizing it eliminates 200+ lines of duplication between the two `init.ts` files and keeps both stores in lockstep when the lifecycle evolves.
  - `fromDbSeed` (v1.2.0) is a passive origin marker stored in the record: `false` for static (microservice config / internal code), `true` when injected by a dynamic DB-seed pipeline. Always optional on the wire; default `false` keeps the v1.0.x/1.1.x payload bytes-identical. Gates the automatic backup-TTL write on rotation.

## Two control planes (since 1.2.0)

The library serves two independent control planes that share the same wire format but are activated by different consumers and have different lifecycles. They are designed to coexist on the same `internalManagementRoute` and the same Redis namespace without interfering with each other.

### Plane A: static control plane (1.0.x / 1.1.x, default)

- **Source of truth**: consumer-side static config (typically `microservice.cfg.ts`), fed by CI/CD variables (e.g. GitLab group variables like `HMAC_<CLIENTID>_SECRET`).
- **Lifecycle**: baked at deploy time. The secrets never rotate at runtime; a rotation requires a new deploy.
- **Use case**: signing inter-service technical calls (orchestration, propagation triggers, health probes, internal management routes). These credentials authenticate the "control plane" itself.
- **Wire shape**: `fromDbSeed` is omitted on the payload (the lib only emits the flag when explicitly `true`). Byte-identical to 1.0.x/1.1.x.
- **Redis footprint**: only the `<namespace>:clients` hash record. No backup key is ever written for these credentials (triple-gated in `setSecret`/`setSecretHash`: `fromDbSeed === true` + `existing` + `secretHash !== newHash`, all three must hold).
- **Rollback**: not supported and not needed. A failed propagation on a static credential at boot is an operator issue, fixed by re-deploying.

### Plane B: dynamic control plane (1.2.0, opt-in)

- **Source of truth**: a database (or any external dynamic store) on the source API side. The lib is agnostic to the store; it only sees `fromDbSeed: true` on the propagation payload.
- **Lifecycle**: runtime-rotatable. The source API runs a pipeline (typically a cron) that reads its DB and pushes credentials to other APIs.
- **Use case**: managing and sharing HMAC credentials that authenticate **data-plane** clients (external consumers of the source API's business endpoints). The source API acts as the credential authority for these clients across a federation of target APIs.
- **Wire shape**: payload carries `fromDbSeed: true`. The target stores the flag in its credential record. The target also writes a TTL backup of the previous secretHash before overwriting, so a partial-failure rollback is possible.
- **Redis footprint per credential**: the `<namespace>:clients` hash record **plus** an ephemeral `<namespace>:credentials-backup:<clientId>` key with native Redis TTL (default 600s, configurable via `dbSeedBackupTtlSeconds` on both `initializeHmacHttpAuth` and `initializeHmacMessageAuth`).
- **Rollback**: scenario 1 (REVERT explicit). The source API calls `propagateClientToApis({ operation: "revert", targets: acceptedTargets, clientId })` (a PATCH on the same `internalManagementRoute`) to restore the previous secretHash from the TTL backup. The same lib also exposes `clients.revert(clientId)` to roll back the local Redis. No-op if the backup has expired or never existed.

### Coexistence rules

- A consumer can use Plane A alone (omit `fromDbSeed`, never call `revert`). The lib behaves exactly like 1.0.x/1.1.x. Zero extra Redis keys, zero extra surface.
- A consumer can use Plane B in addition to Plane A; the two never share a `clientId` namespace in practice (the static config and the dynamic store hold different sets).
- A target that receives propagation from Plane A on a `clientId`, then later receives Plane B on the **same** `clientId`, sees its record's `fromDbSeed` flip to `true` and gains a backup TTL on the next rotation. This is by design (the lib trusts the source's declaration), and a sensible consumer guarantees uniqueness across the two stores upstream.

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
