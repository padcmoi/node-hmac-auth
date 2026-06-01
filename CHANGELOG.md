# Changelog

All notable changes to this project are documented in this file.

Only Conventional Commit types `feat`, `fix`, `chore`, and `docs` are listed below.

## [1.3.0] - 2026-06-01

Minor release. Strictly additive on top of 1.2.x. 1.0.x/1.1.x/1.2.x consumers upgrade without code, wire, or Redis-layout change. Defaults reproduce 1.2.x byte-identical behavior; opt-in via the two new options below.

- `feat(types): add HmacCredentialPurpose type ("any" | "propagation-only") + optional purpose field on HmacClientCredential, CreateHmacClientOptions, HmacCredentialWriteOptions, PropagateHmacClientOptions, StoredClientCredentialRecord (legacy-tolerant parse)`
- `feat(types): InitializeHmacHttpAuthOptions and InitializeHmacMessageAuthOptions accept optional requireBootstrapClientId; VerifyHttpSignatureInput accepts optional internalManagementRoute + requireBootstrapClientId for the same enforcement layer`
- `feat(http): verifyHttpSignature rejects requests matched against a credential whose stored purpose is "propagation-only" unless the path equals the configured internalManagementRoute; new error code PROPAGATION_ONLY_FORBIDDEN (HTTP 403)`
- `feat(http): verifyHttpSignature rejects every signed business request with BOOTSTRAP_LOCKED (HTTP 403) until a credential with the configured requireBootstrapClientId is stored locally; handleInternalManagementRequest keeps GET open with bootstrapLocked: true in the body, accepts POST only for the named clientId, refuses PUT/PATCH/DELETE while locked`
- `feat(http): propagateClientToApis emits an optional purpose field on the wire payload when explicitly set; wire bytes-identical to 1.2.x when omitted`
- `feat(http): handleInternalManagementRequest parses an optional purpose field from POST/PUT bodies and persists it on the credential record so subsequent verify calls enforce the cantonment without any external lookup`
- `feat(message): initializeHmacMessageAuth honors requireBootstrapClientId by throwing BOOTSTRAP_LOCKED on signMessage/verifyMessage until the named credential is stored; both methods also refuse credentials carrying purpose: "propagation-only" with PROPAGATION_ONLY_FORBIDDEN`
- `feat(stores): credentials-clients-factory threads purpose through create / regenerateSecret / setSecret / setSecretHash / setAllowedIps / revert; mapCredential surfaces the field on every read path`
- `docs(wire-contract): add docs/wire-contract.md as the single source of truth for the wire (cryptographic primitives, headers, Redis layout, internal management route shape, error codes, v1.3.0 additions). Cross-language ports certify against this document plus test/vectors/*.json`
- `test(vectors): add test/vectors/hash-client-secret.json (20 cases), test/vectors/sign-request.json (33 cases), test/vectors/internal-route-flows.json (5 multi-step flows incl. bootstrap-locked + propagation-only); wire-vectors.test.ts loads them and asserts the lib still matches byte-identical`
- `test(http+message): add http-purpose-cantonment.test.ts (5 cases), http-bootstrap-locked.test.ts (6 cases), message-purpose-bootstrap.test.ts (2 cases) covering F1 + F2 happy paths, error codes and 1.2.x backward-compat`
- `demo(poc): nest_source runs runV1_3_0_Demo() at boot in an isolated Redis namespace; logs PASS/FAIL per assertion (GET bootstrapLocked, POST/PUT/PATCH/DELETE gating, bootstrap release, purpose cantonment on business vs management route, signMessage refusal)`
- `docs(release-notes+architecture+readme): docs/release-notes/1.3.0.md (long-form), architecture.md gains a "v1.3.0 additions" section, README links to docs/wire-contract.md`
- `docs(express+nestjs): update both consumer guides for v1.2.0 (PATCH revert, dbSeedBackupTtlSeconds, fromDbSeed, propagateClientToApis revert) and v1.3.0 (requireBootstrapClientId, purpose, BOOTSTRAP_LOCKED, PROPAGATION_ONLY_FORBIDDEN, bootstrapLocked GET body, propagate.revert in the complete shared service example) + link to docs/wire-contract.md`
- `docs(diagrams): seq-bootstrap-lock.puml + seq-purpose-cantonment.puml (NEW) illustrate F1 and F2 end-to-end; architecture.puml, seq-propagation.puml, seq-propagation-message.puml, seq-signed-fetch.puml and seq-message.puml updated for the v1.3.0 enforcement layers (purpose? on the wire, BOOTSTRAP_LOCKED + PROPAGATION_ONLY_FORBIDDEN branches, bootstrapLocked on the health body); all PNGs regenerated`

## [1.2.0] - 2026-05-25

- `feat(types): add optional fromDbSeed flag on PropagateHmacClientOptions, HmacClientCredential (optional on the public type for true 1.0.x/1.1.x type-level backward compatibility) and StoredClientCredentialRecord (passive origin marker, default false, omitted on the wire when not explicitly true)`
- `feat(types): CreateHmacClientOptions accepts optional fromDbSeed so clients.create can tag the initial record at creation time (default false keeps the 1.0.x/1.1.x record shape unchanged)`
- `feat(stores): RedisCredentialStore writes/reads/clears credentials-backup:<clientId> with TTL (redisSetEx + redisGet + redisDel helpers; assertRedisClient now also requires get + del)`
- `feat(http+message): clients.setSecret and clients.setSecretHash accept HmacCredentialWriteOptions { fromDbSeed?: boolean }; when fromDbSeed=true and an existing record changes hash, the previous secretHash is automatically written to credentials-backup:<clientId> with TTL`
- `feat(http+message): clients.revert(clientId) restores the credential's secretHash from credentials-backup:<clientId> if the key is still alive, clears the backup, preserves fromDbSeed/allowedIps/expiresAt; no-op when no backup exists`
- `feat(types): InitializeHmacHttpAuthOptions and InitializeHmacMessageAuthOptions expose dbSeedBackupTtlSeconds (default 600s)`
- `feat(http): HmacInternalManagementRequestInput accepts PATCH; handleInternalManagementRequest dispatches PATCH to clients.revert (HTTP store by default, message store when payload.kind="message")`
- `feat(http): propagateClientToApis accepts operation: "revert" (sends PATCH /internal-management with { clientId, kind? }); no secret/secretHash/allowedIps sent for revert`
- `feat(types): HmacInternalPropagationOperation union extended with "revert"; HmacMessageAuthBridge.clients gains revert(clientId)`
- `docs(architecture): record schema documented as {secretHash, createdAt, updatedAt, expiresAt, allowedIps, fromDbSeed}; passive marker semantics clarified`
- `docs(diagrams): seq-propagation.puml + seq-propagation-message.puml mention fromDbSeed?; PNGs regenerated`
- `demo(poc): nest-source/src/db-seed.cfg.ts (NEW) holds dynamic origin rows separated from microservice.cfg.ts (static); nest-source runs a revert-demo (rotate update then revert) on each db-seed row after the initial propagation pass; targets log clients with hash=<first12> and backup=<first12|none> alongside fromDbSeed every 10s`
- `refactor(src): split http/init.ts (967->184 lines), message/init.ts (348->146 lines) and stores/redis.ts (279->33 lines, now a façade) into per-business-logic modules (http/{constants,internal-helpers,internal-management,middlewares,propagate}.ts and stores/{redis-client,namespace,credential-record,credential-store,nonce-store,credentials-clients-factory}.ts); zero public-surface change, src/index.ts unchanged, all 36 vitest tests green`

## [1.1.1] - 2026-05-24

- `fix(types): re-export HmacPropagateTargetStore and HmacMessageAuthBridge from the package index (omitted in 1.1.0, forced consumers to inline the literal "http" | "message")`
- `docs(release-notes): add docs/release-notes/1.1.1.md`

## [1.1.0] - 2026-05-24

- `feat(http): propagateClientToApis accepts targetStore?: "http" | "message" (default "http")`
- `feat(http): initializeHmacHttpAuth accepts optional messageAuth bridge`
- `feat(http): handleInternalManagementRequest dispatches on payload.kind to the message store when "message" (403 if messageAuth absent)`
- `test(propagation): 4 new vitest cases - source ships kind=message, target writes to messageAuth, source-side throws without messageAuth, target-side 403 without messageAuth`
- `docs(release-notes): add docs/release-notes/1.1.0.md`
- `docs(diagrams): add seq-propagation-message.puml + update architecture.puml with the messageAuth bridge edge`
- `demo(poc): targets instantiate messageAuth + expose /message/verify; nest-source propagates 2 message clients (msg_amqp_orders, msg_amqp_billing) with targetStore="message"; verifyAllPropagatedMessageClients logs cross-token message verify summary ok=2/2 alongside the HTTP ok=11/11`

## [1.0.0] - 2026-05-23

- `feat(http): propagateClientToApis sends the locally-computed secretHash instead of the plain secret; target stores it as-is via setSecretHash`
- `feat(http): propagateClientToApis falls back to the local Redis credentialStore for secretHash when both secret and secretHash are omitted`
- `feat(types): HmacHttpPropagationPlan.secret is now optional`
- `test(propagation): 4 new vitest cases - hash on the wire, Redis fallback, missing-everything throw, caller secretHash priority`
- `docs(release-notes): add docs/release-notes/1.0.0.md (before/after, resolution priority, FAQ on 3 acceptance scenarios)`
- `docs(diagrams): add docs/diagrams/ with architecture.puml + seq-signed-fetch.puml + seq-propagation.puml + seq-message.puml`
- `docs(architecture): refresh docs/architecture.md with per-file responsibilities, hashing/signing/propagation contracts, prepublishOnly gate`
- `demo(poc): 11 propagated clientIds incl. client_via_redis_lookup (secret omitted), 3 distinct HMAC_SECRET_TOKEN, verifyAllPropagatedClients logs ok=11/11 at boot + every 15s`

## [0.5.4] - 2026-05-15

- `docs(nestjs-decorator): add §6 "Per-Route Protection with a NestJS Decorator" — Reflector + Guard wrapping runtime.hmacHttpMiddleware, with class/method whitelist semantics and method-over-class override. Renumbers former §6-§10 to §7-§11. Library code unchanged`

## [0.5.3] - 2026-04-29

- `docs(nestjs): clarify required body-parser setup for internal management route and add troubleshooting for clientId/auth failures`
- `docs(nestjs): fix complete shared service propagation examples to pass required allowedIps on create/update`
- `docs(readme): add Docker POC reference for Nest + Express + Redis key propagation`
- `demo(poc): add minimal TypeScript docker-compose playground with one source config propagating to Nest and Express targets`
- `demo(poc): add signed /secure/poc communication loop (every 5s) from Nest source to Nest/Express targets with request/response logging`
- `demo(poc): add negative auth scenario with source-only clientId (not propagated) and expected 401/403 logs every 10s`

## [0.5.2] - 2026-04-21

- `fix(ci): use npm trusted publishing with GitHub Actions provenance`

## [0.5.1] - 2026-04-20

- `test ci`

## [0.5.0] - 2026-04-20

- `feat(runtime): add createHmacRuntime factory with createSignedFetchFromClientId and signedFetchWithClientId helpers`
- `feat(runtime): add hmacHttpMiddleware(...clientIds) helper in createHmacRuntime for scoped clientId allowlist on protected routes`
- `feat(security): add per-client allowedIps (IP/CIDR) restriction with 403 enforcement in HTTP verification`
- `feat(http): support allowedIps propagation through internal management route and propagateClientToApis`
- `feat(clients): add allowedIps support to create/regenerate/setSecret/setSecretHash and new setAllowedIps helper`
- `fix(types): expose HmacRuntime as inferred ReturnType<typeof createHmacRuntime> instead of explicit method signatures`
- `fix(types): make propagateClientToApis apiFetch accept both createHttpSignedFetchClient signer and RequestInit-based wrappers`
- `fix(clients): add missing plainSecret option in regenerateSecret (http + message) while preserving random generation fallback`
- `fix(types): relax RedisLikeClient set args typing for node-redis compatibility`
- `feat(http): add internalManagementRoute in initializeHmacHttpAuth with GET/POST/PUT/DELETE management flow`
- `feat(http): add internal management middleware and low-level request handler with bootstrap-then-auth behavior`
- `feat(http): add propagateClientToApis helper for one-to-many key distribution with 201/403 acceptance reporting`
- `docs(http): document internal management route and propagation helpers in root, Express, and NestJS guides`
- `docs(guides): add complete framework-agnostic shared service example to Express and NestJS docs`
- `feat(http): add optional onBadSignature callback in initializeHmacHttpAuth for BAD_SIGNATURE attempts`
- `feat(http): pass middleware request metadata (ip/forwardedFor/remoteAddress) to onBadSignature callback`
- `docs(http): document onBadSignature callback in root, Express, and NestJS guides`
- `chore(refactor): reorganize src into core/http/message/runtime/stores modules with a single public entrypoint`
- `docs(architecture): add contributor architecture guide for core/http/message/runtime/stores layout`
- `chore(tooling): add ESLint + Prettier setup with npm scripts (lint, lint:fix, format)`
- `chore(lint): temporarily relax strict ESLint safety rules for incremental hardening in a future version`

## [0.4.1] - 2026-04-08

- `fix(ci): harden npm publish workflow with strict semver validation and package/tag version checks`
- `fix(ci): skip publish when the target version is already on npm to avoid duplicate publish failures`

## [0.4.0] - 2026-04-08

- `feat(init): add initializeHmacHttpAuth for HTTP route and signed fetch setup`
- `feat(init): remove initializeHmacAuth alias and keep initializeHmacHttpAuth as the only init entrypoint`
- `feat(http): rename verify and middleware helpers to explicit HTTP names (verifyHttpRequest, verifyHttpSignature, createHttpMiddleware)`
- `feat(http): rename fetch signing helpers to explicit HTTP names (buildHttpSignedHeaders, signedHttpFetch, createHttpSignedFetchClient)`
- `feat(message): add dedicated initializeHmacMessageAuth with signMessage/verifyMessage for async message flows`
- `docs(init): update Express and NestJS guides to use initializeHmacHttpAuth`

## [0.3.0] - 2026-04-08

- `feat(middleware): add createMiddleware as a generic alias of createExpressMiddleware`
- `docs(readme): refactor root README into library glossary and move operational usage to framework docs`
- `docs(express): add dedicated Express install/config/usage guide`
- `docs(nestjs): add dedicated NestJS install/config/usage guide`

## [0.2.1] - 2026-04-08

- `fix(ci): trigger npm publish workflow on semver tags without v`

## [0.2.0] - 2026-04-08

- `feat(hmac): add optional secretToken hashing and plainSecret create support`
- `feat(clients): support plainSecret in create helper`
- `chore(release): 0.2.0`

## [0.1.3] - 2026-04-08

- `chore(release): 0.1.3`

## [0.1.2] - 2026-04-08

- `fix(package): add repository metadata for npm provenance`
- `chore(release): 0.1.2`

## [0.1.1] - 2026-04-08

- No `feat` / `fix` / `chore` commit title found for this release.

## [0.1.0] - 2026-04-08

- No `feat` / `fix` / `chore` commit title found for this release.
