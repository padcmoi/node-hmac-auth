# Changelog

All notable changes to this project are documented in this file.

Only Conventional Commit types `feat`, `fix`, `chore`, and `docs` are listed below.

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
