# Changelog

All notable changes to this project are documented in this file.

Only Conventional Commit types `feat`, `fix`, `chore`, and `docs` are listed below.

## [Unreleased]

- `feat(http): add optional onBadSignature callback in initializeHmacHttpAuth for BAD_SIGNATURE attempts`
- `feat(http): pass middleware request metadata (ip/forwardedFor/remoteAddress) to onBadSignature callback`
- `docs(http): document onBadSignature callback in root, Express, and NestJS guides`

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
