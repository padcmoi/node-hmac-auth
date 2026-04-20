# Architecture (Contributors)

This document describes the internal source layout of `@naskot/node-hmac-auth`.

## Goals

- Keep one stable public entrypoint: `src/index.ts`.
- Group implementation by domain (`core`, `http`, `message`, `runtime`, `stores`).
- Keep framework adapters separate from reusable core logic.

## Source Layout

```txt
src/
  index.ts
  core/
    crypto.ts
    errors.ts
    ip.ts
    types.ts
    utils.ts
  http/
    init.ts
    client/
      signed-fetch.ts
    server/
      express.ts
      verify.ts
  message/
    init.ts
    signature.ts
  runtime/
    create-runtime.ts
  stores/
    redis.ts
```

## Responsibilities

- `core`: shared primitives (types, hashing/signing, IP/CIDR logic, generic utilities, errors).
- `http`: HTTP auth orchestration, request verification, middleware adapters, signed fetch client.
- `message`: message signing/verification helpers for async transports.
- `runtime`: high-level helper factory built on top of initialized HTTP auth.
- `stores`: Redis persistence layer (credentials + nonce replay protection).

## Public API Rule

- Export public symbols only from `src/index.ts`.
- Internal files can move, but public exports must stay stable unless intentionally released as a breaking change.

## Import Conventions

- Prefer imports by domain path (for example `../core/types.js`).
- Avoid circular dependencies between domains.
- `core` should stay dependency-light and reusable by other domains.

## Change Workflow

- Add/modify code in the relevant domain folder.
- Re-export intentionally public additions in `src/index.ts`.
- Validate with:
  - `npm run check`
  - `npm test`
