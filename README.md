# node-hmac-auth

Simple, reusable HMAC authentication for Node.js APIs.

Redis is mandatory.

[![npm version](https://img.shields.io/npm/v/%40naskot%2Fnode-hmac-auth)](https://www.npmjs.com/package/@naskot/node-hmac-auth)
[![TypeScript Ready](https://img.shields.io/badge/TypeScript-Ready-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Node >= 18](https://img.shields.io/badge/node-%3E%3D18-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

## Documentation

- Install, config, and usage guide (Express): [docs/express/README.md](./docs/express/README.md)
- Install, config, and usage guide (NestJS): [docs/nestjs/README.md](./docs/nestjs/README.md)
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

- `initializeHmacAuth(options)`
  - `options.redis` (required)
  - `options.namespace?`
  - `options.maxSkewMs?`
  - `options.defaultSecretLengthBytes?`
  - `options.secretToken?`

### Verify helpers

- `verifyHmacRequest(input)`: low-level verifier (framework-agnostic)
- `createMiddleware(options?)`: generic middleware factory (recommended name)
- `createExpressMiddleware(options?)`: alias kept for backward compatibility

### Fetch helpers

- `buildSignedHeaders(input)`
- `signedFetch(url, options)`
- `createSignedFetchClient(options)`

### Credential helpers

- `clients.create({ clientId, plainSecret?, expiresAt?, secretLengthBytes? })`
- `clients.listClientIds()`
- `clients.get(clientId)`
- `clients.delete(clientId)`
- `clients.regenerateSecret(clientId, options?)`
- `clients.setSecret(clientId, plainSecret, expiresAt?)`
- `clients.setSecretHash(clientId, secretHash, expiresAt?)`
- `clients.getSecretHash(clientId)`
