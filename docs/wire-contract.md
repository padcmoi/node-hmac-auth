# Wire Contract

This document is the canonical specification of the HMAC wire used by `@naskot/node-hmac-auth`. It is the single source of truth for cross-language ports (Python, Go, Rust, Java, ...) targeting interoperability with Node consumers. Every cryptographic primitive, header name, payload shape, and error code listed below is normative.

The current contract level is `v1.4.0`. Lower-level conformance is supported for historical readers, but published versions before v1.4.0 are deprecated for security reasons (the bootstrap-window lock was opt-in). Each section flags the version that introduced the behavior.

> Companion artifacts (also normative):
>
> - Test vectors: [test/vectors/hash-client-secret.json](../test/vectors/hash-client-secret.json), [test/vectors/sign-request.json](../test/vectors/sign-request.json), [test/vectors/internal-route-flows.json](../test/vectors/internal-route-flows.json).
> - Sequence diagrams: [docs/diagrams/](./diagrams/).

## Cryptographic primitives

### `hashClientSecret(secret, secretToken?)`

```
hashClientSecret(secret, "")    = SHA-256(secret)                    hex lowercase
hashClientSecret(secret, token) = HMAC-SHA256(token, secret)         hex lowercase
```

- `secret` and `token` are UTF-8 strings. Empty `token` (or null/undefined) selects the fallback `SHA-256(secret)`.
- The output is always a 64-character lowercase hex string.
- Targets MUST produce byte-identical output for every case listed in [test/vectors/hash-client-secret.json](../test/vectors/hash-client-secret.json).

### `buildSigningPayload({method, path, timestamp, nonce, body})`

```
METHOD\n
PATH_WITH_QUERY\n
TIMESTAMP_MS\n
NONCE\n
SHA-256(BODY)
```

- `METHOD` is uppercased (`get` → `GET`).
- `PATH_WITH_QUERY` is the request path including any `?query=...` part, normalized so an empty path becomes `/`. The lib's helper `normalizePath` parses `path` against `http://localhost` and emits `pathname + search`.
- `TIMESTAMP_MS` is the integer epoch in milliseconds (matches `Date.now()`).
- `NONCE` is a per-request unique value. UUID, ULID, or 16+ bytes of hex random are all valid.
- `SHA-256(BODY)` is the hex lowercase digest of the raw request body (empty body → digest of the empty string).
- Lines are joined with the literal character `\n` (0x0A). There is no trailing newline.

### `signRequest(input)`

```
signRequest({method, path, timestamp, nonce, body, secret}) =
    HMAC-SHA256(secret, buildSigningPayload(input))   hex lowercase
```

- `secret` is the value the verifier holds locally. In the canonical setup, both ends store the same `secretHash` (because propagation ships the secretHash, never the plain secret), so `secret = secretHash` on both sides.
- Comparison between the received signature and the locally computed one MUST be constant-time. The lib uses `timingSafeEqual` on the hex-decoded bytes; equivalent primitives in other languages (`hmac.compare_digest` in Python, `subtle.ConstantTimeCompare` in Go, ...) are acceptable.
- Targets MUST produce byte-identical output for every case in [test/vectors/sign-request.json](../test/vectors/sign-request.json).

## HTTP transport

### Required headers (request)

| Header         | Value                                                           |
| -------------- | --------------------------------------------------------------- |
| `x-client-id`  | The `clientId` issuing the request.                             |
| `x-timestamp`  | The integer epoch in milliseconds, base-10 string.              |
| `x-nonce`      | Per-request unique value (UUID / ULID / hex random ≥ 16 bytes). |
| `x-signature`  | The hex output of `signRequest`.                                |
| `content-type` | `application/json` for any non-GET request.                     |

Header names are compared case-insensitively. Multiple values are not expected; the lib reads the first occurrence.

### Timestamp skew & nonce replay

- `maxSkewMs` defaults to `5 * 60 * 1000` (5 minutes). Requests with `|now - timestamp| > maxSkewMs` are rejected with HTTP 401 `TIMESTAMP_SKEW`.
- Nonces are stored under `<namespace>:nonce:<clientId>:<nonce>:<timestamp>` with a TTL of `ceil(maxSkewMs / 1000)` seconds via `SET NX EX`. A replay returns 401 `REPLAYED_NONCE`. The keyspace MUST be Redis-compatible (`SET key value NX EX ttl`).

### Internal management route

The path is configured by the consumer (typically `/api/internal/hmac`) and is the SAME path on every API instance. Five verbs are dispatched on this exact path:

| Verb     | Operation          | Description                                                             |
| -------- | ------------------ | ----------------------------------------------------------------------- |
| `GET`    | health probe       | Returns the standard health body. Always safe and idempotent.           |
| `POST`   | create             | Creates a credential. Refuses if the clientId already exists.           |
| `PUT`    | update             | Rotates an existing credential. Refuses if the clientId does not exist. |
| `PATCH`  | revert (`v1.2.0+`) | Restores the previous `secretHash` from the TTL backup.                 |
| `DELETE` | delete             | Drops the credential.                                                   |

The bootstrap window (v1.4.0): when local Redis holds zero credentials, the FIRST POST whose `clientId` equals the resolved propagation clientId (default `"self_propagation_signer"`) is accepted without signature verification (the initial seed). Once that credential is stored, every request MUST carry a valid signature. Pre-v1.4.0 levels relied on the operator to opt in to the lock and are deprecated.

### Health response body (GET)

```json
{
  "ok": true,
  "namespace": "<resolved namespace>",
  "route": "<internalManagementRoute>",
  "authRequired": true,
  "clientsCount": 12,
  "authenticatedBy": "<clientId or null>",
  "bootstrapLocked": false
}
```

- `bootstrapLocked` is `v1.3.0+`. Omitted entirely by lower versions. Targets at `v1.3.0+` SHOULD always emit the field so orchestrators (e.g. `@naskot/node-hmac-auth-management`) can detect the locked state without parsing error responses.

### Write request bodies

`POST` / `PUT`:

```json
{
  "clientId": "data_plane_alpha",
  "secret": "...",
  "secretHash": "...",
  "allowedIps": ["10.0.0.0/24"],
  "expiresAt": 1789999999999,
  "kind": "http",
  "fromDbSeed": true,
  "purpose": "propagation-only"
}
```

- Exactly one of `secret` or `secretHash` MUST be present. When propagating cross-token, `secretHash` is used and source/target Redis end up with byte-identical hashes.
- `allowedIps` is an array of IPv4/IPv6/CIDR strings. Empty array = no allowlist. Omitted = unchanged on update, empty on create.
- `expiresAt` is the integer epoch in ms. Null clears the expiration.
- `kind` (`v1.1.0+`) is one of `"http"` (default) or `"message"`. `"message"` routes the write to the message credential store via the `messageAuth` bridge. Targets MUST 403 with `Message store not configured` if `kind: "message"` is received but no bridge was wired.
- `fromDbSeed` (`v1.2.0+`) marks the credential as DB-seed-originated. Emitted on the wire only when explicitly `true`. Activates TTL-backup writes on rotation.
- `purpose` (`v1.3.0+`) is one of `"any"` (implicit default) or `"propagation-only"`. Emitted on the wire only when explicitly set. Targets at `v1.3.0+` store the value alongside the credential record. Older targets ignore the field (forward-compatible).

`PATCH`:

```json
{
  "clientId": "data_plane_alpha",
  "kind": "http"
}
```

- No secret/secretHash/allowedIps/expiresAt is sent. The target restores the previous `secretHash` from `<namespace>:credentials-backup:<clientId>`. If the backup is missing or expired, the operation returns `reverted: false` with status `201`.

`DELETE`:

```json
{ "clientId": "data_plane_alpha" }
```

### Write response bodies

```json
{
  "ok": true,
  "operation": "create",
  "clientId": "data_plane_alpha",
  "kind": "http"
}
```

- `operation` echoes the verb (`create` for POST, `update` for PUT, `revert` for PATCH, `delete` for DELETE).
- `kind` echoes the routed store (omitted on DELETE in v1.0.x/v1.1.x).
- `reverted: boolean` is added on PATCH.

## Redis layout

The lib organises keys under a configurable `<namespace>` (defaults to the resolved store namespace).

| Key pattern                                        | Type            | Purpose                                                                                       |
| -------------------------------------------------- | --------------- | --------------------------------------------------------------------------------------------- |
| `<namespace>:clients`                              | Hash            | Field per clientId. Value is the JSON-serialized credential record.                           |
| `<namespace>:nonce:<clientId>:<nonce>:<timestamp>` | String (NX, EX) | Single-use replay protection.                                                                 |
| `<namespace>:credentials-backup:<clientId>`        | String (EX)     | Previous `secretHash`, TTL-bounded. Written on `fromDbSeed: true` rotations only. (`v1.2.0+`) |

### Credential record JSON

```json
{
  "secretHash": "<64 hex lowercase>",
  "createdAt": 1700000000000,
  "updatedAt": 1700000000000,
  "expiresAt": null,
  "allowedIps": [],
  "fromDbSeed": false,
  "purpose": "any"
}
```

- `fromDbSeed` (`v1.2.0+`) and `purpose` (`v1.3.0+`) are optional on the parsed shape: records persisted by older versions parse cleanly, with the missing fields treated as `false` and `undefined` respectively. Legacy targets may also store the bare secretHash string instead of a JSON object; readers MUST accept that shape.

## Error codes

Errors are surfaced as the JSON body `{ "error": "<CODE>", "message": "<text>" }`. The HTTP status is set to the value listed below.

| Code                         | Status | Introduced | Meaning                                                                                                                               |
| ---------------------------- | ------ | ---------- | ------------------------------------------------------------------------------------------------------------------------------------- | --------------- | ------------- |
| `MISSING_CLIENT_ID`          | 401    | v1.0.0     | `x-client-id` header missing.                                                                                                         |
| `MISSING_SIGNATURE`          | 401    | v1.0.0     | `x-signature` header missing.                                                                                                         |
| `MISSING_TIMESTAMP`          | 401    | v1.0.0     | `x-timestamp` header missing.                                                                                                         |
| `MISSING_NONCE`              | 401    | v1.0.0     | `x-nonce` header missing.                                                                                                             |
| `INVALID_TIMESTAMP`          | 401    | v1.0.0     | `x-timestamp` is not a finite number.                                                                                                 |
| `TIMESTAMP_SKEW`             | 401    | v1.0.0     | `                                                                                                                                     | now - timestamp | > maxSkewMs`. |
| `UNKNOWN_CLIENT`             | 401    | v1.0.0     | `x-client-id` is not in the local store.                                                                                              |
| `CLIENT_EXPIRED`             | 401    | v1.0.0     | The credential's `expiresAt` has passed.                                                                                              |
| `MISSING_CLIENT_IP`          | 403    | v1.0.0     | Client IP could not be resolved and the credential has an IP allowlist.                                                               |
| `CLIENT_IP_NOT_ALLOWED`      | 403    | v1.0.0     | Client IP fails the credential's IP allowlist.                                                                                        |
| `CLIENT_NOT_FOUND`           | 404    | v1.0.0     | Internal lifecycle call on a missing clientId.                                                                                        |
| `BAD_SIGNATURE`              | 401    | v1.0.0     | Signature compare failed (constant-time).                                                                                             |
| `REPLAYED_NONCE`             | 401    | v1.0.0     | Nonce previously consumed.                                                                                                            |
| `INTERNAL_ROUTE_DISABLED`    | 400    | v1.0.0     | `internalManagementRoute` was not configured.                                                                                         |
| `METHOD_NOT_ALLOWED`         | 405    | v1.0.0     | Verb other than GET/POST/PUT/PATCH/DELETE on the management route.                                                                    |
| `FORBIDDEN`                  | 403    | v1.0.0     | Generic management-route refusal (duplicate clientId, unsupported kind, missing required field, ...).                                 |
| `INTERNAL_ERROR`             | 500    | v1.0.0     | Unexpected internal failure.                                                                                                          |
| `PROPAGATION_ONLY_FORBIDDEN` | 403    | v1.3.0     | A credential with `purpose: "propagation-only"` was used to sign a request that is not the configured `internalManagementRoute`.      |
| `BOOTSTRAP_LOCKED`           | 403    | v1.4.0     | The bootstrap-window lock is active: the resolved propagation clientId (default `self_propagation_signer`) is not yet stored locally. |

## Plane B: dynamic control plane (recap)

A target that supports `v1.2.0+` honors `fromDbSeed: true` by writing a TTL backup of the previous `secretHash` on rotation (under `<namespace>:credentials-backup:<clientId>`) and accepts `PATCH` to restore it. A target stuck at `v1.0.0` / `v1.1.0` accepts rotations but provides no rollback path (PATCH returns 404 if the route is enabled; `reverted: false` if the route exists but no backup is present). Orchestrators built on top (`@naskot/node-hmac-auth-management`) MUST inspect target health before propagating credentials that need atomic rollback. See [docs/architecture.md](./architecture.md#two-control-planes-since-120) for the complete two-plane model.

## v1.3.0 additions (made mandatory by default in v1.4.0)

Three additive features. Defaults reproduce v1.2.x byte-identical behavior.

### Feature 1: `purpose: "propagation-only"`

- Adds a usage-scope marker to credentials.
- Stored in the credential record. Propagated on the wire when explicitly set.
- Enforced server-side: `verifyHttpSignature` rejects any signed request matched against a credential whose `purpose` is `"propagation-only"` UNLESS the request path equals the configured `internalManagementRoute`. Rejection: HTTP 403 `PROPAGATION_ONLY_FORBIDDEN`.
- Message-store equivalents (`signMessage` / `verifyMessage`) refuse the credential outright with HTTP 403 `PROPAGATION_ONLY_FORBIDDEN`.

### Feature 2: `requireBootstrapClientId`

- Option on `initializeHmacHttpAuth` and `initializeHmacMessageAuth`.
- When set, the API rejects every signed request AND every internal-management write (PUT / PATCH / DELETE, plus POST whose clientId is not the named one) with HTTP 403 `BOOTSTRAP_LOCKED` until a credential with this exact clientId exists in the local store.
- `GET` health probes stay open and report `bootstrapLocked: true`.
- Once the named credential is stored, the lock auto-releases for the rest of the process lifetime. The check re-evaluates on every request, so a manual `DELETE` of the bootstrap credential restores the lock.
- Pairs naturally with Feature 1: declaring the bootstrap credential with `purpose: "propagation-only"` means that even if its secret leaks, the attacker cannot consume business routes — only propagate other (auditable) credentials.

### Feature 3: wire spec + test vectors

- This document, plus the three JSON files under `test/vectors/`. A language port that round-trips every vector with byte-identical output is certified compatible at the declared level.

## Certification procedure

1. Implement the cryptographic primitives in the target language.
2. Run all hash vectors: for each case, compute `hashClientSecret(secret, secretToken)` and check `expectedHex`.
3. Run all sign vectors: for each case, compute `signRequest({method, path, timestamp, nonce, body, secret})` and check `expectedHex`.
4. Implement an HTTP server that exposes the internal management route per this contract. Run each flow in `internal-route-flows.json` whose `level` is `<= v1.4.0`.
5. Bundle a signed-fetch client and exchange requests with the reference Node target shipped in `poc/`.

Targets passing 1-3 are wire-compatible. Targets passing 4 are management-route compatible. Targets passing 5 are end-to-end compatible.
