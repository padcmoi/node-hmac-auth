# HMAC Propagation POC (Nest + Express + Redis)

Minimal TypeScript POC to validate inter-API propagation through `internalManagementRoute`.

## Services

- `nest_source` (NestJS):
  - contains the **only** `microservice.cfg.ts`
  - creates/syncs local credentials
  - propagates credentials to target APIs
  - sends a signed HMAC `POST /secure/poc` every 5 seconds to targets
  - sends a second signed HMAC `POST /secure/poc` every 10 seconds with `source_only_client` (not propagated), expected to be rejected by targets
- `nest_target` (NestJS): target API
- `express_target` (Express): target API
- `redis`: shared storage

## Key Rule

Only `nest_source` has `src/microservice.cfg.ts` and drives propagation.

## Two propagation sources (v1.2.0)

`nest_source` exposes two distinct, independent surfaces for declaring credentials. Both end up propagated to the same targets but the targets store the origin as a passive marker (`fromDbSeed`):

- **`src/microservice.cfg.ts`** — static config, default. Credentials live in code. The lib propagates them with `fromDbSeed: false` (omitted on the wire). This is the v1.0.x / v1.1.x behavior.
- **`src/db-seed.cfg.ts`** — dynamic origin, **optional**. Simulates rows pulled from a DB by a consumer-side seed pipeline. Each entry is propagated with `fromDbSeed: true`; the targets store the flag in their credential record so they know the credential was dynamically managed.

The two files are completely separate. A consumer that opts out of the dynamic pipeline simply does not import `db-seed.cfg.ts` — no flag, no surface, no extra in-memory state. Removing the file (or leaving its array empty) leaves the rest of the POC unchanged.

Expected `nest_target` / `express_target` log line confirming the split:

```
[nest_target] http clients => internal_sync(fromDbSeed=false), ..., client_analytics(fromDbSeed=true), client_billing(fromDbSeed=true), ...
[nest_target] message clients => msg_amqp_orders(fromDbSeed=false), msg_amqp_billing(fromDbSeed=true)
```

## Feature coverage matrix

This POC torture-tests every public surface of the lib. Each row references the log line a reader should grep to confirm the path was exercised.

| Lib feature                                                         | Version | POC location                                 | Expected log signal                                                                                                 |
| ------------------------------------------------------------------- | ------- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| Signed HTTP fetch + verification                                    | 1.0.x   | `sendSignedHelloToTargets` every 5s          | `[nest_source] secure fetch results=[...status:200...]`                                                             |
| Rejected signed fetch (UNKNOWN_CLIENT)                              | 1.0.x   | `sendRejectedSignedHelloToTargets` every 10s | `[nest_source] rejected secure fetch results=[...status:401...UNKNOWN_CLIENT...]`                                   |
| Message signing + verification                                      | 1.1.0   | `verifyAllPropagatedMessageClients`          | `[nest_source] message verify summary ok=2/2`                                                                       |
| Propagation create (POST)                                           | 1.0.x   | `syncFromConfig` static loop                 | `[nest_source] propagation applied for clientId=<id>`                                                               |
| `targetStore: "message"`                                            | 1.1.0   | static + dynamic message clients             | `[nest_target] message clients => msg_amqp_orders(...)`                                                             |
| Local Redis fallback (omit secret in plan)                          | 1.0.x   | `client_via_redis_lookup`                    | `secret_via_redis_lookup` resolves to a `secretHash` server-side                                                    |
| Cross-token verification (distinct `HMAC_SECRET_TOKEN` per service) | 1.0.x   | `verifyAllPropagatedClients`                 | `[nest_source] cross-token verify summary ok=11/11`                                                                 |
| `fromDbSeed` origin marker (wire + record)                          | 1.2.0   | `db-seed.cfg.ts` propagated entries          | `[nest_target] http clients => ...client_analytics(fromDbSeed=true,...)`                                            |
| Backup TTL auto-write on db-seed rotation                           | 1.2.0   | `revert-demo step1`                          | (backup observable transiently on target between step1 and step2; consumed by step2)                                |
| `propagateClientToApis({ operation: "revert" })` (PATCH)            | 1.2.0   | `revert-demo step2`                          | `[nest_source] revert-demo step2 revert clientId=... reverted=true`                                                 |
| Hash restored to pre-rotation value after revert                    | 1.2.0   | logs target post step2                       | `[nest_target] http clients => ...client_analytics(...,hash=<first12>,backup=(none))` matches the pre-rotation hash |
| Static credentials NEVER get a backup                               | 1.2.0   | logs target periodic                         | every static row in `http clients => ...` ends with `,backup=(none)`                                                |
| `clients.revert` local on source (no remote PATCH)                  | 1.2.0   | `runRevertTortureSuite` cases                | `[nest_source] torture: local revert ... reverted=true/false`                                                       |
| `revert` on credential without backup (no-op)                       | 1.2.0   | `runRevertTortureSuite`                      | `[nest_source] torture: remote revert untouched_db_seed reverted=false`                                             |
| `revert` on unknown clientId (no-op + cleans orphan)                | 1.2.0   | `runRevertTortureSuite`                      | `[nest_source] torture: remote revert non_existing_client reverted=false`                                           |
| Message bridge `revert`                                             | 1.2.0   | `runRevertTortureSuite`                      | `[nest_source] torture: message revert msg_amqp_billing reverted=true`                                              |
| Rotation N+1 before TTL → backup overwritten                        | 1.2.0   | `runRevertTortureSuite`                      | `[nest_source] torture: double-rotate then revert restores ROUND2 hash`                                             |
| `propagate operation: "create"` on existing clientId → 403          | 1.0.x   | `runCrudTortureSuite`                        | `[nest_source] torture: create-existing status=403 body.message="Client already exists"`                            |
| `propagate operation: "update"` on missing clientId → 403           | 1.0.x   | `runCrudTortureSuite`                        | `[nest_source] torture: update-missing status=403 body.message="Client does not exist"`                             |
| `propagate operation: "delete"` on existing clientId → 201          | 1.0.x   | `runCrudTortureSuite`                        | `[nest_source] torture: delete-existing status=201 body.operation="delete"`                                         |
| `propagate operation: "delete"` on missing clientId → 403           | 1.0.x   | `runCrudTortureSuite`                        | `[nest_source] torture: delete-missing status=403`                                                                  |
| `propagate operation: "health"` → 200                               | 1.0.x   | `runCrudTortureSuite`                        | `[nest_source] torture: health status=200 body.ok=true`                                                             |
| `regenerateSecret` HTTP                                             | 1.0.x   | `runClientsManagementTortureSuite`           | `[nest_source] torture: regenerate http <id> hash changed`                                                          |
| `regenerateSecret` message                                          | 1.0.x   | `runClientsManagementTortureSuite`           | `[nest_source] torture: regenerate message <id> hash changed`                                                       |
| `setAllowedIps` then `clients.get` reflects update                  | 1.0.x   | `runClientsManagementTortureSuite`           | `[nest_source] torture: setAllowedIps <id> stored=[...]`                                                            |
| `clients.delete` then `clients.get` returns null                    | 1.0.x   | `runClientsManagementTortureSuite`           | `[nest_source] torture: delete-local <id> after-get=null`                                                           |
| `revert` preserves `fromDbSeed/allowedIps/expiresAt`                | 1.2.0   | `runFieldPreservationTortureSuite`           | `[nest_source] torture: revert-preserves fromDbSeed=true allowedIps=[...] expiresAt=...`                            |
| `requireBootstrapClientId` lock + release                           | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS bootstrap POST stores the named credential and releases the lock`                               |
| `bootstrapLocked` exposed on GET health body                        | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS GET reports bootstrapLocked=true while locked`                                                  |
| `BOOTSTRAP_LOCKED` on PUT / PATCH / DELETE while locked             | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS PUT refused with BOOTSTRAP_LOCKED while locked`                                                 |
| `purpose: "propagation-only"` accepted on management route          | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS verifyHttpSignature accepts propagation-only on the management route`                           |
| `PROPAGATION_ONLY_FORBIDDEN` on business route                      | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS verifyHttpSignature rejects propagation-only on a business route`                               |
| `PROPAGATION_ONLY_FORBIDDEN` on signMessage                         | 1.3.0   | `runV1_3_0_Demo`                             | `[v1.3.0-demo] PASS signMessage rejects propagation-only credential`                                                |

Every torture step logs both its action and the assertion outcome. A failing assertion produces a line prefixed with `torture FAIL`. The v1.3.0 demo runs in an isolated Redis namespace after the legacy suite; a green run shows zero `torture FAIL` lines and `[v1.3.0-demo] summary ok=8/8`.

## Run

From this folder:

```bash
docker compose up --build
```

## Required Nest Security Setup

For signed HMAC requests on JSON routes, this setup is required:

```ts
const app = await NestFactory.create<NestExpressApplication>(AppModule, {
  bodyParser: false,
  rawBody: true,
});

app.useBodyParser("json");
app.use("/secure", hmacAuth.verifyHttpRequest);
```

Without this setup, signature verification fails on secured routes.

## Expected Logs

- `nest_source`:
  - `http internal credential created/updated clientId=internal_sync`
  - `http internal credential created/updated clientId=source_only_client`
  - `propagation attempt=... clientId=internal_sync ...`
  - `propagation attempt=... clientId=external_client ...`
  - `secure fetch results=[...]` every 5 seconds with target JSON responses
  - `rejected secure fetch results=[...]` every 10 seconds with non-2xx status (typically `401` unknown clientId)
- `nest_target` and `express_target`:
  - `http clients => internal_sync,external_client`
  - `secure request from clientId=internal_sync body={"message":"hello POC i am nestjs source",...}`

This proves signed fetch and secured routes are working end-to-end.

## Stop

```bash
docker compose down -v
```

`-v` resets Redis and all Docker volumes used to cache `node_modules`.
