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
