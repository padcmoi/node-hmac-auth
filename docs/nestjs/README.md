# NestJS Guide

This guide shows a minimal, production-oriented setup for using `@naskot/node-hmac-auth` with NestJS.

## 1) Install

```bash
npm install @naskot/node-hmac-auth @nestjs/common @nestjs/core @nestjs/platform-express redis reflect-metadata rxjs
```

## 2) Initialize Redis + HMAC

```ts
import { createClient } from "redis";
import { initializeHmacHttpAuth } from "@naskot/node-hmac-auth";

const redis = createClient({
  url: process.env.REDIS_URL, // ex: redis://user:password@127.0.0.1:6379
});

await redis.connect();

const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: "my-api-prod",
  maxSkewMs: 5 * 60 * 1000,
  defaultSecretLengthBytes: 32,
  secretToken: process.env.HMAC_SECRET_TOKEN, // strongly recommended
  onBadSignature: async (event) => {
    const meta = (event.metadata ?? {}) as {
      ip?: string;
      remoteAddress?: string;
      forwardedFor?: string | string[];
    };

    const forwarded = Array.isArray(meta.forwardedFor) ? meta.forwardedFor[0] : meta.forwardedFor;
    const ipFromForwarded = forwarded?.split(",")[0]?.trim();
    const ip = ipFromForwarded || meta.ip || meta.remoteAddress || "unknown";

    console.warn("BAD_SIGNATURE", {
      ip,
      clientId: event.clientId,
      path: event.path,
      nonce: event.nonce,
      timestamp: event.timestamp,
    });

    // Example anti-bruteforce / ban pipeline:
    // await redis.incr(`ban:hmac:${ip}`);
    // await redis.expire(`ban:hmac:${ip}`, 60);
  },
});
```

## 3) Seed a Client Credential (once)

```ts
const existing = await hmacAuth.clients.get("client_mobile");
if (!existing) {
  await hmacAuth.clients.create({
    clientId: "client_mobile",
    plainSecret: "superSharedSecret", // use a secure secret manager in real systems
    expiresAt: null, // optional
    allowedIps: ["195.7.8.9", "195.7.8.0/24"], // optional IP/CIDR allowlist for this clientId
  });
}
```

## 4) Nest App Setup (raw body + middleware order)

Important:

- Keep raw body enabled so HMAC verification uses exact request content.
- Keep JSON parsing enabled before HMAC middleware so internal management payloads are readable.
- If JSON parsing is missing for `/api/internal/hmac`, `POST`/`PUT` can be refused with `FORBIDDEN: clientId is required`.

```ts
import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";

const app = await NestFactory.create<NestExpressApplication>(AppModule, {
  bodyParser: false,
  rawBody: true,
});

// If behind a reverse proxy/load balancer, keep client IP from X-Forwarded-For.
app.set("trust proxy", true);

// Required when bodyParser:false is used:
// keeps JSON body parsing for routes such as /api/internal/hmac.
app.useBodyParser("json");

app.use("/secure", hmacAuth.verifyHttpRequest);
app.use(hmacAuth.createInternalManagementMiddleware());
```

Notes:

- `bodyParser: false` + `app.useBodyParser("json")` is the recommended NestJS setup with this library.
- Register `app.useBodyParser("json")` before attaching HMAC middleware.
- If your app has custom parsers, ensure they do not bypass or replace JSON parsing for `/api/internal/hmac`.

## 5) Controller Example

```ts
import { Body, Controller, Get, HttpCode, Post, Req } from "@nestjs/common";

@Controller()
export class AppController {
  @Get("public/ping")
  ping() {
    return { ok: true, mode: "public" };
  }

  @Get("secure/get")
  secureGet(@Req() req: any) {
    return { ok: true, mode: "secure", auth: req.hmacAuth ?? null };
  }

  @Post("secure/post")
  @HttpCode(200)
  securePost(@Req() req: any, @Body() body: unknown) {
    return { ok: true, mode: "secure", body: body ?? null, auth: req.hmacAuth ?? null };
  }
}
```

## 6) Per-Route Protection with a NestJS Decorator

§4 mounts `hmacAuth.verifyHttpRequest` on the `/secure` prefix — Express-style path protection that also works in NestJS. The NestJS-idiomatic surface is a controller/method decorator. The library stays framework-agnostic (it ships middleware only), so the decorator is ~30 lines of NestJS glue written once in your project on top of `createHmacRuntime(hmacAuth).hmacHttpMiddleware(...)`.

```ts
import {
  applyDecorators,
  type CanActivate,
  type ExecutionContext,
  Inject,
  Injectable,
  SetMetadata,
  UseGuards,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import type { HmacRuntime } from "@naskot/node-hmac-auth";

export const HMAC_RUNTIME = Symbol("HMAC_RUNTIME");
const HMAC_AUTH_CLIENTS_META = "hmac:auth:clients";

@Injectable()
export class HmacAuthGuard implements CanActivate {
  constructor(
    @Inject(HMAC_RUNTIME) private readonly runtime: HmacRuntime,
    private readonly reflector: Reflector
  ) {}

  canActivate(context: ExecutionContext) {
    const clientIds =
      this.reflector.getAllAndOverride<string[]>(HMAC_AUTH_CLIENTS_META, [context.getHandler(), context.getClass()]) ?? [];
    const middleware = this.runtime.hmacHttpMiddleware(...clientIds);
    type Req = Parameters<typeof middleware>[0];
    type Res = Parameters<typeof middleware>[1];
    const req = context.switchToHttp().getRequest<Req>();
    const res = context.switchToHttp().getResponse<Res>();
    return new Promise<boolean>((resolve, reject) => {
      void middleware(req, res, (err?: unknown) => {
        if (!err) return resolve(true);
        reject(err instanceof Error ? err : new Error(typeof err === "string" ? err : "HMAC middleware rejected the request"));
      });
    });
  }
}

export const RequireAuthHmac = (...clientIds: string[]) =>
  applyDecorators(SetMetadata(HMAC_AUTH_CLIENTS_META, clientIds), UseGuards(HmacAuthGuard));
```

Bind the runtime in your HMAC module so `HmacAuthGuard` can inject it:

```ts
import { Module } from "@nestjs/common";
import { createHmacRuntime } from "@naskot/node-hmac-auth";
import { HmacAuthGuard, HMAC_RUNTIME } from "./require-auth-hmac.decorator";

@Module({
  providers: [
    { provide: HMAC_RUNTIME, useFactory: () => createHmacRuntime(hmacAuth) }, // hmacAuth from §2
    HmacAuthGuard,
  ],
  exports: [HMAC_RUNTIME, HmacAuthGuard],
})
export class HmacModule {}
```

Apply on controllers — class-level for all routes, method-level to override a specific handler:

```ts
import { Controller, Get, Param, Post } from "@nestjs/common";
import { RequireAuthHmac } from "./require-auth-hmac.decorator";

@RequireAuthHmac("toto", "dudu")
@Controller("admin/config-templates")
export class AdminConfigTemplatesController {
  @RequireAuthHmac("admin_console", "toto")
  @Get(":alias")
  detail(@Param("alias") alias: string) {}

  @Post()
  create() {}
}
```

Notes:

- `@RequireAuthHmac()` — any registered clientId passes (signature verification only).
- `@RequireAuthHmac("admin_console")` — only `admin_console` passes (whitelist of one).
- `@RequireAuthHmac("a", "b", "c")` — whitelist of multiple clientIds, any one passes.
- Method-level annotation overrides class-level for that handler (`Reflector.getAllAndOverride([handler, class])`).
- Routes without `@RequireAuthHmac` are not protected by this decorator — drop down to the §4 path-prefix middleware if you keep it.
- The decorator delegates to `runtime.hmacHttpMiddleware(...clientIds)` and inherits the full check chain: signature, clock-skew window, nonce replay, optional `allowedIps`, optional clientId whitelist. Failures propagate as the `401` / `403` responses described in §8.
- Express has no decorator surface — its equivalent stays the `/secure` path-prefix middleware (§4).

## 7) Public Route Calling a Secure Peer Route

Read signing material from Redis (`secretHash`) at call time, then use `createHttpSignedFetchClient`.

```ts
const PEER_BASE_URL = process.env.PEER_BASE_URL ?? "http://127.0.0.1:3002";
const CLIENT_ID = "client_mobile";

async function callPeer(url: string, options: any = {}) {
  const client = await hmacAuth.clients.get(CLIENT_ID);
  if (!client) {
    throw new Error(`${CLIENT_ID} not found in Redis`);
  }

  const peerFetch = hmacAuth.createHttpSignedFetchClient({
    clientId: CLIENT_ID,
    secret: client.secretHash,
    secretIsHashed: true,
  });

  return peerFetch(url, options);
}

const response = await callPeer(`${PEER_BASE_URL}/secure/get?from=api_1`, {
  method: "GET",
});
```

## 8) Behavior Summary

- Missing `x-client-id` -> `401`
- Unknown `clientId` -> `401`
- Missing source IP while `allowedIps` is configured -> `403`
- Source IP not allowed by `allowedIps` -> `403`
- Bad signature -> `401`
- Expired client secret -> `401`
- Replayed nonce -> `401`

Headers used by verifier:

- `x-client-id`
- `x-timestamp`
- `x-nonce`
- `x-signature`

Note: `createExpressHttpMiddleware()` is available as explicit Express middleware naming.

## 9) Sign and Verify Messages

For async message transports (queues/events), use message helpers instead of HTTP helpers.

```ts
import { initializeHmacMessageAuth } from "@naskot/node-hmac-auth";

const hmacMessageAuth = initializeHmacMessageAuth({
  redis,
  namespace: "my-api-prod-messages",
  secretToken: process.env.HMAC_SECRET_TOKEN,
});

const signed = await hmacMessageAuth.signMessage({
  clientId: "client_mobile",
  message: { event: "order.created", id: 42 },
});

await hmacMessageAuth.verifyMessage({
  clientId: "client_mobile",
  message: { event: "order.created", id: 42 },
  signature: signed.signature,
});
```

Message verification intentionally does not enforce timestamp skew checks or anti-replay.

## 10) Internal HMAC Key Management Route (optional)

You can enable a dedicated internal route used to bootstrap and propagate credentials between APIs.

```ts
const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: "my-api-prod",
  secretToken: process.env.HMAC_SECRET_TOKEN,
  internalManagementRoute: "/api/internal/hmac",
});

app.use(hmacAuth.createInternalManagementMiddleware());
```

Supported methods on `/api/internal/hmac`:

- `GET`: healthcheck
- `POST`: create/propagate a credential
- `PUT`: update a credential secret
- `DELETE`: delete a credential

For `POST` / `PUT` / `DELETE`, target APIs return:

- `201` when accepted
- `403` when refused

Security behavior:

- If at least one client already exists in Redis, route requires valid HMAC auth.
- If no client exists yet, first credential bootstrap is accepted without HMAC auth.

Troubleshooting:

- `FORBIDDEN: clientId is required` usually means JSON payload is not parsed on the target API.
- `FORBIDDEN: Internal HMAC management authentication failed` means the target API already has at least one client, so valid HMAC auth is required.

### Propagate to one or many APIs

Use a signed `apiFetch` (created from an existing key) when target APIs already require authentication.

```ts
const signer = hmacAuth.createHttpSignedFetchClient({
  clientId: "internal_sync",
  secret: "internal_sync_secret",
});

const results = await hmacAuth.propagateClientToApis({
  operation: "create",
  targets: ["https://api-a.example.com", "https://api-b.example.com"],
  clientId: "client_mobile",
  secret: "superSharedSecret",
  allowedIps: ["195.7.8.9", "195.7.8.0/24"], // required for create/update propagation
  apiFetch: signer,
});

// Each result includes status and accepted boolean (201/403)
console.log(results);
```

Behavior changes around `propagateClientToApis` are documented in the dedicated release notes:

- 1.1.0 — propagation can also target the message credential store via `targetStore: "message"` (optional `messageAuth` bridge in `initializeHmacHttpAuth`). See [docs/release-notes/1.1.0.md](../release-notes/1.1.0.md).
- 1.0.0 — propagation transports the `secretHash` on the wire + Redis fallback when `secret`/`secretHash` are omitted. See [docs/release-notes/1.0.0.md](../release-notes/1.0.0.md).

## 11) Complete Shared Service Example

This service is framework-agnostic at code level

```ts
import { createClient } from "redis";
import { createHmacRuntime, initializeHmacHttpAuth, initializeHmacMessageAuth } from "@naskot/node-hmac-auth";
import type {
  CreateHmacClientOptions,
  PropagateServiceCreateOptions,
  PropagateServiceDeleteOptions,
  PropagateServiceHealthOptions,
  PropagateServiceUpdateOptions,
  SignedHttpFetchClientCallOptions,
} from "@naskot/node-hmac-auth";

const redis = createClient({
  url: process.env.REDIS_URL, // ex: redis://user:password@127.0.0.1:6379
});

await redis.connect();

const HMAC_NAMESPACE = process.env.HMAC_NAMESPACE ?? "my-api-prod";

export const hmacAuth = initializeHmacHttpAuth({
  redis,
  namespace: HMAC_NAMESPACE,
  maxSkewMs: 5 * 60 * 1000,
  defaultSecretLengthBytes: 32,
  secretToken: process.env.HMAC_SECRET_TOKEN, // strongly recommended
  internalManagementRoute: process.env.INTERNAL_MANAGEMENT_ROUTE ?? "/api/internal/hmac-auth", // optional: clientId propagation between APIs
  onBadSignature: async (event) => {
    const meta = (event.metadata ?? {}) as {
      ip?: string;
      remoteAddress?: string;
      forwardedFor?: string | string[];
    };

    const forwarded = Array.isArray(meta.forwardedFor) ? meta.forwardedFor[0] : meta.forwardedFor;
    const ipFromForwarded = forwarded?.split(",")[0]?.trim();
    const ip = ipFromForwarded || meta.ip || meta.remoteAddress || "unknown";

    console.warn("BAD_SIGNATURE", {
      ip,
      clientId: event.clientId,
      path: event.path,
      nonce: event.nonce,
      timestamp: event.timestamp,
    });
  },
});

export const hmacMessageAuth = initializeHmacMessageAuth({
  redis,
  namespace: `${HMAC_NAMESPACE}-messages`,
  secretToken: process.env.HMAC_SECRET_TOKEN,
});

const { createSignedFetchFromClientId, signedFetchWithClientId, hmacHttpMiddleware } = createHmacRuntime(hmacAuth);

export const credential = {
  /**
   * Read one client credential by clientId.
   *
   * Usage:
   * const client = await credential.get("client_mobile");
   */
  get: async (clientId: string) => {
    return await hmacAuth.clients.get(clientId);
  },

  /**
   * Create a client credential only if it does not already exist.
   *
   * Usage:
   * await credential.create({
   *   clientId: "client_mobile",
   *   plainSecret: "superSharedSecret",
   *   expiresAt: null,
   * });
   */
  create: async (opts: CreateHmacClientOptions) => {
    if (await credential.get(opts.clientId)) {
      return { status: false as const, error: `Cannot create credential: clientId '${opts.clientId}' already exists.` };
    }

    return await hmacAuth.clients.create(opts);
  },

  /**
   * Regenerate an existing client secret using a required plainSecret.
   *
   * Usage:
   * await credential.regenerateSecret("client_mobile", "newSuperSecret");
   */
  regenerateSecret: async (clientId: string, plainSecret: string) => {
    if (!(await credential.get(clientId))) {
      return { status: false as const, error: `Cannot regenerate credential: clientId '${clientId}' does not exist.` };
    }

    return await hmacAuth.clients.regenerateSecret(clientId, { plainSecret });
  },

  /**
   * Revoke (delete) an existing client credential.
   *
   * Usage:
   * await credential.revoke("client_mobile");
   */
  revoke: async (clientId: string) => {
    if (!(await credential.get(clientId))) {
      return { status: false as const, error: `Cannot revoke credential: clientId '${clientId}' does not exist.` };
    }

    await hmacAuth.clients.delete(clientId);
    return { status: true as const, clientId };
  },
};

export const http = {
  /**
   * Set one or more candidate clientIds for a signed fetch context.
   * The first non-empty clientId is always used.
   *
   * Usage:
   * await http.use("svc-a").fetch("https://api.example.com/secure", { method: "POST" });
   * await http.useClientIds("svc-a").fetch("https://api.example.com/secure", { method: "POST" });
   *
   * app.use("/secure", http.useClientIds().middleware);
   * app.use("/secure", http.useClientIds("svc-a", "svc-b").middleware);
   */
  use: (...clientIds: string[]) => http.useClientIds(...clientIds),
  useClientIds: (...clientIds: string[]) => {
    const firstClientId = clientIds.find((value) => typeof value === "string" && value.trim());

    return {
      fetch: (input: string, options?: SignedHttpFetchClientCallOptions) => {
        if (!firstClientId) {
          throw new Error(
            "Forbidden: signed fetch requires at least one clientId. Use http.useClientIds('svc-a').fetch(url, options)."
          );
        }
        return signedFetchWithClientId(input, firstClientId, options);
      },
      middleware: hmacHttpMiddleware(...clientIds),
    };
  },
};

export const interApi = {
  /**
   * Internal management middleware for inter-API clientId propagation route.
   *
   * Usage:
   * app.use(interApi.middleware);
   */
  middleware: hmacAuth.createInternalManagementMiddleware(),

  propagate: {
    create: async (opts: PropagateServiceCreateOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "create",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        secret: opts.plainSecret,
        allowedIps: opts.allowedIps,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    update: async (opts: PropagateServiceUpdateOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "update",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        secret: opts.plainSecret,
        allowedIps: opts.allowedIps,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    delete: async (opts: PropagateServiceDeleteOptions) => {
      const fetchWithClientId = opts.useClientId ? opts.useClientId : opts.propagateClientId;

      const results = await hmacAuth.propagateClientToApis({
        operation: "delete",
        targets: opts.targetApis,
        clientId: opts.propagateClientId,
        apiFetch: await createSignedFetchFromClientId(fetchWithClientId),
      });

      return results;
    },

    health: async (opts: PropagateServiceHealthOptions) => {
      const results = await hmacAuth.propagateClientToApis({
        operation: "health",
        targets: opts.targetApis,
        apiFetch: await createSignedFetchFromClientId(opts.useClientId),
      });

      return results;
    },
  },
};

export const message = {
  /**
   * Sign an async message payload with a clientId (queue/event use case).
   *
   * Usage:
   * const signed = await message.sign("client_mobile", { event: "order.created", id: 42 });
   */
  sign: async (clientId: string, payload: unknown) => {
    return hmacMessageAuth.signMessage({ clientId, message: payload });
  },

  /**
   * Verify an async message signature with a clientId.
   *
   * Usage:
   * await message.verify("client_mobile", { event: "order.created", id: 42 }, signature);
   */
  verify: async (clientId: string, payload: unknown, signature: string) => {
    return hmacMessageAuth.verifyMessage({ clientId, message: payload, signature });
  },
};
```
