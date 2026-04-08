import { describe, expect, it, vi } from "vitest";
import {
  buildHttpSignedHeaders,
  createHttpSignedFetchClient,
  hashClientSecret,
  initializeHmacHttpAuth,
  signedHttpFetch,
  verifyHttpSignature,
} from "../src/index.js";

function headersToRecord(headers: Headers): Record<string, string> {
  return Object.fromEntries(Array.from(headers.entries()));
}

class FakeRedis {
  private readonly hashes = new Map<string, Map<string, string>>();
  private readonly kv = new Map<string, { value: string; expiresAt: number | null }>();

  async hGet(key: string, field: string): Promise<string | null> {
    return this.hashes.get(key)?.get(field) ?? null;
  }

  async hSet(key: string, field: string, value: string): Promise<number> {
    const hash = this.hashes.get(key) ?? new Map<string, string>();
    this.hashes.set(key, hash);
    hash.set(field, value);
    return 1;
  }

  async hDel(key: string, field: string): Promise<number> {
    const hash = this.hashes.get(key);
    if (!hash) {
      return 0;
    }
    const existed = hash.delete(field);
    return existed ? 1 : 0;
  }

  async hKeys(key: string): Promise<string[]> {
    return Array.from(this.hashes.get(key)?.keys() ?? []);
  }

  async set(key: string, value: string, ...args: unknown[]): Promise<"OK" | null> {
    this.cleanup();

    let nx = false;
    let exSeconds: number | null = null;

    if (args.length === 1 && typeof args[0] === "object" && args[0] != null) {
      const options = args[0] as { NX?: boolean; EX?: number };
      nx = options.NX === true;
      exSeconds = typeof options.EX === "number" ? options.EX : null;
    } else {
      for (let i = 0; i < args.length; i += 1) {
        const token = String(args[i] ?? "").toUpperCase();
        if (token === "NX") {
          nx = true;
          continue;
        }
        if (token === "EX") {
          const raw = args[i + 1];
          exSeconds = Number(raw);
          i += 1;
        }
      }
    }

    if (nx && this.kv.has(key)) {
      return null;
    }

    const expiresAt = exSeconds == null ? null : Date.now() + exSeconds * 1000;
    this.kv.set(key, { value, expiresAt });
    return "OK";
  }

  hasHashKey(key: string): boolean {
    return this.hashes.has(key);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [key, entry] of this.kv.entries()) {
      if (entry.expiresAt != null && entry.expiresAt <= now) {
        this.kv.delete(key);
      }
    }
  }
}

describe("HMAC auth", () => {
  it("supports verifyHttpRequest as middleware and keeps middleware aliases", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_middleware", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const makeRes = () => {
      return {
        statusCode: 200,
        body: undefined as unknown,
        status(code: number) {
          this.statusCode = code;
          return this;
        },
        json(payload: unknown) {
          this.body = payload;
          return this;
        },
      };
    };

    const body = JSON.stringify({ ok: true });
    const ts1 = Date.now();
    const headers1 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts1,
        nonce: "nonce_mw_1",
      }),
    );

    const req1: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers1,
      rawBody: body,
    };
    const res1 = makeRes();
    const next1 = vi.fn();

    await auth.verifyHttpRequest(req1, res1 as any, next1);
    expect(next1).toHaveBeenCalledTimes(1);
    expect(req1.hmacAuth?.clientId).toBe("app_a");

    const ts2 = ts1 + 1;
    const headers2 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts2,
        nonce: "nonce_mw_2",
      }),
    );

    const req2: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers2,
      rawBody: body,
    };
    const res2 = makeRes();
    const next2 = vi.fn();

    await auth.createHttpMiddleware()(req2, res2 as any, next2);
    expect(next2).toHaveBeenCalledTimes(1);
    expect(req2.hmacAuth?.clientId).toBe("app_a");

    const ts3 = ts2 + 1;
    const headers3 = headersToRecord(
      buildHttpSignedHeaders({
        method: "POST",
        url: "/secure/post",
        body,
        clientId: "app_a",
        secret: "secret_a",
        timestamp: ts3,
        nonce: "nonce_mw_3",
      }),
    );

    const req3: any = {
      method: "POST",
      originalUrl: "/secure/post",
      url: "/secure/post",
      headers: headers3,
      rawBody: body,
    };
    const res3 = makeRes();
    const next3 = vi.fn();

    await auth.createExpressHttpMiddleware()(req3, res3 as any, next3);
    expect(next3).toHaveBeenCalledTimes(1);
    expect(req3.hmacAuth?.clientId).toBe("app_a");
  });

  it("verifies a valid signed request with redis-backed secrets", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_a",
      maxSkewMs: 5000,
    });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const body = JSON.stringify({ hello: "world" });

    const headers = buildHttpSignedHeaders({
      method: "POST",
      url: "/v1/messages?x=1",
      body,
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_1",
    });

    const verified = await auth.verifyHttpSignature({
      method: "POST",
      path: "/v1/messages?x=1",
      headers: headersToRecord(headers),
      rawBody: body,
      now: timestamp,
    });

    expect(verified.clientId).toBe("app_a");
    expect(verified.nonce).toBe("nonce_1");
    expect(redis.hasHashKey("tenant_a:clients")).toBe(true);
  });

  it("rejects replayed nonce", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_a", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const body = "";
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body,
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "same_nonce",
    });
    const headerRecord = headersToRecord(headers);

    await auth.verifyHttpSignature({
      method: "GET",
      path: "/health",
      headers: headerRecord,
      rawBody: body,
      now: timestamp,
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headerRecord,
        rawBody: body,
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "REPLAYED_NONCE" });
  });

  it("returns 401 when clientId is missing", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_b", maxSkewMs: 5000 });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_1",
    });
    headers.delete("x-client-id");

    await expect(
      verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headers),
        rawBody: "",
        redis,
        namespace: "tenant_b",
        maxSkewMs: 5000,
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "MISSING_CLIENT_ID", status: 401 });
  });

  it("returns 401 for unknown client or wrong secret", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_c", maxSkewMs: 5000 });
    await auth.clients.setSecret("known_client", "server_secret");

    const timestamp = Date.now();

    const unknownClientHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "unknown_client",
      secret: "server_secret",
      timestamp,
      nonce: "nonce_unknown",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(unknownClientHeaders),
        rawBody: "",
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "UNKNOWN_CLIENT", status: 401 });

    const wrongSecretHeaders = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "known_client",
      secret: "wrong_secret",
      timestamp,
      nonce: "nonce_wrong_secret",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(wrongSecretHeaders),
        rawBody: "",
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
  });

  it("returns 401 when client secret is expired", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_expired", maxSkewMs: 5000 });
    await auth.clients.setSecret("exp_client", "secret_a", Date.now() - 1000);

    const timestamp = Date.now();
    const headers = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "exp_client",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_expired",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headers),
        rawBody: "",
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "CLIENT_EXPIRED", status: 401 });
  });

  it("supports client helpers create/list/delete/regenerate", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_admin", maxSkewMs: 5000 });

    const created = await auth.clients.create({
      clientId: "client_admin",
      expiresAt: Date.now() + 60_000,
      secretLengthBytes: 16,
    });

    expect(created.clientId).toBe("client_admin");
    expect(created.secret.length).toBe(32);
    expect(created.secretHash).toBeTruthy();

    const ids = await auth.clients.listClientIds();
    expect(ids).toContain("client_admin");

    const regenerated = await auth.clients.regenerateSecret("client_admin");
    expect(regenerated.clientId).toBe("client_admin");
    expect(regenerated.secret).not.toBe(created.secret);

    await auth.clients.delete("client_admin");
    const deleted = await auth.clients.get("client_admin");
    expect(deleted).toBeNull();
  });

  it("supports create with provided plainSecret and deterministic hash", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_plain_secret", maxSkewMs: 5000 });

    const first = await auth.clients.create({
      clientId: "client_a",
      plainSecret: "helloworld",
    });
    const second = await auth.clients.create({
      clientId: "client_b",
      plainSecret: "helloworld",
    });

    expect(first.secret).toBe("helloworld");
    expect(second.secret).toBe("helloworld");
    expect(first.secretHash).toBe(second.secretHash);
    expect(first.secretHash).toBe(hashClientSecret("helloworld"));
    expect((await auth.clients.get("client_a"))?.secretHash).toBe(first.secretHash);
    expect((await auth.clients.get("client_b"))?.secretHash).toBe(second.secretHash);
  });

  it("rejects create when plainSecret is empty", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({ redis, namespace: "tenant_empty_secret", maxSkewMs: 5000 });

    await expect(
      auth.clients.create({
        clientId: "client_empty",
        plainSecret: "   ",
      }),
    ).rejects.toThrow("plainSecret cannot be empty");
  });

  it("supports secretToken for deterministic tokenized secret hashes", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_tokenized",
      maxSkewMs: 5000,
      secretToken: "abc",
    });

    const first = await auth.clients.create({
      clientId: "client_a",
      plainSecret: "helloworld",
    });
    const second = await auth.clients.create({
      clientId: "client_b",
      plainSecret: "helloworld",
    });

    expect(first.secretHash).toBe(second.secretHash);
    expect(first.secretHash).toBe(hashClientSecret("helloworld", "abc"));
    expect(first.secretHash).not.toBe(hashClientSecret("helloworld"));
  });

  it("verifies tokenized signatures only when using the same secretToken", async () => {
    const redis = new FakeRedis();
    const auth = initializeHmacHttpAuth({
      redis,
      namespace: "tenant_token_verify",
      maxSkewMs: 5000,
      secretToken: "abc",
    });
    await auth.clients.setSecret("app_a", "secret_a");

    const timestamp = Date.now();
    const headersWithToken = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      hashToken: "abc",
      timestamp,
      nonce: "nonce_tokenized",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headersWithToken),
        rawBody: "",
        now: timestamp,
      }),
    ).resolves.toMatchObject({ clientId: "app_a" });

    const headersWithoutToken = buildHttpSignedHeaders({
      method: "GET",
      url: "/health",
      body: "",
      clientId: "app_a",
      secret: "secret_a",
      timestamp,
      nonce: "nonce_no_token",
    });

    await expect(
      auth.verifyHttpSignature({
        method: "GET",
        path: "/health",
        headers: headersToRecord(headersWithoutToken),
        rawBody: "",
        now: timestamp,
      }),
    ).rejects.toMatchObject({ code: "BAD_SIGNATURE" });
  });

  it("signs fetch requests with helper", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response(null, { status: 204 });
    });

    await signedHttpFetch("https://api.example.com/v1/ping", {
      method: "POST",
      body: { ok: true },
      clientId: "app_a",
      secret: "secret_a",
      timestamp: 1000,
      nonce: "nonce_1",
      fetchImpl: fetchMock,
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);

    const call = fetchMock.mock.calls[0];
    const init = (call?.[1] ?? {}) as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get("x-client-id")).toBe("app_a");
    expect(headers.get("x-signature")).toBeTruthy();
  });

  it("creates a preconfigured signed fetch client", async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => {
      return new Response(null, { status: 204 });
    });

    const apiFetch = createHttpSignedFetchClient({
      clientId: "local_client",
      secret: "local_secret",
      fetchImpl: fetchMock,
    });

    await apiFetch("https://api.example.com/v1/ping", {
      method: "GET",
    });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = (fetchMock.mock.calls[0]?.[1] ?? {}) as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.get("x-client-id")).toBe("local_client");
    expect(headers.get("x-signature")).toBeTruthy();
  });
});
