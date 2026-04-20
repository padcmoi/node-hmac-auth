import { describe, expect, it, vi } from "vitest";
import { createHttpSignedFetchClient, signedHttpFetch } from "../src/index.js";

describe("HMAC auth - signed fetch", () => {
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
