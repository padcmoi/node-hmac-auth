import { hashClientSecret, signRequest } from "../hmac.js";
import { generateNonce, isJsonObjectBody, normalizePath, toBodyString } from "../utils.js";

type SignedBody = string | Buffer | Uint8Array | URLSearchParams | Record<string, unknown> | null;

export interface BuildHttpSignedHeadersInput {
  method: string;
  url: string;
  body: SignedBody;
  clientId: string;
  secret: string;
  secretIsHashed?: boolean;
  hashToken?: string;
  nonce?: string;
  timestamp?: number;
  headers?: HeadersInit;
}

export interface SignedHttpFetchOptions extends Omit<RequestInit, "headers" | "body" | "method"> {
  method?: string;
  headers?: HeadersInit;
  body?: SignedBody;
  clientId: string;
  secret: string;
  secretIsHashed?: boolean;
  hashToken?: string;
  nonce?: string;
  timestamp?: number;
  fetchImpl?: typeof fetch;
}

export interface CreateHttpSignedFetchClientOptions {
  clientId: string;
  secret: string;
  secretIsHashed?: boolean;
  hashToken?: string;
  defaultHeaders?: HeadersInit;
  fetchImpl?: typeof fetch;
}

export type SignedHttpFetchClientCallOptions = Omit<
  SignedHttpFetchOptions,
  "clientId" | "secret" | "secretIsHashed" | "fetchImpl"
>;

function buildBodyForRequest(
  body: SignedBody,
  headers: Headers,
): {
  bodyForRequest: BodyInit | undefined;
  bodyForSignature: string;
} {
  if (body == null) {
    return { bodyForRequest: undefined, bodyForSignature: "" };
  }

  if (typeof body === "string" || Buffer.isBuffer(body) || body instanceof Uint8Array) {
    const asText = toBodyString(body);
    return { bodyForRequest: asText, bodyForSignature: asText };
  }

  if (body instanceof URLSearchParams) {
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8");
    }
    return { bodyForRequest: body, bodyForSignature: body.toString() };
  }

  if (isJsonObjectBody(body)) {
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    const json = JSON.stringify(body);
    return { bodyForRequest: json, bodyForSignature: json };
  }

  return { bodyForRequest: body as BodyInit, bodyForSignature: toBodyString(body) };
}

export function buildHttpSignedHeaders(input: BuildHttpSignedHeadersInput): Headers {
  const headers = new Headers(input.headers);
  const timestamp = input.timestamp ?? Date.now();
  const nonce = input.nonce ?? generateNonce();
  const signingSecret = input.secretIsHashed ? input.secret : hashClientSecret(input.secret, input.hashToken);
  const signature = signRequest({
    method: input.method,
    path: normalizePath(input.url),
    timestamp,
    nonce,
    body: toBodyString(input.body),
    secret: signingSecret,
  });

  headers.set("x-client-id", input.clientId);
  headers.set("x-timestamp", String(timestamp));
  headers.set("x-nonce", nonce);
  headers.set("x-signature", signature);

  return headers;
}

export async function signedHttpFetch(url: string, options: SignedHttpFetchOptions): Promise<Response> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new Error("No fetch implementation available");
  }

  const method = (options.method ?? (options.body == null ? "GET" : "POST")).toUpperCase();
  const headers = new Headers(options.headers);
  const { bodyForRequest, bodyForSignature } = buildBodyForRequest(options.body ?? null, headers);

  const signedHeaders = buildHttpSignedHeaders({
    method,
    url,
    body: bodyForSignature,
    clientId: options.clientId,
    secret: options.secret,
    secretIsHashed: options.secretIsHashed,
    hashToken: options.hashToken,
    nonce: options.nonce,
    timestamp: options.timestamp,
    headers,
  });

  return fetchImpl(url, {
    ...options,
    method,
    headers: signedHeaders,
    body: method === "GET" || method === "HEAD" ? undefined : bodyForRequest,
  });
}

function mergeHeaders(base?: HeadersInit, extra?: HeadersInit): Headers {
  const headers = new Headers(base);
  if (!extra) {
    return headers;
  }

  const extraHeaders = new Headers(extra);
  for (const [key, value] of extraHeaders.entries()) {
    headers.set(key, value);
  }

  return headers;
}

export function createHttpSignedFetchClient(options: CreateHttpSignedFetchClientOptions) {
  const signingSecret = options.secretIsHashed ? options.secret : hashClientSecret(options.secret, options.hashToken);

  return async function signedClientFetch(url: string, callOptions: SignedHttpFetchClientCallOptions = {}): Promise<Response> {
    return signedHttpFetch(url, {
      ...callOptions,
      headers: mergeHeaders(options.defaultHeaders, callOptions.headers),
      clientId: options.clientId,
      secret: signingSecret,
      secretIsHashed: true,
      fetchImpl: options.fetchImpl,
    });
  };
}
