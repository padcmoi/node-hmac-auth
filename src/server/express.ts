import { HmacAuthError } from "../errors.js";
import type { RedisLikeClient } from "../stores/redis.js";
import { verifyHttpSignature } from "./verify.js";

export interface ExpressHmacMiddlewareOptions {
  redis: RedisLikeClient;
  namespace?: string;
  maxSkewMs?: number;
  attachAuthTo?: string;
  onError?: (error: HmacAuthError, req: any, res: any, next: (error?: unknown) => void) => void;
}

export type HttpHmacMiddlewareOptions = ExpressHmacMiddlewareOptions;

export function captureRawBody(req: { rawBody?: Buffer }, _res: unknown, buf: Buffer): void {
  req.rawBody = Buffer.from(buf);
}

function fallbackRawBody(req: any): unknown {
  if (req.rawBody != null) {
    return req.rawBody;
  }
  if (req.body == null) {
    return "";
  }
  if (typeof req.body === "string") {
    return req.body;
  }
  if (Buffer.isBuffer(req.body)) {
    return req.body;
  }
  return JSON.stringify(req.body);
}

function toHmacError(error: unknown): HmacAuthError {
  if (error instanceof HmacAuthError) {
    return error;
  }
  return new HmacAuthError("INTERNAL_ERROR", "Internal auth error", 500);
}

export function createExpressHttpHmacMiddleware(options: ExpressHmacMiddlewareOptions) {
  if (!options?.redis) {
    throw new Error("Redis connection is mandatory");
  }

  const attachAuthTo = options.attachAuthTo ?? "hmacAuth";

  return async function hmacMiddleware(req: any, res: any, next: (error?: unknown) => void) {
    try {
      const verified = await verifyHttpSignature({
        method: req.method,
        path: req.originalUrl ?? req.url,
        headers: req.headers,
        rawBody: fallbackRawBody(req),
        redis: options.redis,
        namespace: options.namespace,
        maxSkewMs: options.maxSkewMs,
      });

      req[attachAuthTo] = verified;
      next();
    } catch (error) {
      const hmacError = toHmacError(error);
      if (options.onError) {
        options.onError(hmacError, req, res, next);
        return;
      }

      if (typeof res?.status === "function" && typeof res?.json === "function") {
        res.status(hmacError.status).json({
          error: hmacError.code,
          message: hmacError.message,
        });
        return;
      }

      next(hmacError);
    }
  };
}

export function createHttpHmacMiddleware(options: HttpHmacMiddlewareOptions) {
  return createExpressHttpHmacMiddleware(options);
}
