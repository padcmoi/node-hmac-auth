import type { HmacAuthError } from "../core/errors.js";
import type {
  HmacInternalManagementRequestInput,
  HmacInternalManagementRequestResult,
  OnBadHttpSignature,
} from "../core/types.js";
import type { RedisLikeClient } from "../stores/redis.js";
import { toHmacError } from "./internal-helpers.js";
import { createExpressHttpHmacMiddleware } from "./server/express.js";

/**
 * Middleware factories exposed by `initializeHmacHttpAuth`.
 *
 * Two factories live here, both returning Express-compatible middleware:
 *
 *   `createHttpMiddlewareFactory(...)` - thin wrapper around
 *      `createExpressHttpHmacMiddleware` for protecting business routes.
 *
 *   `createInternalManagementMiddlewareFactory(...)` - turns
 *      `handleInternalManagementRequest` into an Express middleware that
 *      writes the response itself when handled, and forwards otherwise.
 */

type AnyReq = any;
type AnyRes = any;
type Next = (error?: unknown) => void;

export type HttpMiddlewareFactoryOptions = {
  attachAuthTo?: string;
  maxSkewMs?: number;
  onError?: (error: HmacAuthError, req: AnyReq, res: AnyRes, next: Next) => void;
  onBadSignature?: OnBadHttpSignature;
};

export interface CreateHttpMiddlewareFactoryDeps {
  redis: RedisLikeClient;
  namespace: string;
  maxSkewMs: number;
  defaultOnBadSignature?: OnBadHttpSignature;
  /** v1.3.0: propagated to `verifyHttpSignature` for purpose cantonment. */
  internalManagementRoute?: string;
  /** v1.3.0: propagated to `verifyHttpSignature` for bootstrap-window lock. */
  requireBootstrapClientId?: string;
}

export function createHttpMiddlewareFactory(
  deps: CreateHttpMiddlewareFactoryDeps
): (options?: HttpMiddlewareFactoryOptions) => (req: AnyReq, res: AnyRes, next: Next) => Promise<void> {
  return (middlewareOptions) =>
    createExpressHttpHmacMiddleware({
      redis: deps.redis,
      namespace: deps.namespace,
      maxSkewMs: middlewareOptions?.maxSkewMs ?? deps.maxSkewMs,
      attachAuthTo: middlewareOptions?.attachAuthTo,
      onError: middlewareOptions?.onError,
      onBadSignature: middlewareOptions?.onBadSignature ?? deps.defaultOnBadSignature,
      internalManagementRoute: deps.internalManagementRoute,
      requireBootstrapClientId: deps.requireBootstrapClientId,
    });
}

export interface CreateInternalManagementMiddlewareFactoryDeps {
  handleInternalManagementRequest: (input: HmacInternalManagementRequestInput) => Promise<HmacInternalManagementRequestResult>;
  maxSkewMs: number;
  defaultOnBadSignature?: OnBadHttpSignature;
}

export function createInternalManagementMiddlewareFactory(
  deps: CreateInternalManagementMiddlewareFactoryDeps
): (options?: HttpMiddlewareFactoryOptions) => (req: AnyReq, res: AnyRes, next: Next) => Promise<void> {
  return (middlewareOptions) => {
    const attachAuthTo = middlewareOptions?.attachAuthTo ?? "hmacAuth";

    return async (req, res, next) => {
      try {
        const result = await deps.handleInternalManagementRequest({
          method: req.method,
          path: req.originalUrl ?? req.url,
          headers: req.headers,
          rawBody: req.rawBody ?? req.body,
          now: Date.now(),
          maxSkewMs: middlewareOptions?.maxSkewMs ?? deps.maxSkewMs,
          onBadSignature: middlewareOptions?.onBadSignature ?? deps.defaultOnBadSignature,
          metadata: {
            ip: req?.ip,
            ips: req?.ips,
            remoteAddress: req?.socket?.remoteAddress,
            forwardedFor: req?.headers?.["x-forwarded-for"],
          },
        });

        if (!result.handled) {
          next();
          return;
        }

        if (result.verifiedAuth) {
          req[attachAuthTo] = result.verifiedAuth;
        }

        if (typeof res?.status === "function" && typeof res?.json === "function") {
          res.status(result.status).json(result.body);
          return;
        }

        next();
      } catch (error) {
        const hmacError = toHmacError(error);
        if (middlewareOptions?.onError) {
          middlewareOptions.onError(hmacError, req, res, next);
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
  };
}
