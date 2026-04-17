import type { SignedHttpFetchClientCallOptions } from "./client/signed-fetch.js";
import type { InitializedHmacHttpAuth } from "./init.js";

type HmacAuthRuntime = Pick<InitializedHmacHttpAuth, "clients" | "createHttpSignedFetchClient" | "verifyHttpRequest">;

export function createHmacRuntime(hmacAuth: HmacAuthRuntime) {
  const createSignedFetchFromClientId = async (clientId: string) => {
    const client = await hmacAuth.clients.get(clientId);
    if (!client) {
      throw new Error(`${clientId} not found in Redis`);
    }

    return hmacAuth.createHttpSignedFetchClient({
      clientId,
      secret: client.secretHash,
      secretIsHashed: true,
    });
  };

  const signedFetchWithClientId = async (input: string, clientId: string, options?: SignedHttpFetchClientCallOptions) => {
    const signedFetch = await createSignedFetchFromClientId(clientId);
    return signedFetch(input, options);
  };

  const hmacHttpMiddleware = (...clientIds: string[]) => {
    const allowed = new Set(clientIds.map((v) => v.trim()).filter(Boolean));
    return async (req: any, res: any, next: (error?: unknown) => void) =>
      hmacAuth.verifyHttpRequest(req, res, (error?: unknown) => {
        const callerClientId = String(req?.hmacAuth?.clientId ?? "");
        if (error || allowed.size === 0 || allowed.has(callerClientId)) return next(error);
        throw new Error(`Client '${callerClientId || "unknown"}' is not allowed`);
      });
  };

  return {
    createSignedFetchFromClientId,
    signedFetchWithClientId,
    hmacHttpMiddleware,
  };
}

export type HmacRuntime = ReturnType<typeof createHmacRuntime>;
