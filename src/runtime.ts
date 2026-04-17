import type { SignedHttpFetchClientCallOptions } from "./client/signed-fetch.js";
import type { InitializedHmacHttpAuth } from "./init.js";

export function createHmacRuntime(hmacAuth: Pick<InitializedHmacHttpAuth, "clients" | "createHttpSignedFetchClient">) {
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

  return {
    createSignedFetchFromClientId,
    signedFetchWithClientId,
  };
}

export type HmacRuntime = ReturnType<typeof createHmacRuntime>;
