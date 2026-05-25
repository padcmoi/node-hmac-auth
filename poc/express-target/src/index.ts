import express from "express";
import { createHmacExpressRuntime } from "./hmac.service";

declare global {
  namespace Express {
    interface Request {
      rawBody?: Buffer;
    }
  }
}

async function bootstrap(): Promise<void> {
  const port = Number(process.env.PORT ?? 3003);
  const hmac = await createHmacExpressRuntime("express_target");

  const app = express();
  app.set("trust proxy", true);
  app.use(
    express.json({
      verify: (req, _res, buffer) => {
        (req as express.Request & { rawBody?: Buffer }).rawBody = Buffer.from(buffer);
      },
    })
  );
  // Compatibility with verbs that carry no body (GET, DELETE, PATCH without
  // payload). `express.json({ verify })` only fires its callback when there is
  // a body to parse, so `req.rawBody` stays undefined for body-less requests.
  // The lib's middleware then falls back to `req.body` (which `express.json`
  // sets to `{}` even for GET) and signs `JSON.stringify({}) === "{}"` server-
  // side while the caller signed `""`. We normalize by forcing an empty Buffer
  // so the server and the client agree on `hash("")`.
  app.use((req, _res, next) => {
    const r = req as express.Request & { rawBody?: Buffer };
    if (!r.rawBody) {
      r.rawBody = Buffer.alloc(0);
    }
    next();
  });

  app.use("/secure", hmac.hmacAuth.verifyHttpRequest);
  app.use(hmac.getInternalManagementMiddleware());

  app.post("/secure/poc", (req, res) => {
    const authClientId = (req as express.Request & { hmacAuth?: { clientId?: string } }).hmacAuth?.clientId ?? "unknown";
    const body = req.body ?? null;

    console.log(`[express_target] secure request from clientId=${authClientId} body=${JSON.stringify(body)}`);

    res.status(200).json({
      ok: true,
      receiver: "express_target",
      receivedFrom: authClientId,
      receivedBody: body,
    });
  });

  // v1.1.0 POC: verify a message signed by the source's message store. Proves
  // the propagated secretHash on this target matches the source's hash byte-for-byte.
  app.post("/message/verify", async (req, res) => {
    const body = (req.body ?? {}) as { clientId?: string; message?: unknown; signature?: string };
    if (!body.clientId || !body.signature || body.message === undefined) {
      res.status(400).json({ ok: false, error: "BAD_REQUEST", message: "clientId, message and signature are required" });
      return;
    }
    try {
      const verified = await hmac.hmacMessageAuth.verifyMessage({
        clientId: body.clientId,
        message: body.message,
        signature: body.signature,
      });
      res.status(200).json({
        ok: true,
        receiver: "express_target",
        verifiedClientId: verified.clientId,
        messageHash: verified.messageHash,
      });
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as any).code : "VERIFY_FAILED";
      const message = error instanceof Error ? error.message : String(error);
      res.status(200).json({ ok: false, receiver: "express_target", error: code, message });
    }
  });

  app.listen(port, "0.0.0.0", async () => {
    console.log(`[express_target] listening on :${port}`);
    await hmac.logHttpClients();
    await hmac.logMessageClients();
  });

  setInterval(() => {
    void hmac.logHttpClients();
    void hmac.logMessageClients();
  }, 10000);
}

void bootstrap();
