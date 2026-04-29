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

  app.listen(port, "0.0.0.0", async () => {
    console.log(`[express_target] listening on :${port}`);
    await hmac.logHttpClients();
  });

  setInterval(() => {
    void hmac.logHttpClients();
  }, 10000);
}

void bootstrap();
