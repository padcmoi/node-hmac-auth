import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import { createHmacSourceRuntime } from "./hmac.service";
import { runV1_3_0_Demo } from "./v1-3-0-demo";

async function bootstrap(): Promise<void> {
  const port = Number(process.env.PORT ?? 3001);

  const hmac = await createHmacSourceRuntime();

  const app = await NestFactory.create<NestExpressApplication>(AppModule, {
    bodyParser: false,
    rawBody: true,
  });

  app.set("trust proxy", true);
  app.useBodyParser("json");
  app.use(hmac.getInternalManagementMiddleware());

  await app.listen(port, "0.0.0.0");
  console.log(`[nest_source] listening on :${port}`);

  await hmac.syncFromConfig();
  await hmac.logHttpClients();
  await hmac.logMessageClients();
  await hmac.sendSignedHelloToTargets();
  await hmac.sendRejectedSignedHelloToTargets();
  await hmac.verifyAllPropagatedClients();
  await hmac.verifyAllPropagatedMessageClients();

  // v1.3.0 end-to-end demonstration of purpose='propagation-only' (F1) and
  // requireBootstrapClientId (F2). Runs in an isolated namespace so the
  // legacy POC traffic above is unaffected. Failures here are loud but
  // non-fatal.
  try {
    await runV1_3_0_Demo();
  } catch (error) {
    console.error("[v1.3.0-demo] failed:", error);
  }

  setInterval(() => {
    void hmac.logHttpClients();
    void hmac.logMessageClients();
  }, 10000);

  setInterval(() => {
    void hmac.sendSignedHelloToTargets();
  }, 5000);

  setInterval(() => {
    void hmac.sendRejectedSignedHelloToTargets();
  }, 10000);

  setInterval(() => {
    void hmac.verifyAllPropagatedClients();
  }, 15000);

  setInterval(() => {
    void hmac.verifyAllPropagatedMessageClients();
  }, 15000);
}

void bootstrap();
