import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import { createHmacSourceRuntime } from "./hmac.service";

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
  await hmac.sendSignedHelloToTargets();
  await hmac.sendRejectedSignedHelloToTargets();
  await hmac.verifyAllPropagatedClients();

  setInterval(() => {
    void hmac.logHttpClients();
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
}

void bootstrap();
