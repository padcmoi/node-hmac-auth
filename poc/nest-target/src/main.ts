import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import { createHmacTargetRuntime } from "./hmac.service";

async function bootstrap(): Promise<void> {
  const port = Number(process.env.PORT ?? 3002);
  const hmac = await createHmacTargetRuntime("nest_target");

  const app = await NestFactory.create<NestExpressApplication>(AppModule.forRoot(hmac.hmacMessageAuth), {
    bodyParser: false,
    rawBody: true,
  });

  app.set("trust proxy", true);
  app.useBodyParser("json");
  app.use("/secure", hmac.hmacAuth.verifyHttpRequest);
  app.use(hmac.getInternalManagementMiddleware());

  await app.listen(port, "0.0.0.0");
  console.log(`[nest_target] listening on :${port}`);
  await hmac.logHttpClients();
  await hmac.logMessageClients();

  setInterval(() => {
    void hmac.logHttpClients();
    void hmac.logMessageClients();
  }, 10000);
}

void bootstrap();
