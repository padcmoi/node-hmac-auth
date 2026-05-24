import { DynamicModule, Module } from "@nestjs/common";
import type { InitializedHmacMessageAuth } from "@naskot/node-hmac-auth";
import { AppController, NEST_TARGET_MESSAGE_AUTH } from "./app.controller";

@Module({})
export class AppModule {
  static forRoot(messageAuth: InitializedHmacMessageAuth): DynamicModule {
    return {
      module: AppModule,
      controllers: [AppController],
      providers: [{ provide: NEST_TARGET_MESSAGE_AUTH, useValue: messageAuth }],
    };
  }
}
