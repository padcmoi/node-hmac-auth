import { Body, Controller, HttpCode, Inject, Post, Req } from "@nestjs/common";
import type { InitializedHmacMessageAuth } from "@naskot/node-hmac-auth";

export const NEST_TARGET_MESSAGE_AUTH = Symbol("NEST_TARGET_MESSAGE_AUTH");

@Controller()
export class AppController {
  constructor(@Inject(NEST_TARGET_MESSAGE_AUTH) private readonly messageAuth: InitializedHmacMessageAuth) {}

  @Post("secure/poc")
  @HttpCode(200)
  handlePoc(@Req() req: any, @Body() body: unknown) {
    const authClientId = req?.hmacAuth?.clientId ?? "unknown";
    console.log(`[nest_target] secure request from clientId=${authClientId} body=${JSON.stringify(body)}`);

    return {
      ok: true,
      receiver: "nest_target",
      receivedFrom: authClientId,
      receivedBody: body ?? null,
    };
  }

  // v1.1.0 POC: verify that a message signed by the source's message store
  // is verifiable here. Proves the propagated secretHash matches byte-for-byte.
  @Post("message/verify")
  @HttpCode(200)
  async verifyMessage(@Body() body: { clientId?: string; message?: unknown; signature?: string }) {
    if (!body?.clientId || !body?.signature || body.message === undefined) {
      return { ok: false, error: "BAD_REQUEST", message: "clientId, message and signature are required" };
    }
    try {
      const verified = await this.messageAuth.verifyMessage({
        clientId: body.clientId,
        message: body.message,
        signature: body.signature,
      });
      return { ok: true, receiver: "nest_target", verifiedClientId: verified.clientId, messageHash: verified.messageHash };
    } catch (error) {
      const code = error instanceof Error && "code" in error ? (error as any).code : "VERIFY_FAILED";
      const message = error instanceof Error ? error.message : String(error);
      return { ok: false, receiver: "nest_target", error: code, message };
    }
  }
}
