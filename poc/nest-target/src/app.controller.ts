import { Body, Controller, HttpCode, Post, Req } from "@nestjs/common";

@Controller("secure")
export class AppController {
  @Post("poc")
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
}
