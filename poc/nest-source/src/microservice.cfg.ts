import type { MicroserviceConfigTemplate } from "./microservice-config.types";

export const microserviceConfig: MicroserviceConfigTemplate = {
  version: "1",
  hmac_config: {
    hmacMessage: {
      credentials: [{ clientId: "internal_sync", secret: "superSecret" }],
    },
    hmacHttp: {
      internalCredentials: [
        {
          clientId: "internal_sync",
          secret: "superSecret",
          allowedIps: ["0.0.0.0/0", "::/0"],
        },
        {
          clientId: "source_only_client",
          secret: "sourceOnlySecret",
          allowedIps: ["0.0.0.0/0", "::/0"],
        },
      ],
      propagationPlans: [
        {
          signerClientId: "internal_sync",
          targets: ["http://nest_target:3002", "http://express_target:3003"],
          clientId: "internal_sync",
          secret: "superSecret",
          allowedIps: ["0.0.0.0/0", "::/0"],
        },
        {
          signerClientId: "internal_sync",
          targets: ["http://nest_target:3002", "http://express_target:3003"],
          clientId: "external_client",
          secret: "superSharedSecret",
          allowedIps: ["0.0.0.0/0", "::/0"],
        },
      ],
    },
  },
};
