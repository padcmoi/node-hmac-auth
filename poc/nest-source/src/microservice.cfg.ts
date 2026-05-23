import type { MicroserviceConfigTemplate } from "./microservice-config.types";

// Scaled-up POC: 10 propagation clients with diverse plain secrets propagated
// across the 3 services that all have DIFFERENT `HMAC_SECRET_TOKEN`. The
// secretHash hotfix in `propagateClientToApis` guarantees each target receives
// the LOCAL hash (computed with source's token) and stores it as-is via
// setSecretHash, so every clientId is verifiable cross-token end-to-end.
const TARGETS = ["http://nest_target:3002", "http://express_target:3003"];

const PROPAGATED_CLIENTS = [
  { clientId: "internal_sync", secret: "superSecret" },
  { clientId: "external_client", secret: "superSharedSecret" },
  { clientId: "client_mobile", secret: "mobileSecret-aZ8Q12" },
  { clientId: "client_web", secret: "webSecret-LK9XwQ3" },
  { clientId: "client_admin_console", secret: "adminConsoleSecret-77zz" },
  { clientId: "client_partner_a", secret: "partnerA-uYR99qq" },
  { clientId: "client_partner_b", secret: "partnerB-pLm44ee" },
  { clientId: "client_ci_runner", secret: "ciRunnerSecret-DD2228" },
  { clientId: "client_analytics", secret: "analyticsSecret-ANA-001" },
  { clientId: "client_billing", secret: "billingSecret-INV-2026" },
];

export const microserviceConfig: MicroserviceConfigTemplate = {
  version: "1",
  hmac_config: {
    hmacMessage: {
      credentials: [{ clientId: "internal_sync", secret: "superSecret" }],
    },
    hmacHttp: {
      internalCredentials: [
        ...PROPAGATED_CLIENTS.map((entry) => ({
          clientId: entry.clientId,
          secret: entry.secret,
          allowedIps: ["0.0.0.0/0", "::/0"],
        })),
        // Source-only client: not in propagationPlans below; the signed-rejected
        // fetch test sends with this clientId and expects 401 UNKNOWN_CLIENT
        // on both targets (they never received it).
        {
          clientId: "source_only_client",
          secret: "sourceOnlySecret",
          allowedIps: ["0.0.0.0/0", "::/0"],
        },
      ],
      propagationPlans: PROPAGATED_CLIENTS.map((entry) => ({
        signerClientId: "internal_sync",
        targets: TARGETS,
        clientId: entry.clientId,
        secret: entry.secret,
        allowedIps: ["0.0.0.0/0", "::/0"],
      })),
    },
  },
};
