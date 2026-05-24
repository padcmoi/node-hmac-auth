import type { MicroserviceConfigTemplate } from "./microservice-config.types";

// Scaled-up POC: 10 propagation clients with diverse plain secrets propagated
// across the 3 services that all have DIFFERENT `HMAC_SECRET_TOKEN`. The
// secretHash hotfix in `propagateClientToApis` guarantees each target receives
// the LOCAL hash (computed with source's token) and stores it as-is via
// setSecretHash, so every clientId is verifiable cross-token end-to-end.
const TARGETS = ["http://nest_target:3002", "http://express_target:3003"];

// `usesLocalRedisLookup: true` exercises the v0.6.0 fallback: the
// propagationPlans entry will be emitted WITHOUT a `secret` field; the lib
// resolves the secretHash from the local Redis (where it landed thanks to the
// matching internalCredentials entry that was synced earlier in syncFromConfig).
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
  // v0.6.0 demo: declared in internalCredentials (with a plain secret), but
  // the propagation plan below omits its `secret` and relies on the lib's
  // Redis fallback to fetch the secretHash already stored locally.
  { clientId: "client_via_redis_lookup", secret: "redisLookupSecret-XYZ-606", usesLocalRedisLookup: true },
];

// v1.1.0: message clients to propagate over HTTP via targetStore="message".
// Each one is declared locally in hmacMessage.credentials (so syncFromConfig
// creates it in the source message store) AND in propagationPlans below with
// targetStore: "message" so it lands on each remote's message store too.
const MESSAGE_CLIENTS = [
  { clientId: "msg_amqp_orders", secret: "msgOrdersSecret-MO-001" },
  { clientId: "msg_amqp_billing", secret: "msgBillingSecret-MB-001" },
];

export const microserviceConfig: MicroserviceConfigTemplate = {
  version: "1",
  hmac_config: {
    hmacMessage: {
      credentials: [{ clientId: "internal_sync", secret: "superSecret" }, ...MESSAGE_CLIENTS],
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
      propagationPlans: [
        ...PROPAGATED_CLIENTS.map((entry) => {
          const base = {
            signerClientId: "internal_sync",
            targets: TARGETS,
            clientId: entry.clientId,
            allowedIps: ["0.0.0.0/0", "::/0"],
          };
          // Auto-lookup branch: deliberately omit `secret` so the lib falls
          // back to the local Redis credentialStore (where this clientId was
          // synced from internalCredentials moments earlier).
          if (entry.usesLocalRedisLookup) {
            return base;
          }
          return { ...base, secret: entry.secret };
        }),
        // v1.1.0: message-store propagation. The signer stays an HTTP client
        // (the propagation POST itself must be authenticable by the target's
        // verifyHttpSignature). The `targetStore: "message"` flag tells the
        // remote to write the propagated client into its message store.
        ...MESSAGE_CLIENTS.map((entry) => ({
          signerClientId: "internal_sync",
          targets: TARGETS,
          clientId: entry.clientId,
          secret: entry.secret,
          allowedIps: ["0.0.0.0/0", "::/0"],
          targetStore: "message" as const,
        })),
      ],
    },
  },
};
