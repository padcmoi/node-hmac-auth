/**
 * Dynamic DB-seed origin simulation (POC, v1.2.0+).
 *
 * The lib treats HMAC credentials as opaque: every credential is just a
 * `clientId` + `secretHash` regardless of where the operator chose to keep
 * the source-of-truth. The optional `fromDbSeed: true` marker on the
 * propagation payload (and on the stored credential record) lets the
 * operator distinguish, on the target side, credentials managed
 * dynamically from a database from credentials declared statically in
 * `microservice.cfg.ts` / code.
 *
 * This file deliberately uses an in-memory array instead of a real
 * database. The POC stays minimal: no extra container, no migration.
 * A real consumer plugs its own DB-backed pipeline here (cron pulling
 * rows, listening to a queue, etc.) and ends up calling the same
 * `propagateClientToApis({ fromDbSeed: true, ... })` shape.
 *
 * The feature is fully optional: leaving this file empty (or never
 * importing it) keeps the lib in classic 1.0.x / 1.1.x behaviour with
 * `fromDbSeed=false` everywhere on the wire.
 */
export type DbSeedRow = {
  clientId: string;
  secret: string;
  targetStore?: "http" | "message";
};

export const dbSeedRows: DbSeedRow[] = [
  // Simulated rows that would normally live in a `hmac_credential_seed`-style
  // table. Each will be propagated with `fromDbSeed: true`.
  { clientId: "client_analytics", secret: "analyticsSecret-ANA-001" },
  { clientId: "client_billing", secret: "billingSecret-INV-2026" },
  { clientId: "msg_amqp_billing", secret: "msgBillingSecret-MB-001", targetStore: "message" },
];
