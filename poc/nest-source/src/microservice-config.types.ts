export type HmacHttpInternalCredentialPlan = {
  clientId: string;
  secret: string;
  allowedIps?: string[];
};

export type HmacHttpPropagationPlan = {
  signerClientId: string;
  targets: string[];
  clientId: string;
  // `secret` becomes optional in 0.6.0: when omitted, the lib falls back to
  // the local Redis credentialStore and reuses the existing secretHash for
  // `clientId`, provided the same clientId is already declared in
  // `internalCredentials`.
  secret?: string;
  allowedIps: string[];
  // v1.1.0: select the target credential store on the remote. Defaults to
  // "http" (1.0.x behavior). Set to "message" to write the propagated client
  // into the remote message store via the same internal-management route.
  targetStore?: "http" | "message";
};

// NOTE (v1.2.0): the `fromDbSeed` origin marker is intentionally NOT exposed
// on this static config type. Dynamic (db-seeded) credentials live in their
// own pipeline (see `db-seed.cfg.ts`). Keeping the two surfaces separate is a
// deliberate architectural choice so a consumer that opts out of the dynamic
// pipeline pays zero cost (no flag, no surface, no in-memory state).

export type HmacMessageCredentialPlan = {
  clientId: string;
  secret: string;
};

export type MicroserviceConfigTemplate = {
  version: "1";
  hmac_config?: {
    hmacHttp?: {
      internalCredentials?: HmacHttpInternalCredentialPlan[];
      propagationPlans?: HmacHttpPropagationPlan[];
    };
    hmacMessage?: {
      credentials?: HmacMessageCredentialPlan[];
    };
  };
};
