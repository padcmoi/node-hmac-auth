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
};

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
