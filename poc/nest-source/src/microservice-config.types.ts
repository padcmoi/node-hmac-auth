export type HmacHttpInternalCredentialPlan = {
  clientId: string;
  secret: string;
  allowedIps?: string[];
};

export type HmacHttpPropagationPlan = {
  signerClientId: string;
  targets: string[];
  clientId: string;
  secret: string;
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
