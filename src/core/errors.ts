export type HmacAuthErrorCode =
  | "MISSING_CLIENT_ID"
  | "MISSING_SIGNATURE"
  | "MISSING_TIMESTAMP"
  | "MISSING_NONCE"
  | "INVALID_TIMESTAMP"
  | "TIMESTAMP_SKEW"
  | "UNKNOWN_CLIENT"
  | "CLIENT_EXPIRED"
  | "MISSING_CLIENT_IP"
  | "CLIENT_IP_NOT_ALLOWED"
  | "CLIENT_NOT_FOUND"
  | "BAD_SIGNATURE"
  | "REPLAYED_NONCE"
  | "INTERNAL_ROUTE_DISABLED"
  | "INTERNAL_ERROR";

export class HmacAuthError extends Error {
  public readonly status: number;
  public readonly code: HmacAuthErrorCode;

  constructor(code: HmacAuthErrorCode, message: string, status = 401) {
    super(message);
    this.name = "HmacAuthError";
    this.code = code;
    this.status = status;
  }
}
