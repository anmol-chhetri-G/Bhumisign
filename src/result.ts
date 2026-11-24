export type ErrorCode =
  | "MALFORMED"
  | "BAD_SIGNATURE"
  | "BAD_POP"
  | "NOT_YET_VALID"
  | "EXPIRED"
  | "ISSUER_MISMATCH"
  | "USAGE_NOT_PERMITTED"
  | "PROFILE_VIOLATION"
  | "REVOKED"
  | "CRL_MISSING"
  | "CRL_STALE"
  | "CRL_INVALID"
  | "UNKNOWN_CERT"
  | "UNKNOWN_PARCEL"
  | "DUPLICATE_PARCEL"
  | "HEAD_MISMATCH"
  | "NOT_OWNER"
  | "INTENT_EXPIRED"
  | "INTENT_MISMATCH"
  | "NONCE_REUSED"
  | "BROKEN_CHAIN"
  | "BAD_EVIDENCE"
  | "CLOCK_SKEW";

export interface Failure {
  ok: false;
  error: ErrorCode;
  detail?: string;
}

export type VerifyResult = { ok: true } | Failure;

export const ok = (): { ok: true } => ({ ok: true });

export const fail = (error: ErrorCode, detail?: string): Failure =>
  detail === undefined ? { ok: false, error } : { ok: false, error, detail };
