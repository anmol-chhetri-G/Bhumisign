export type Role = "ROOT_CA" | "LRO_OFFICER" | "CITIZEN" | "VERIFIER";
export type CertUsage = "certSign" | "crlSign" | "titleSign" | "transferSign" | "dataEncrypt";

export const ROLES: readonly Role[] = ["ROOT_CA", "LRO_OFFICER", "CITIZEN", "VERIFIER"];
export const CERT_USAGES: readonly CertUsage[] = [
  "certSign",
  "crlSign",
  "titleSign",
  "transferSign",
  "dataEncrypt",
];

/** Which usages each role must and may have. Enforced at issuance AND at verification. */
export const ROLE_PROFILE: Record<Role, { required: readonly CertUsage[]; allowed: readonly CertUsage[] }> = {
  ROOT_CA: { required: ["certSign", "crlSign"], allowed: ["certSign", "crlSign"] },
  LRO_OFFICER: { required: ["titleSign", "dataEncrypt"], allowed: ["titleSign", "dataEncrypt"] },
  CITIZEN: { required: ["transferSign", "dataEncrypt"], allowed: ["transferSign", "dataEncrypt"] },
  VERIFIER: { required: ["dataEncrypt"], allowed: ["dataEncrypt"] },
};

export interface Subject {
  id: string; // e.g. citizenship number surrogate; identity proofing is out of scope
  name: string;
  role: Role;
}

export interface CertificateBody {
  v: 1;
  serial: string; // 128-bit random, lowercase hex
  subject: Subject;
  issuerSerial: string; // equals serial for the self-signed root
  notBefore: string; // ISO-8601 UTC, e.g. 2026-11-24T00:00:00.000Z
  notAfter: string;
  usages: CertUsage[];
  signKey: string; // ECDSA P-256 public key, SPKI base64url
  encKey: string | null; // ECDH P-256 public key, present iff usages include dataEncrypt
}

export interface Certificate {
  body: CertificateBody;
  signature: string;
}

export type RevocationReason =
  | "keyCompromise"
  | "superseded"
  | "cessationOfOperation"
  | "affiliationChanged"
  | "unspecified";

export interface RevocationEntry {
  serial: string;
  revokedAt: string;
  reason: RevocationReason;
}

export interface CrlBody {
  v: 1;
  issuerSerial: string;
  crlNumber: number;
  thisUpdate: string;
  nextUpdate: string;
  revoked: RevocationEntry[];
}

export interface Crl {
  body: CrlBody;
  signature: string;
}

export interface EnrollmentRequest {
  subject: Subject;
  usages: CertUsage[];
  signKey: string;
  encKey: string | null;
  popSignature: string; // proof of possession: signed by the private key matching signKey
}

/** A signer = a certificate plus the matching private signing key. */
export interface Signer {
  certificate: Certificate;
  privateKey: CryptoKey;
}

/** Everything a verifier needs. `anchor` MUST come from an out-of-band, pinned source. */
export interface TrustContext {
  anchor: Certificate;
  crl: Crl | null;
  now: Date;
  directory: ReadonlyMap<string, Certificate>;
}
