import { canonicalize } from "../crypto/canonical";
import { toHex } from "../crypto/bytes";
import {
  exportPublicKey,
  generateEcdhKeyPair,
  generateSigningKeyPair,
  importSigningPublicKey,
  randomBytes,
  signMessage,
  verifyMessage,
} from "../crypto/primitives";
import { fail } from "../result";
import type { Failure } from "../result";
import type {
  CertUsage,
  Certificate,
  CertificateBody,
  Crl,
  EnrollmentRequest,
  RevocationEntry,
  RevocationReason,
  Signer,
  Subject,
} from "./types";
import { checkProfile } from "./verify";
import { isRecord } from "./validate";

const DAY_MS = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

export type IssueResult = { ok: true; certificate: Certificate } | Failure;

/** Payload covered by the proof-of-possession signature. */
const popPayload = (r: Omit<EnrollmentRequest, "popSignature">) =>
  canonicalize({ subject: r.subject, usages: r.usages, signKey: r.signKey, encKey: r.encKey });

export async function createEnrollmentRequest(
  subject: Subject,
  usages: CertUsage[],
  signing: CryptoKeyPair,
  encryptionPublicKey: CryptoKey | null,
): Promise<EnrollmentRequest> {
  const base = {
    subject,
    usages,
    signKey: await exportPublicKey(signing.publicKey),
    encKey: encryptionPublicKey ? await exportPublicKey(encryptionPublicKey) : null,
  };
  return { ...base, popSignature: await signMessage(signing.privateKey, "enroll", popPayload(base)) };
}

export class CertificateAuthority {
  private readonly issued = new Map<string, Certificate>();
  private readonly revoked = new Map<string, RevocationEntry>();
  private crlCounter = 0;

  private constructor(
    readonly certificate: Certificate,
    private readonly signingKey: CryptoKey,
  ) {
    this.issued.set(certificate.body.serial, certificate);
  }

  /** Self-signed root. In a real deployment this key lives offline / in an HSM. */
  static async createRoot(name: string, now: Date, validityDays = 3650): Promise<CertificateAuthority> {
    const keys = await generateSigningKeyPair(false);
    const serial = toHex(randomBytes(16));
    const body: CertificateBody = {
      v: 1,
      serial,
      subject: { id: "root", name, role: "ROOT_CA" },
      issuerSerial: serial,
      notBefore: now.toISOString(),
      notAfter: iso(now.getTime() + validityDays * DAY_MS),
      usages: ["certSign", "crlSign"],
      signKey: await exportPublicKey(keys.publicKey),
      encKey: null,
    };
    const signature = await signMessage(keys.privateKey, "cert", canonicalize(body));
    return new CertificateAuthority({ body, signature }, keys.privateKey);
  }

  get directory(): ReadonlyMap<string, Certificate> {
    return this.issued;
  }

  async issue(request: EnrollmentRequest, now: Date, validityDays = 365): Promise<IssueResult> {
    if (!isRecord(request) || typeof request.popSignature !== "string") return fail("MALFORMED");
    if (request.subject.role === "ROOT_CA") return fail("PROFILE_VIOLATION", "cannot issue a root");

    // Proof of possession: the requester must hold the private key for the key being certified.
    let requesterKey: CryptoKey;
    try {
      requesterKey = await importSigningPublicKey(request.signKey);
    } catch {
      return fail("MALFORMED", "bad signKey");
    }
    const { popSignature, ...rest } = request;
    if (!(await verifyMessage(requesterKey, "enroll", popPayload(rest), popSignature))) return fail("BAD_POP");

    const notBefore = now.getTime();
    const notAfter = Math.min(
      notBefore + validityDays * DAY_MS,
      Date.parse(this.certificate.body.notAfter),
    );
    const body: CertificateBody = {
      v: 1,
      serial: toHex(randomBytes(16)),
      subject: request.subject,
      issuerSerial: this.certificate.body.serial,
      notBefore: iso(notBefore),
      notAfter: iso(notAfter),
      usages: request.usages,
      signKey: request.signKey,
      encKey: request.encKey,
    };
    const profile = checkProfile(body);
    if (!profile.ok) return profile;
    if (notAfter <= notBefore) return fail("EXPIRED", "CA certificate expires before the requested period");

    const certificate: Certificate = {
      body,
      signature: await signMessage(this.signingKey, "cert", canonicalize(body)),
    };
    this.issued.set(body.serial, certificate);
    return { ok: true, certificate };
  }

  revoke(serial: string, reason: RevocationReason, now: Date): boolean {
    if (serial === this.certificate.body.serial || !this.issued.has(serial)) return false;
    if (!this.revoked.has(serial)) this.revoked.set(serial, { serial, revokedAt: now.toISOString(), reason });
    return true;
  }

  async publishCrl(now: Date, validityHours = 24): Promise<Crl> {
    const body = {
      v: 1 as const,
      issuerSerial: this.certificate.body.serial,
      crlNumber: ++this.crlCounter,
      thisUpdate: now.toISOString(),
      nextUpdate: iso(now.getTime() + validityHours * 3_600_000),
      revoked: [...this.revoked.values()],
    };
    return { body, signature: await signMessage(this.signingKey, "crl", canonicalize(body)) };
  }
}

/* ---------- convenience for demos and tests ---------- */

export interface Identity extends Signer {
  signing: CryptoKeyPair;
  encryption: CryptoKeyPair | null;
}

const DEFAULT_USAGES: Record<Subject["role"], CertUsage[]> = {
  ROOT_CA: ["certSign", "crlSign"],
  LRO_OFFICER: ["titleSign", "dataEncrypt"],
  CITIZEN: ["transferSign", "dataEncrypt"],
  VERIFIER: ["dataEncrypt"],
};

/** Generates fresh key pairs, builds the enrollment request and has the CA certify it. */
export async function enrollIdentity(
  ca: CertificateAuthority,
  subject: Subject,
  now: Date,
  validityDays = 365,
): Promise<Identity> {
  const usages = DEFAULT_USAGES[subject.role];
  const signing = await generateSigningKeyPair(true);
  const encryption = usages.includes("dataEncrypt") ? await generateEcdhKeyPair(true) : null;
  const request = await createEnrollmentRequest(subject, usages, signing, encryption?.publicKey ?? null);
  const result = await ca.issue(request, now, validityDays);
  if (!result.ok) throw new Error(`enrollment failed: ${result.error}`);
  return { certificate: result.certificate, privateKey: signing.privateKey, signing, encryption };
}
