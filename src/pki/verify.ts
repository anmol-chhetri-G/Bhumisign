import { canonicalize } from "../crypto/canonical";
import { importSigningPublicKey, verifyMessage } from "../crypto/primitives";
import { fail, ok } from "../result";
import type { VerifyResult } from "../result";
import { ROLE_PROFILE } from "./types";
import type { CertUsage, Certificate, CertificateBody, Crl, TrustContext } from "./types";
import { isCertificate, isCrl, parseUtc } from "./validate";

/** Role/usage/encKey consistency. Used by the CA when issuing and by verifiers. */
export function checkProfile(body: CertificateBody): VerifyResult {
  const profile = ROLE_PROFILE[body.subject.role];
  for (const need of profile.required) {
    if (!body.usages.includes(need)) return fail("PROFILE_VIOLATION", `missing usage ${need}`);
  }
  for (const have of body.usages) {
    if (!profile.allowed.includes(have)) return fail("PROFILE_VIOLATION", `usage ${have} not allowed`);
  }
  if (new Set(body.usages).size !== body.usages.length) return fail("PROFILE_VIOLATION", "duplicate usage");
  if (body.usages.includes("dataEncrypt") !== (body.encKey !== null)) {
    return fail("PROFILE_VIOLATION", "encKey must be present iff dataEncrypt is requested");
  }
  return ok();
}

function checkWindow(from: string, to: string, at: Date): VerifyResult {
  const t = at.getTime();
  const nb = parseUtc(from);
  const na = parseUtc(to);
  if (nb === null || na === null) return fail("MALFORMED", "bad validity period");
  if (t < nb) return fail("NOT_YET_VALID");
  if (t > na) return fail("EXPIRED");
  return ok();
}

export async function verifyCrl(crl: Crl, ctx: TrustContext): Promise<VerifyResult> {
  if (!isCrl(crl)) return fail("CRL_INVALID", "malformed");
  const { anchor, now } = ctx;
  if (crl.body.issuerSerial !== anchor.body.serial) return fail("CRL_INVALID", "wrong issuer");
  if (!anchor.body.usages.includes("crlSign")) return fail("CRL_INVALID", "issuer cannot sign CRLs");
  const key = await importSigningPublicKey(anchor.body.signKey);
  if (!(await verifyMessage(key, "crl", canonicalize(crl.body), crl.signature))) {
    return fail("CRL_INVALID", "bad signature");
  }
  const thisUpdate = parseUtc(crl.body.thisUpdate) ?? 0;
  const nextUpdate = parseUtc(crl.body.nextUpdate) ?? 0;
  if (thisUpdate > now.getTime()) return fail("CRL_INVALID", "thisUpdate is in the future");
  if (now.getTime() > nextUpdate) return fail("CRL_STALE"); // fail closed
  return ok();
}

export interface VerifyOptions {
  /** Require this usage on the certificate. */
  usage?: CertUsage;
  /** Evaluate validity and revocation as of this time (default: ctx.now). */
  at?: Date;
  /** Default true: a missing CRL is an error (fail closed). */
  requireCrl?: boolean;
}

export async function verifyCertificate(
  cert: Certificate,
  ctx: TrustContext,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const { anchor } = ctx;
  const at = options.at ?? ctx.now;
  if (!isCertificate(cert) || !isCertificate(anchor)) return fail("MALFORMED");

  // The trust anchor must be a well-formed, self-signed root that can sign certificates.
  if (
    anchor.body.subject.role !== "ROOT_CA" ||
    anchor.body.issuerSerial !== anchor.body.serial ||
    !anchor.body.usages.includes("certSign")
  ) {
    return fail("PROFILE_VIOLATION", "bad trust anchor");
  }
  const anchorKey = await importSigningPublicKey(anchor.body.signKey);
  if (!(await verifyMessage(anchorKey, "cert", canonicalize(anchor.body), anchor.signature))) {
    return fail("BAD_SIGNATURE", "trust anchor self-signature");
  }
  const anchorWindow = checkWindow(anchor.body.notBefore, anchor.body.notAfter, at);
  if (!anchorWindow.ok) return anchorWindow;

  const isAnchor = cert.body.serial === anchor.body.serial;
  if (isAnchor) {
    if (canonicalize(cert.body) !== canonicalize(anchor.body)) return fail("BAD_SIGNATURE", "not the pinned anchor");
    return options.usage && !cert.body.usages.includes(options.usage) ? fail("USAGE_NOT_PERMITTED") : ok();
  }

  if (cert.body.issuerSerial !== anchor.body.serial) return fail("ISSUER_MISMATCH");
  if (!(await verifyMessage(anchorKey, "cert", canonicalize(cert.body), cert.signature))) {
    return fail("BAD_SIGNATURE");
  }
  if (cert.body.subject.role === "ROOT_CA") return fail("PROFILE_VIOLATION", "only the anchor may be a root");
  const profile = checkProfile(cert.body);
  if (!profile.ok) return profile;
  const window = checkWindow(cert.body.notBefore, cert.body.notAfter, at);
  if (!window.ok) return window;
  if (options.usage && !cert.body.usages.includes(options.usage)) return fail("USAGE_NOT_PERMITTED", options.usage);

  if (options.requireCrl ?? true) {
    if (!ctx.crl) return fail("CRL_MISSING");
    const crlResult = await verifyCrl(ctx.crl, ctx);
    if (!crlResult.ok) return crlResult;
    const entry = ctx.crl.body.revoked.find((e) => e.serial === cert.body.serial);
    if (entry && (parseUtc(entry.revokedAt) ?? Infinity) <= at.getTime()) {
      return fail("REVOKED", entry.reason);
    }
  }
  return ok();
}
