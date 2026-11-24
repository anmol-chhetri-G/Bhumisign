import { CERT_USAGES, ROLES } from "./types";
import type { Certificate, Crl, Role, CertUsage } from "./types";

const HEX32 = /^[0-9a-f]{32}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;

export const isRecord = (x: unknown): x is Record<string, unknown> =>
  typeof x === "object" && x !== null && !Array.isArray(x);

/** Strict UTC timestamp parser. Returns milliseconds since epoch, or null when invalid. */
export function parseUtc(text: unknown): number | null {
  if (typeof text !== "string" || !ISO_UTC.test(text)) return null;
  const ms = Date.parse(text);
  return Number.isNaN(ms) ? null : ms;
}

const isSignature = (x: unknown): x is string => typeof x === "string" && B64URL.test(x);

export function isCertificate(x: unknown): x is Certificate {
  if (!isRecord(x) || !isRecord(x.body) || !isSignature(x.signature)) return false;
  const b = x.body;
  const subject = b.subject;
  if (b.v !== 1 || typeof b.serial !== "string" || !HEX32.test(b.serial)) return false;
  if (typeof b.issuerSerial !== "string" || !HEX32.test(b.issuerSerial)) return false;
  if (!isRecord(subject)) return false;
  if (typeof subject.id !== "string" || typeof subject.name !== "string") return false;
  if (!ROLES.includes(subject.role as Role)) return false;
  const nb = parseUtc(b.notBefore);
  const na = parseUtc(b.notAfter);
  if (nb === null || na === null || nb >= na) return false;
  if (!Array.isArray(b.usages) || !b.usages.every((u) => CERT_USAGES.includes(u as CertUsage))) return false;
  if (typeof b.signKey !== "string" || !B64URL.test(b.signKey)) return false;
  if (b.encKey !== null && (typeof b.encKey !== "string" || !B64URL.test(b.encKey))) return false;
  return true;
}

export function isCrl(x: unknown): x is Crl {
  if (!isRecord(x) || !isRecord(x.body) || !isSignature(x.signature)) return false;
  const b = x.body;
  if (b.v !== 1 || typeof b.issuerSerial !== "string" || !HEX32.test(b.issuerSerial)) return false;
  if (!Number.isSafeInteger(b.crlNumber)) return false;
  if (parseUtc(b.thisUpdate) === null || parseUtc(b.nextUpdate) === null) return false;
  if (!Array.isArray(b.revoked)) return false;
  return b.revoked.every(
    (e) =>
      isRecord(e) &&
      typeof e.serial === "string" &&
      HEX32.test(e.serial) &&
      parseUtc(e.revokedAt) !== null &&
      typeof e.reason === "string",
  );
}
