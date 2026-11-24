import { isRecord, parseUtc } from "../pki/validate";
import type { TitleRecord, TransferEvidence } from "./types";

const HEX32 = /^[0-9a-f]{32}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;

const hex = (re: RegExp, x: unknown): boolean => typeof x === "string" && re.test(x);
const label = (x: unknown): boolean => typeof x === "string" && x.length > 0 && x.length <= 128;
const signature = (x: unknown): boolean => typeof x === "string" && B64URL.test(x);
const positiveInt = (x: unknown): boolean => Number.isSafeInteger(x) && (x as number) > 0;

function isTitleBody(b: unknown): boolean {
  return (
    isRecord(b) &&
    b.v === 1 &&
    label(b.parcelId) &&
    Number.isSafeInteger(b.seq) && (b.seq as number) >= 0 &&
    (b.prevHash === null || hex(HEX64, b.prevHash)) &&
    hex(HEX32, b.ownerSerial) &&
    label(b.ownerId) &&
    positiveInt(b.areaSqm) &&
    parseUtc(b.issuedAt) !== null &&
    hex(HEX32, b.issuerSerial) &&
    (b.evidenceHash === null || hex(HEX64, b.evidenceHash))
  );
}

export function isTransferEvidence(x: unknown): x is TransferEvidence {
  if (!isRecord(x) || !isRecord(x.intent) || !isRecord(x.acceptance)) return false;
  const i = x.intent.body;
  const a = x.acceptance.body;
  return (
    isRecord(i) && i.v === 1 && label(i.parcelId) && hex(HEX64, i.titleHash) &&
    hex(HEX32, i.sellerSerial) && hex(HEX32, i.buyerSerial) && hex(HEX32, i.nonce) &&
    parseUtc(i.issuedAt) !== null && parseUtc(i.expiresAt) !== null &&
    signature(x.intent.signature) &&
    isRecord(a) && a.v === 1 && hex(HEX64, a.intentHash) && hex(HEX32, a.buyerSerial) &&
    parseUtc(a.acceptedAt) !== null && signature(x.acceptance.signature)
  );
}

/** Structural validation of untrusted input (e.g. a history file handed to a bank). */
export function isTitleRecord(x: unknown): x is TitleRecord {
  return (
    isRecord(x) &&
    isRecord(x.title) &&
    isTitleBody(x.title.body) &&
    signature(x.title.signature) &&
    (x.evidence === null || isTransferEvidence(x.evidence))
  );
}
