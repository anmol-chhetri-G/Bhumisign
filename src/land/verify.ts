import { canonicalize } from "../crypto/canonical";
import { importSigningPublicKey, verifyMessage } from "../crypto/primitives";
import { fail, ok } from "../result";
import type { VerifyResult } from "../result";
import { verifyCertificate } from "../pki/verify";
import type { Certificate, TrustContext } from "../pki/types";
import { parseUtc } from "../pki/validate";
import { hashBody } from "./title";
import type { TitleRecord } from "./types";
import { isTitleRecord } from "./validate";

async function checkSignedBy(
  cert: Certificate | undefined,
  ctx: TrustContext,
  usage: "titleSign" | "transferSign",
  at: Date,
  context: string,
  body: unknown,
  signature: string,
): Promise<VerifyResult> {
  if (!cert) return fail("UNKNOWN_CERT");
  const certResult = await verifyCertificate(cert, ctx, { usage, at });
  if (!certResult.ok) return certResult;
  const key = await importSigningPublicKey(cert.body.signKey);
  return (await verifyMessage(key, context, canonicalize(body), signature))
    ? ok()
    : fail("BAD_SIGNATURE", context);
}

/**
 * Verifies one link of a parcel history against its predecessor (undefined for the first link).
 * Used by the registry before accepting a record AND by third parties re-verifying a history.
 */
export async function verifyLink(
  prev: TitleRecord | undefined,
  record: TitleRecord,
  ctx: TrustContext,
): Promise<VerifyResult> {
  if (!isTitleRecord(record) || (prev !== undefined && !isTitleRecord(prev))) return fail("MALFORMED");
  const t = record.title.body;
  const issuedAtMs = parseUtc(t.issuedAt) ?? 0;
  // Every certificate is evaluated as of the LRO-attested issuance time, never a signer-claimed time.
  const issuedAt = new Date(issuedAtMs);

  // 1. LRO officer signature
  const officerResult = await checkSignedBy(
    ctx.directory.get(t.issuerSerial), ctx, "titleSign", issuedAt, "title", t, record.title.signature,
  );
  if (!officerResult.ok) return officerResult;

  // 2. owner must be a known citizen certificate that matches the recorded id
  const owner = ctx.directory.get(t.ownerSerial);
  if (!owner || owner.body.subject.role !== "CITIZEN" || owner.body.subject.id !== t.ownerId) {
    return fail("UNKNOWN_CERT", "owner");
  }

  // 3. position in the chain
  if (!prev) {
    return t.seq === 0 && t.prevHash === null && t.evidenceHash === null && record.evidence === null
      ? ok()
      : fail("BROKEN_CHAIN", "invalid first record");
  }
  const p = prev.title.body;
  if (t.parcelId !== p.parcelId || t.seq !== p.seq + 1) return fail("BROKEN_CHAIN", "sequence");
  if (t.prevHash !== (await hashBody(p))) return fail("BROKEN_CHAIN", "prevHash");

  // 4. consent evidence: seller intent + buyer acceptance, both signed and consistent
  const ev = record.evidence;
  if (!ev) return fail("BAD_EVIDENCE", "missing");
  const { intent, acceptance } = ev;
  const intentHash = await hashBody(intent.body);
  if (t.evidenceHash !== (await hashBody({ intent: intent.body, acceptance: acceptance.body }))) {
    return fail("BAD_EVIDENCE", "evidenceHash");
  }
  if (
    intent.body.parcelId !== t.parcelId ||
    intent.body.titleHash !== t.prevHash ||
    intent.body.sellerSerial !== p.ownerSerial ||
    intent.body.buyerSerial !== t.ownerSerial ||
    acceptance.body.buyerSerial !== t.ownerSerial ||
    acceptance.body.intentHash !== intentHash
  ) {
    return fail("INTENT_MISMATCH");
  }
  const intentAt = parseUtc(intent.body.issuedAt);
  const expiresAt = parseUtc(intent.body.expiresAt);
  const acceptedAt = parseUtc(acceptance.body.acceptedAt);
  if (intentAt === null || expiresAt === null || acceptedAt === null) return fail("MALFORMED");
  if (!(intentAt <= acceptedAt && acceptedAt <= issuedAtMs && issuedAtMs <= expiresAt)) {
    return fail("INTENT_EXPIRED", "timestamps out of order or offer expired");
  }

  const seller = await checkSignedBy(
    ctx.directory.get(intent.body.sellerSerial), ctx, "transferSign", issuedAt,
    "transfer-intent", intent.body, intent.signature,
  );
  if (!seller.ok) return seller;
  return checkSignedBy(
    ctx.directory.get(acceptance.body.buyerSerial), ctx, "transferSign", issuedAt,
    "transfer-accept", acceptance.body, acceptance.signature,
  );
}

/** Third-party check (e.g. a bank): re-verifies every link from the first registration. */
export async function verifyHistory(
  records: readonly TitleRecord[],
  ctx: TrustContext,
): Promise<VerifyResult> {
  if (!Array.isArray(records)) return fail("MALFORMED");
  if (records.length === 0) return fail("UNKNOWN_PARCEL");
  let prev: TitleRecord | undefined;
  for (const [index, record] of records.entries()) {
    const result = await verifyLink(prev, record, ctx);
    if (!result.ok) return { ...result, detail: `record ${index}: ${result.detail ?? result.error}` };
    prev = record;
  }
  return ok();
}
