import { canonicalize } from "../crypto/canonical";
import { toHex } from "../crypto/bytes";
import { randomBytes, signMessage } from "../crypto/primitives";
import { fail } from "../result";
import type { Failure } from "../result";
import type { Certificate, Signer, TrustContext } from "../pki/types";
import { parseUtc } from "../pki/validate";
import type { Registry } from "./registry";
import { hashBody } from "./title";
import { isTransferEvidence } from "./validate";
import type {
  AcceptanceBody,
  Title,
  TitleBody,
  TitleRecord,
  TransferAcceptance,
  TransferEvidence,
  TransferIntent,
  TransferIntentBody,
} from "./types";

/** Step 1 (seller): sign an offer bound to the exact title version being sold. */
export async function createTransferIntent(
  seller: Signer,
  params: { title: Title; buyer: Certificate; now: Date; ttlMinutes?: number },
): Promise<TransferIntent> {
  const ttl = (params.ttlMinutes ?? 60) * 60_000;
  const body: TransferIntentBody = {
    v: 1,
    parcelId: params.title.body.parcelId,
    titleHash: await hashBody(params.title.body),
    sellerSerial: seller.certificate.body.serial,
    buyerSerial: params.buyer.body.serial,
    nonce: toHex(randomBytes(16)),
    issuedAt: params.now.toISOString(),
    expiresAt: new Date(params.now.getTime() + ttl).toISOString(),
  };
  return { body, signature: await signMessage(seller.privateKey, "transfer-intent", canonicalize(body)) };
}

/** Step 2 (buyer): countersign the hash of the seller's intent. */
export async function acceptTransferIntent(
  buyer: Signer,
  intent: TransferIntent,
  now: Date,
): Promise<TransferAcceptance> {
  const body: AcceptanceBody = {
    v: 1,
    intentHash: await hashBody(intent.body),
    buyerSerial: buyer.certificate.body.serial,
    acceptedAt: now.toISOString(),
  };
  return { body, signature: await signMessage(buyer.privateKey, "transfer-accept", canonicalize(body)) };
}

export type ExecuteResult = { ok: true; record: TitleRecord } | Failure;

/**
 * Step 3 (LRO officer): check the consent, build the next title and append it.
 * Fast pre-checks give precise error codes; the registry then re-verifies everything.
 */
export async function executeTransfer(params: {
  officer: Signer;
  registry: Registry;
  evidence: TransferEvidence;
  ctx: TrustContext;
}): Promise<ExecuteResult> {
  const { officer, registry, evidence, ctx } = params;
  if (!isTransferEvidence(evidence)) return fail("MALFORMED");
  const { intent, acceptance } = evidence;
  const head = registry.head(intent.body.parcelId);
  if (!head) return fail("UNKNOWN_PARCEL");

  if (intent.body.titleHash !== (await hashBody(head.title.body))) {
    return fail("HEAD_MISMATCH", "intent refers to a title version that is no longer current");
  }
  if (head.title.body.ownerSerial !== intent.body.sellerSerial) return fail("NOT_OWNER");
  if (registry.hasNonce(intent.body.nonce)) return fail("NONCE_REUSED");
  const expiresAt = parseUtc(intent.body.expiresAt);
  if (expiresAt === null) return fail("MALFORMED");
  if (ctx.now.getTime() > expiresAt) return fail("INTENT_EXPIRED");

  const buyer = ctx.directory.get(intent.body.buyerSerial);
  if (!buyer) return fail("UNKNOWN_CERT", "buyer");

  const body: TitleBody = {
    v: 1,
    parcelId: head.title.body.parcelId,
    seq: head.title.body.seq + 1,
    prevHash: intent.body.titleHash,
    ownerSerial: buyer.body.serial,
    ownerId: buyer.body.subject.id,
    areaSqm: head.title.body.areaSqm,
    issuedAt: ctx.now.toISOString(),
    issuerSerial: officer.certificate.body.serial,
    evidenceHash: await hashBody({ intent: intent.body, acceptance: acceptance.body }),
  };
  const record: TitleRecord = {
    title: { body, signature: await signMessage(officer.privateKey, "title", canonicalize(body)) },
    evidence,
  };
  const appended = await registry.append(record, ctx);
  return appended.ok ? { ok: true, record } : appended;
}
