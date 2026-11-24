import { canonicalize } from "../crypto/canonical";
import { sha256Hex, signMessage } from "../crypto/primitives";
import { fail } from "../result";
import type { Failure } from "../result";
import type { Certificate, Signer } from "../pki/types";
import type { Title, TitleBody } from "./types";

/** Hash of any signed body: SHA-256 over its canonical JSON. Signatures are never hashed. */
export const hashBody = (body: unknown): Promise<string> => sha256Hex(canonicalize(body));

export type IssueTitleResult = { ok: true; title: Title } | Failure;

/** First registration of a parcel (seq 0). Only a certificate with titleSign should call this. */
export async function issueTitle(
  officer: Signer,
  params: { parcelId: string; owner: Certificate; areaSqm: number; now: Date },
): Promise<IssueTitleResult> {
  if (params.owner.body.subject.role !== "CITIZEN") return fail("PROFILE_VIOLATION", "owner must be a citizen");
  if (!Number.isSafeInteger(params.areaSqm) || params.areaSqm <= 0) return fail("MALFORMED", "areaSqm");
  const body: TitleBody = {
    v: 1,
    parcelId: params.parcelId,
    seq: 0,
    prevHash: null,
    ownerSerial: params.owner.body.serial,
    ownerId: params.owner.body.subject.id,
    areaSqm: params.areaSqm,
    issuedAt: params.now.toISOString(),
    issuerSerial: officer.certificate.body.serial,
    evidenceHash: null,
  };
  return { ok: true, title: { body, signature: await signMessage(officer.privateKey, "title", canonicalize(body)) } };
}
