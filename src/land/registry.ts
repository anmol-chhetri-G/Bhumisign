import { fail, ok } from "../result";
import type { VerifyResult } from "../result";
import type { TrustContext } from "../pki/types";
import { parseUtc } from "../pki/validate";
import type { TitleRecord } from "./types";
import { isTitleRecord } from "./validate";
import { verifyLink } from "./verify";

/** Records must be stamped within this window of the registry's own clock (blocks back-dating). */
export const MAX_CLOCK_SKEW_MS = 5 * 60_000;

/**
 * Append-only, in-memory registry: one linear chain per parcel.
 * It re-verifies every record before accepting it and makes the append atomic
 * (compare-and-swap on the chain length), so concurrent double sales cannot both succeed.
 */
export class Registry {
  private readonly chains = new Map<string, TitleRecord[]>();
  private readonly usedNonces = new Set<string>();

  head(parcelId: string): TitleRecord | undefined {
    return this.chains.get(parcelId)?.at(-1);
  }

  history(parcelId: string): readonly TitleRecord[] {
    return [...(this.chains.get(parcelId) ?? [])];
  }

  hasNonce(nonce: string): boolean {
    return this.usedNonces.has(nonce);
  }

  async append(record: TitleRecord, ctx: TrustContext): Promise<VerifyResult> {
    if (!isTitleRecord(record)) return fail("MALFORMED");
    const issuedAt = parseUtc(record.title.body.issuedAt) ?? 0;
    if (Math.abs(ctx.now.getTime() - issuedAt) > MAX_CLOCK_SKEW_MS) return fail("CLOCK_SKEW");
    const parcelId = record.title.body.parcelId;
    const before = this.chains.get(parcelId) ?? [];
    const prev = before.at(-1);

    if (!prev && record.title.body.seq !== 0) return fail("UNKNOWN_PARCEL");
    if (prev && record.title.body.seq === 0) return fail("DUPLICATE_PARCEL");
    const nonce = record.evidence?.intent.body.nonce;
    if (nonce !== undefined && this.usedNonces.has(nonce)) return fail("NONCE_REUSED");

    const result = await verifyLink(prev, record, ctx);
    if (!result.ok) return result;

    // Compare-and-swap. Chains are append-only, so an unchanged length means an unchanged head.
    // Everything from here to the end of the method is synchronous, so it cannot interleave.
    const current = this.chains.get(parcelId) ?? [];
    if (current.length !== before.length) {
      return fail("HEAD_MISMATCH", "registry head changed during verification");
    }
    if (nonce !== undefined) {
      if (this.usedNonces.has(nonce)) return fail("NONCE_REUSED");
      this.usedNonces.add(nonce);
    }
    this.chains.set(parcelId, [...current, record]);
    return ok();
  }
}
