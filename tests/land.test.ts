import { describe, expect, it } from "vitest";
import { canonicalize } from "../src/crypto/canonical";
import { signMessage } from "../src/crypto/primitives";
import type { Identity } from "../src/pki/ca";
import { Registry } from "../src/land/registry";
import { hashBody, issueTitle } from "../src/land/title";
import { acceptTransferIntent, createTransferIntent, executeTransfer } from "../src/land/transfer";
import type { TitleBody, TitleRecord, TransferEvidence } from "../src/land/types";
import { verifyHistory } from "../src/land/verify";
import { PARCEL, at, makeWorld } from "./helpers";
import type { World } from "./helpers";

const clone = <T>(x: T): T => structuredClone(x);

async function evidenceFor(w: World, seller = w.sita, buyer = w.ram, minute = 12): Promise<TransferEvidence> {
  const head = w.registry.head(PARCEL) as TitleRecord;
  const intent = await createTransferIntent(seller, { title: head.title, buyer: buyer.certificate, now: at(minute) });
  const acceptance = await acceptTransferIntent(buyer, intent, at(minute + 1));
  return { intent, acceptance };
}

async function sell(w: World, minute = 12) {
  const evidence = await evidenceFor(w, w.sita, w.ram, minute);
  return { evidence, result: await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(minute + 5)) }) };
}

describe("issuing titles", () => {
  it("rejects invalid owners and areas", async () => {
    const w = await makeWorld();
    expect(await issueTitle(w.officer, { parcelId: "P2", owner: w.bank.certificate, areaSqm: 10, now: at(5) })).toMatchObject({ ok: false, error: "PROFILE_VIOLATION" });
    for (const areaSqm of [0, -5, 1.5, Number.NaN]) {
      expect(await issueTitle(w.officer, { parcelId: "P2", owner: w.sita.certificate, areaSqm, now: at(5) })).toMatchObject({ ok: false, error: "MALFORMED" });
    }
  });

  it("registry rejects duplicate registration and orphan transfers", async () => {
    const w = await makeWorld();
    expect(await w.registry.append({ title: w.title, evidence: null }, w.ctx())).toMatchObject({ ok: false, error: "DUPLICATE_PARCEL" });
    const { result } = await sell(w);
    expect(result.ok).toBe(true);
    const second = (await executeTransfer({ officer: w.officer, registry: w.registry, evidence: await evidenceFor(w, w.ram, w.mallory, 30), ctx: w.ctx(at(35)) })) as { ok: true; record: TitleRecord };
    const fresh = new Registry();
    expect(await fresh.append(second.record, w.ctx(at(35)))).toMatchObject({ ok: false, error: "UNKNOWN_PARCEL" });
  });

  it("a title signed by a non-officer is rejected", async () => {
    const w = await makeWorld();
    const forged = await issueTitle(w.sita, { parcelId: "P9", owner: w.sita.certificate, areaSqm: 100, now: at(6) });
    expect(forged.ok).toBe(true);
    if (!forged.ok) return;
    expect(await new Registry().append({ title: forged.title, evidence: null }, w.ctx())).toMatchObject({ ok: false, error: "USAGE_NOT_PERMITTED" });
  });
});

describe("transfer happy path", () => {
  it("moves ownership and produces a history any third party can verify", async () => {
    const w = await makeWorld();
    const { result } = await sell(w);
    expect(result.ok).toBe(true);
    expect(w.registry.head(PARCEL)?.title.body).toMatchObject({ seq: 1, ownerSerial: w.ram.certificate.body.serial });
    expect(await verifyHistory(w.registry.history(PARCEL), w.ctx(at(30)))).toEqual({ ok: true });
  });

  it("supports a chain of several transfers", async () => {
    const w = await makeWorld();
    expect((await sell(w, 12)).result.ok).toBe(true);
    const back = await evidenceFor(w, w.ram, w.mallory, 30);
    expect((await executeTransfer({ officer: w.officer, registry: w.registry, evidence: back, ctx: w.ctx(at(35)) })).ok).toBe(true);
    expect(w.registry.history(PARCEL)).toHaveLength(3);
    expect(await verifyHistory(w.registry.history(PARCEL), w.ctx(at(40)))).toEqual({ ok: true });
  });

  it("history() returns a copy; mutating it does not affect the registry", async () => {
    const w = await makeWorld();
    (w.registry.history(PARCEL) as TitleRecord[]).pop();
    expect(w.registry.history(PARCEL)).toHaveLength(1);
    expect(w.registry.history("unknown")).toEqual([]);
  });
});

describe("attacks on transfers", () => {
  it("double sale: a second sale of the old title version is rejected", async () => {
    const w = await makeWorld();
    const stale = await evidenceFor(w, w.sita, w.mallory, 12); // prepared against seq 0
    expect((await sell(w, 14)).result.ok).toBe(true); // Sita legitimately sells to Ram first
    const result = await executeTransfer({ officer: w.officer, registry: w.registry, evidence: stale, ctx: w.ctx(at(30)) });
    expect(result).toMatchObject({ ok: false, error: "HEAD_MISMATCH" });
  });

  it("replaying executed evidence is rejected", async () => {
    const w = await makeWorld();
    const { evidence } = await sell(w);
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(40)) })).toMatchObject({ ok: false, error: "HEAD_MISMATCH" });
  });

  it("reusing a nonce on another parcel is rejected", async () => {
    const w = await makeWorld();
    const { evidence } = await sell(w);
    // second parcel owned by Sita; she (maliciously or by bug) signs an intent re-using the old nonce
    const second = await issueTitle(w.officer, { parcelId: "P2", owner: w.sita.certificate, areaSqm: 50, now: at(20) });
    if (!second.ok) throw new Error("setup");
    await w.registry.append({ title: second.title, evidence: null }, w.ctx(at(21)));
    const body = { ...(await createTransferIntent(w.sita, { title: second.title, buyer: w.mallory.certificate, now: at(22) })).body, nonce: evidence.intent.body.nonce };
    const intent = { body, signature: await signMessage(w.sita.privateKey, "transfer-intent", canonicalize(body)) };
    const acceptance = await acceptTransferIntent(w.mallory, intent, at(23));
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence: { intent, acceptance }, ctx: w.ctx(at(24)) })).toMatchObject({ ok: false, error: "NONCE_REUSED" });
  });

  it("a non-owner cannot sell", async () => {
    const w = await makeWorld();
    const evidence = await evidenceFor(w, w.mallory, w.mallory, 12);
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(20)) })).toMatchObject({ ok: false, error: "NOT_OWNER" });
  });

  it("an expired offer is rejected", async () => {
    const w = await makeWorld();
    const head = w.registry.head(PARCEL) as TitleRecord;
    const intent = await createTransferIntent(w.sita, { title: head.title, buyer: w.ram.certificate, now: at(12), ttlMinutes: 5 });
    const acceptance = await acceptTransferIntent(w.ram, intent, at(13));
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence: { intent, acceptance }, ctx: w.ctx(at(60)) })).toMatchObject({ ok: false, error: "INTENT_EXPIRED" });
  });

  it("the buyer must really accept: wrong signer, wrong intent, tampered terms", async () => {
    const w = await makeWorld();
    const head = w.registry.head(PARCEL) as TitleRecord;
    const intent = await createTransferIntent(w.sita, { title: head.title, buyer: w.ram.certificate, now: at(12) });
    const run = (evidence: TransferEvidence) => executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(20)) });

    const bySomeoneElse = await acceptTransferIntent(w.mallory, intent, at(13));
    bySomeoneElse.body.buyerSerial = w.ram.certificate.body.serial; // Mallory pretends to be Ram
    expect(await run({ intent, acceptance: bySomeoneElse })).toMatchObject({ ok: false, error: "BAD_SIGNATURE" });

    const other = await createTransferIntent(w.sita, { title: head.title, buyer: w.ram.certificate, now: at(12) });
    const wrongIntent = await acceptTransferIntent(w.ram, other, at(13));
    expect(await run({ intent, acceptance: wrongIntent })).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });

    const changed = clone(intent);
    changed.body.buyerSerial = w.mallory.certificate.body.serial; // seller's signature no longer matches
    expect(await run({ intent: changed, acceptance: await acceptTransferIntent(w.mallory, changed, at(13)) })).toMatchObject({ ok: false, error: "BAD_SIGNATURE" });
  });

  it("unknown parcel and unknown buyer are rejected", async () => {
    const w = await makeWorld();
    const evidence = await evidenceFor(w);
    const ghost = clone(evidence);
    ghost.intent.body.parcelId = "NOPE";
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence: ghost, ctx: w.ctx(at(20)) })).toMatchObject({ error: "UNKNOWN_PARCEL" });
    const nobody = clone(evidence);
    nobody.intent.body.buyerSerial = "a".repeat(32);
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence: nobody, ctx: w.ctx(at(20)) })).toMatchObject({ error: "UNKNOWN_CERT" });
  });

  it("revoked parties and revoked or non-officer signers are rejected", async () => {
    const w = await makeWorld();
    const evidence = await evidenceFor(w);
    w.ca.revoke(w.sita.certificate.body.serial, "keyCompromise", at(13));
    const crl = await w.ca.publishCrl(at(14));
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(15), crl) })).toMatchObject({ ok: false, error: "REVOKED" });

    const w2 = await makeWorld();
    const ev2 = await evidenceFor(w2);
    expect(await executeTransfer({ officer: w2.mallory, registry: w2.registry, evidence: ev2, ctx: w2.ctx(at(15)) })).toMatchObject({ ok: false, error: "USAGE_NOT_PERMITTED" });
    w2.ca.revoke(w2.officer.certificate.body.serial, "keyCompromise", at(13));
    const crl2 = await w2.ca.publishCrl(at(14));
    expect(await executeTransfer({ officer: w2.officer, registry: w2.registry, evidence: ev2, ctx: w2.ctx(at(15), crl2) })).toMatchObject({ ok: false, error: "REVOKED" });
  });

  it("a back-dated offer cannot dodge a revocation (certificates are checked as of execution time)", async () => {
    const w = await makeWorld();
    w.ca.revoke(w.sita.certificate.body.serial, "keyCompromise", at(13)); // key stolen at minute 13
    const crl = await w.ca.publishCrl(at(14));
    // the thief signs an offer claiming it was made at minute 12, before the revocation
    const evidence = await evidenceFor(w, w.sita, w.ram, 12);
    expect(evidence.intent.body.issuedAt).toBe(at(12).toISOString());
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(20), crl) })).toMatchObject({ ok: false, error: "REVOKED" });
  });

  it("the registry rejects back-dated and future-dated titles", async () => {
    const w = await makeWorld();
    for (const minute of [-100, 100]) {
      const t = await issueTitle(w.officer, { parcelId: "P3", owner: w.sita.certificate, areaSqm: 10, now: at(10 + minute) });
      if (!t.ok) throw new Error("setup");
      expect(await new Registry().append({ title: t.title, evidence: null }, w.ctx(at(10)))).toMatchObject({ ok: false, error: "CLOCK_SKEW" });
    }
  });

  it("concurrent double sale: exactly one of two competing transfers wins", async () => {
    const w = await makeWorld();
    const toRam = await evidenceFor(w, w.sita, w.ram, 12);
    const toMallory = await evidenceFor(w, w.sita, w.mallory, 12);
    const ctx = w.ctx(at(20));
    const results = await Promise.all([
      executeTransfer({ officer: w.officer, registry: w.registry, evidence: toRam, ctx }),
      executeTransfer({ officer: w.officer, registry: w.registry, evidence: toMallory, ctx }),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.find((r) => !r.ok)).toMatchObject({ error: "HEAD_MISMATCH" });
    expect(w.registry.history(PARCEL)).toHaveLength(2);
    expect(await verifyHistory(w.registry.history(PARCEL), ctx)).toEqual({ ok: true });
  });

  it("concurrent registration of the same parcel: one wins", async () => {
    const w = await makeWorld();
    const reg = new Registry();
    const ctx = w.ctx();
    const results = await Promise.all([
      reg.append({ title: w.title, evidence: null }, ctx),
      reg.append({ title: w.title, evidence: null }, ctx),
    ]);
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(reg.history(PARCEL)).toHaveLength(1);
  });
});

describe("third-party history verification", () => {
  it("an empty history is not valid", async () => {
    const w = await makeWorld();
    expect(await verifyHistory([], w.ctx())).toMatchObject({ ok: false, error: "UNKNOWN_PARCEL" });
  });

  it("malformed input is reported as MALFORMED and never throws", async () => {
    const w = await makeWorld();
    await sell(w);
    const good = w.registry.history(PARCEL);
    const bad: unknown[] = [
      null, 42, "x", {}, { title: null, evidence: null }, { title: {}, evidence: null },
      { title: { body: {}, signature: "x" }, evidence: null },
      { ...clone(good[0]), evidence: 5 },
      { ...clone(good[1]), evidence: { intent: {}, acceptance: {} } },
    ];
    for (const record of bad) {
      expect(await verifyHistory([record as TitleRecord], w.ctx())).toMatchObject({ ok: false, error: "MALFORMED" });
      expect(await w.registry.append(record as TitleRecord, w.ctx())).toMatchObject({ ok: false, error: "MALFORMED" });
    }
    const ghost = { intent: {}, acceptance: {} } as unknown as TransferEvidence;
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence: ghost, ctx: w.ctx() })).toMatchObject({ error: "MALFORMED" });
    const withBadTitle = clone(good[1]) as TitleRecord;
    withBadTitle.title.body.areaSqm = -1;
    expect(await verifyHistory([good[0] as TitleRecord, withBadTitle], w.ctx(at(30)))).toMatchObject({ error: "MALFORMED" });
  });

  it("detects tampering with any field of any record", async () => {
    const w = await makeWorld();
    await sell(w);
    const pristine = w.registry.history(PARCEL);
    const mutations: Array<[string, (h: TitleRecord[]) => void]> = [
      ["area", (h) => { h[1]!.title.body.areaSqm = 99999; }],
      ["owner", (h) => { h[1]!.title.body.ownerSerial = w.mallory.certificate.body.serial; }],
      ["first area", (h) => { h[0]!.title.body.areaSqm = 1; }],
      ["prevHash", (h) => { h[1]!.title.body.prevHash = "0".repeat(64); }],
      ["seq", (h) => { h[1]!.title.body.seq = 5; }],
      ["signature", (h) => { h[1]!.title.signature = h[0]!.title.signature; }],
      ["evidence removed", (h) => { h[1]!.evidence = null; }],
      ["evidence swapped", (h) => { h[1]!.evidence!.intent.body.nonce = "1".repeat(32); }],
      ["acceptance forged", (h) => { h[1]!.evidence!.acceptance.signature = h[1]!.evidence!.intent.signature; }],
      ["genesis with evidence", (h) => { h[0]!.evidence = h[1]!.evidence; }],
      ["record reordered", (h) => { h.reverse(); }],
      ["record dropped", (h) => { h.shift(); }],
    ];
    for (const [name, mutate] of mutations) {
      const copy = clone(pristine) as TitleRecord[];
      mutate(copy);
      const result = await verifyHistory(copy, w.ctx(at(30)));
      expect(result.ok, `mutation "${name}" must be detected`).toBe(false);
    }
  });

  it("old transfers stay valid after a later revocation of a party (as-of-issuance semantics)", async () => {
    const w = await makeWorld();
    await sell(w, 12);
    w.ca.revoke(w.sita.certificate.body.serial, "affiliationChanged", at(60));
    const crl = await w.ca.publishCrl(at(61));
    expect(await verifyHistory(w.registry.history(PARCEL), w.ctx(at(62), crl))).toEqual({ ok: true });
  });

  it("history fails if the officer was revoked before signing", async () => {
    const w = await makeWorld();
    await sell(w, 12);
    w.ca.revoke(w.officer.certificate.body.serial, "keyCompromise", at(1));
    const crl = await w.ca.publishCrl(at(61));
    expect(await verifyHistory(w.registry.history(PARCEL), w.ctx(at(62), crl))).toMatchObject({ ok: false, error: "REVOKED" });
  });

  it("hashBody is stable and sensitive to every change", async () => {
    const w = await makeWorld();
    const base = await hashBody(w.title.body);
    expect(await hashBody(clone(w.title.body))).toBe(base);
    expect(await hashBody({ ...w.title.body, areaSqm: w.title.body.areaSqm + 1 })).not.toBe(base);
  });
});

describe("a malicious officer: valid signatures but invalid links", () => {
  const resign = async (w: World, body: TitleBody) => ({
    body,
    signature: await signMessage(w.officer.privateKey, "title", canonicalize(body)),
  });

  /** Builds a validly signed record from the given evidence, bypassing every executeTransfer pre-check. */
  async function forgedRecord(w: World, prev: TitleRecord, evidence: TransferEvidence, owner: Identity, when: Date): Promise<TitleRecord> {
    const body: TitleBody = {
      v: 1,
      parcelId: prev.title.body.parcelId,
      seq: prev.title.body.seq + 1,
      prevHash: await hashBody(prev.title.body),
      ownerSerial: owner.certificate.body.serial,
      ownerId: owner.certificate.body.subject.id,
      areaSqm: prev.title.body.areaSqm,
      issuedAt: when.toISOString(),
      issuerSerial: w.officer.certificate.body.serial,
      evidenceHash: await hashBody({ intent: evidence.intent.body, acceptance: evidence.acceptance.body }),
    };
    return { title: await resign(w, body), evidence };
  }

  async function twoRecordHistory() {
    const w = await makeWorld();
    await sell(w);
    return { w, history: clone(w.registry.history(PARCEL)) as TitleRecord[] };
  }

  it("cannot splice in a different, validly signed first record", async () => {
    const { w, history } = await twoRecordHistory();
    history[0] = { title: await resign(w, { ...history[0]!.title.body, areaSqm: 5000 }), evidence: null };
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "BROKEN_CHAIN" });
  });

  it("cannot skip or repeat sequence numbers", async () => {
    const { w, history } = await twoRecordHistory();
    history[1]!.title = await resign(w, { ...history[1]!.title.body, seq: 5 });
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "BROKEN_CHAIN" });
  });

  it("cannot move a record to another parcel", async () => {
    const { w, history } = await twoRecordHistory();
    history[1]!.title = await resign(w, { ...history[1]!.title.body, parcelId: "OTHER" });
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "BROKEN_CHAIN" });
  });

  it("cannot claim consent that does not match the recorded evidence", async () => {
    const { w, history } = await twoRecordHistory();
    history[1]!.title = await resign(w, { ...history[1]!.title.body, evidenceHash: "0".repeat(64) });
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "BAD_EVIDENCE" });
  });

  it("cannot hand the parcel to someone who did not accept", async () => {
    const { w, history } = await twoRecordHistory();
    history[1]!.title = await resign(w, {
      ...history[1]!.title.body,
      ownerSerial: w.mallory.certificate.body.serial,
      ownerId: w.mallory.certificate.body.subject.id,
    });
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });
  });

  it("cannot reuse consent that was given for an older title version", async () => {
    const { w, history } = await twoRecordHistory();
    const body = history[1]!.title.body;
    const stale = clone(history[1]!.evidence!) as TransferEvidence;
    stale.intent.body.titleHash = "1".repeat(64); // consent for a different version
    history[1] = {
      title: await resign(w, { ...body, evidenceHash: await hashBody({ intent: stale.intent.body, acceptance: stale.acceptance.body }) }),
      evidence: stale,
    };
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });
  });

  it("cannot execute a transfer after the offer expired", async () => {
    const { w, history } = await twoRecordHistory();
    const body = history[1]!.title.body;
    history[1]!.title = await resign(w, { ...body, issuedAt: at(500).toISOString() });
    expect(await verifyHistory(history, w.ctx(at(600)))).toMatchObject({ ok: false, error: "INTENT_EXPIRED" });
  });

  it("cannot let a different buyer accept an offer addressed to someone else", async () => {
    const { w, history } = await twoRecordHistory();
    const intent = await createTransferIntent(w.sita, { title: history[0]!.title, buyer: w.ram.certificate, now: at(12) });
    const acceptance = await acceptTransferIntent(w.mallory, intent, at(13)); // offer was made to Ram
    history[1] = await forgedRecord(w, history[0]!, { intent, acceptance }, w.mallory, at(17));
    expect(await verifyHistory(history, w.ctx(at(30)))).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });
  });

  it("cannot execute an offer signed by someone who is not the current owner", async () => {
    const w = await makeWorld();
    const head = w.registry.head(PARCEL) as TitleRecord;
    const intent = await createTransferIntent(w.mallory, { title: head.title, buyer: w.ram.certificate, now: at(12) });
    const acceptance = await acceptTransferIntent(w.ram, intent, at(13));
    const record = await forgedRecord(w, head, { intent, acceptance }, w.ram, at(17));
    expect(await w.registry.append(record, w.ctx(at(17)))).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });
  });

  it("cannot resurrect an old offer after the parcel has returned to the seller", async () => {
    const w = await makeWorld();
    const oldIntent = await createTransferIntent(w.sita, { title: w.title, buyer: w.mallory.certificate, now: at(11) });
    const oldAcceptance = await acceptTransferIntent(w.mallory, oldIntent, at(12));
    expect((await sell(w, 14)).result.ok).toBe(true); // Sita sells to Ram
    const back = await evidenceFor(w, w.ram, w.sita, 25); // Ram sells back to Sita
    expect((await executeTransfer({ officer: w.officer, registry: w.registry, evidence: back, ctx: w.ctx(at(30)) })).ok).toBe(true);

    const evidence = { intent: oldIntent, acceptance: oldAcceptance };
    const record = await forgedRecord(w, w.registry.head(PARCEL) as TitleRecord, evidence, w.mallory, at(35));
    expect(await w.registry.append(record, w.ctx(at(35)))).toMatchObject({ ok: false, error: "INTENT_MISMATCH" });
    expect(await executeTransfer({ officer: w.officer, registry: w.registry, evidence, ctx: w.ctx(at(35)) })).toMatchObject({ ok: false, error: "HEAD_MISMATCH" });
  });
});
