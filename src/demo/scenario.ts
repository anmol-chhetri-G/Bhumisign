import { utf8, fromUtf8 } from "../crypto/bytes";
import { hybridDecrypt, hybridEncrypt } from "../crypto/hybrid";
import {
  CertificateAuthority,
  enrollIdentity,
  enrollProtectedIdentity,
  unlockProtectedIdentity,
} from "../pki/ca";
import type { Crl, TrustContext } from "../pki/types";
import { verifyCertificate } from "../pki/verify";
import { Registry } from "../land/registry";
import { issueTitle } from "../land/title";
import { acceptTransferIntent, createTransferIntent, executeTransfer } from "../land/transfer";
import { verifyHistory } from "../land/verify";
import type { TitleRecord } from "../land/types";

export interface LogEntry {
  step: string;
  expected: "accept" | "reject";
  outcome: "accept" | "reject";
  detail: string;
  pass: boolean; // outcome matched expectation
}

/** Runs the whole story: honest flow first, then each attack the design is meant to stop. */
export async function runScenario(start: Date = new Date()): Promise<LogEntry[]> {
  const log: LogEntry[] = [];
  let clock = start.getTime();
  const tick = (minutes = 1) => new Date((clock += minutes * 60_000));
  const record = (step: string, expected: "accept" | "reject", result: { ok: boolean; error?: string; detail?: string }) => {
    const outcome = result.ok ? "accept" : "reject";
    log.push({ step, expected, outcome, detail: result.ok ? "ok" : `${result.error}${result.detail ? `: ${result.detail}` : ""}`, pass: outcome === expected });
  };

  // Phase 1: set-up and enrolment (Sita enrolls directly into a password-protected keystore)
  const ca = await CertificateAuthority.createRoot("Nepal Land Registry Root CA (demo)", tick());
  const officer = await enrollIdentity(ca, { id: "lro-007", name: "LRO Officer", role: "LRO_OFFICER" }, tick());
  const sitaPass = "Sita@SecretPassphrase2026!";
  const sitaProtected = await enrollProtectedIdentity(
    ca,
    { id: "np-1001", name: "Sita Sharma", role: "CITIZEN" },
    sitaPass,
    tick(),
  );
  const ram = await enrollIdentity(ca, { id: "np-1002", name: "Ram Thapa", role: "CITIZEN" }, tick());
  const mallory = await enrollIdentity(ca, { id: "np-6666", name: "Mallory", role: "CITIZEN" }, tick());
  const bank = await enrollIdentity(ca, { id: "bank-01", name: "Demo Bank", role: "VERIFIER" }, tick());
  let crl: Crl = await ca.publishCrl(tick());
  const ctx = (): TrustContext => ({ anchor: ca.certificate, crl, now: new Date(clock), directory: ca.directory });
  record("Enrolment: officer, citizens and bank certified", "accept", await verifyCertificate(bank.certificate, ctx(), { usage: "dataEncrypt" }));

  // Key storage: wrong passphrase is rejected; right passphrase restores a non-extractable key
  const wrongPassResult = await unlockProtectedIdentity(sitaProtected, "wrong-passphrase").then(
    () => ({ ok: true }),
    () => ({ ok: false, error: "BAD_PASSPHRASE", detail: "wrong passphrase or corrupted key blob" }),
  );
  record("Keystore: Incorrect passphrase fails to unwrap key", "reject", wrongPassResult);
  const sita = await unlockProtectedIdentity(sitaProtected, sitaPass);
  const nonExtractable = await globalThis.crypto.subtle
    .exportKey("pkcs8", sita.privateKey)
    .then(() => false, () => true);
  record("Keystore: Sita unlocks non-extractable key with passphrase", "accept", { ok: nonExtractable });

  // Phase 2: issue the first title
  const registry = new Registry();
  const issued = await issueTitle(officer, { parcelId: "KTM-W10-K1234", owner: sita.certificate, areaSqm: 2400, now: tick() });
  if (!issued.ok) throw new Error("issuance failed");
  record("Issue title to Sita", "accept", await registry.append({ title: issued.title, evidence: null }, ctx()));

  // Phase 3: transfer Sita -> Ram (Sita signs using her unlocked non-extractable key)
  const intent = await createTransferIntent(sita, { title: issued.title, buyer: ram.certificate, now: tick() });
  const acceptance = await acceptTransferIntent(ram, intent, tick());
  const evidence = { intent, acceptance };
  const moved = await executeTransfer({ officer, registry, evidence, ctx: ctx() });
  record("Transfer Sita to Ram (both signed, LRO executes)", "accept", moved);

  // Phase 4: third-party verification
  record("Bank verifies the full history", "accept", await verifyHistory(registry.history("KTM-W10-K1234"), ctx()));

  // Attacks
  tick();
  const staleIntent = await createTransferIntent(sita, { title: issued.title, buyer: mallory.certificate, now: tick() });
  const staleAccept = await acceptTransferIntent(mallory, staleIntent, tick());
  record("Double sale: Sita sells the old title version again", "reject",
    await executeTransfer({ officer, registry, evidence: { intent: staleIntent, acceptance: staleAccept }, ctx: ctx() }));

  record("Replay of the already executed transfer", "reject", await executeTransfer({ officer, registry, evidence, ctx: ctx() }));

  const head = registry.head("KTM-W10-K1234") as TitleRecord;
  const forgedIntent = await createTransferIntent(mallory, { title: head.title, buyer: mallory.certificate, now: tick() });
  const forgedAccept = await acceptTransferIntent(mallory, forgedIntent, tick());
  record("Mallory sells land she does not own", "reject",
    await executeTransfer({ officer, registry, evidence: { intent: forgedIntent, acceptance: forgedAccept }, ctx: ctx() }));

  const tampered = structuredClone(registry.history("KTM-W10-K1234")) as TitleRecord[];
  const last = tampered[tampered.length - 1] as TitleRecord;
  last.title.body.areaSqm = 24000;
  record("Bank detects a tampered area in the history", "reject", await verifyHistory(tampered, ctx()));

  const ramIntent = await createTransferIntent(ram, { title: head.title, buyer: mallory.certificate, now: tick() });
  const malloryAccept = await acceptTransferIntent(mallory, ramIntent, tick());
  record("A citizen certificate cannot act as LRO officer", "reject",
    await executeTransfer({ officer: mallory, registry, evidence: { intent: ramIntent, acceptance: malloryAccept }, ctx: ctx() }));

  ca.revoke(mallory.certificate.body.serial, "keyCompromise", tick());
  crl = await ca.publishCrl(tick());
  record("Revoked certificate is rejected", "reject", await verifyCertificate(mallory.certificate, ctx(), { usage: "transferSign" }));

  // Confidential attachment (sale deed) for the bank only
  if (!bank.encryption || !mallory.encryption) throw new Error("missing encryption keys");
  const aad = utf8("deed|KTM-W10-K1234");
  const envelope = await hybridEncrypt(bank.encryption.publicKey, utf8("sale deed contents"), aad);
  const opened = await hybridDecrypt(bank.encryption, envelope, aad).then((b) => fromUtf8(b) === "sale deed contents", () => false);
  record("Bank decrypts the sale deed", "accept", { ok: opened });
  const stolen = await hybridDecrypt(mallory.encryption, envelope, aad).then(() => true, () => false);
  record("Mallory cannot decrypt the sale deed", "reject", { ok: stolen });

  return log;
}
