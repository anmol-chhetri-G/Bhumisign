import { describe, expect, it } from "vitest";
import { utf8, fromUtf8 } from "../src/crypto/bytes";
import { canonicalize } from "../src/crypto/canonical";
import { hybridDecrypt, hybridEncrypt } from "../src/crypto/hybrid";
import { exportPublicKey, generateEcdhKeyPair, generateSigningKeyPair, signMessage, verifyMessage } from "../src/crypto/primitives";
import {
  CertificateAuthority,
  createEnrollmentRequest,
  enrollIdentity,
  enrollProtectedIdentity,
  unlockProtectedIdentity,
} from "../src/pki/ca";
import type { Certificate, Crl, EnrollmentRequest } from "../src/pki/types";
import { verifyCertificate } from "../src/pki/verify";
import { T0, at, makeWorld } from "./helpers";

const DAY = 86_400_000;
const clone = <T>(x: T): T => structuredClone(x);

describe("certificate issuance and verification", () => {
  it("verifies every role under the pinned root", async () => {
    const w = await makeWorld();
    for (const id of [w.officer, w.sita, w.ram, w.bank]) {
      expect(await verifyCertificate(id.certificate, w.ctx())).toEqual({ ok: true });
    }
  });

  it("verifies the root itself and rejects a root that is not the pinned anchor", async () => {
    const w = await makeWorld();
    expect(await verifyCertificate(w.ca.certificate, w.ctx())).toEqual({ ok: true });
    const other = await CertificateAuthority.createRoot("Evil Root", T0);
    expect(await verifyCertificate(other.certificate, w.ctx())).toMatchObject({ ok: false, error: "ISSUER_MISMATCH" });
  });

  it("detects a substituted anchor that reuses the real root's serial", async () => {
    const w = await makeWorld();
    const keys = await generateSigningKeyPair(true);
    const body = { ...clone(w.ca.certificate.body), signKey: await exportPublicKey(keys.publicKey) };
    const fake: Certificate = { body, signature: await signMessage(keys.privateKey, "cert", canonicalize(body)) };
    const result = await verifyCertificate(w.sita.certificate, { ...w.ctx(), anchor: fake });
    expect(result).toMatchObject({ ok: false, error: "BAD_SIGNATURE" });
  });

  it("rejects certificates with any tampered field", async () => {
    const w = await makeWorld();
    const cert = w.sita.certificate;
    const mutations: Array<(c: Certificate) => void> = [
      (c) => { c.body.subject.name = "Sita Sharma II"; },
      (c) => { c.body.subject.id = "np-9999"; },
      (c) => { c.body.subject.role = "LRO_OFFICER"; },
      (c) => { c.body.usages = [...c.body.usages, "titleSign"]; },
      (c) => { c.body.serial = "0".repeat(32); },
      (c) => { c.body.notAfter = "2099-01-01T00:00:00.000Z"; },
      (c) => { c.body.signKey = w.mallory.certificate.body.signKey; },
      (c) => { c.body.encKey = w.mallory.certificate.body.encKey; },
      (c) => { c.signature = w.mallory.certificate.signature; },
    ];
    for (const mutate of mutations) {
      const copy = clone(cert);
      mutate(copy);
      expect((await verifyCertificate(copy, w.ctx())).ok).toBe(false);
    }
  });

  it("enforces the validity window", async () => {
    const w = await makeWorld();
    const cert = w.sita.certificate;
    expect(await verifyCertificate(cert, w.ctx(at(0)))).toMatchObject({ error: "NOT_YET_VALID" });
    const later = new Date(T0.getTime() + 400 * DAY);
    expect(await verifyCertificate(cert, w.ctx(later))).toMatchObject({ error: "EXPIRED" });
  });

  it("caps leaf validity at the CA certificate's own expiry", async () => {
    const ca = await CertificateAuthority.createRoot("Short CA", T0, 10);
    const id = await enrollIdentity(ca, { id: "x", name: "X", role: "CITIZEN" }, at(1), 365);
    expect(id.certificate.body.notAfter).toBe(ca.certificate.body.notAfter);
  });

  it("enforces key usage and rejects wrong-issuer certificates", async () => {
    const w = await makeWorld();
    expect(await verifyCertificate(w.sita.certificate, w.ctx(), { usage: "titleSign" })).toMatchObject({ error: "USAGE_NOT_PERMITTED" });
    expect(await verifyCertificate(w.officer.certificate, w.ctx(), { usage: "titleSign" })).toEqual({ ok: true });
    const otherCa = await CertificateAuthority.createRoot("Other CA", T0);
    const foreign = await enrollIdentity(otherCa, { id: "f", name: "F", role: "CITIZEN" }, at(1));
    expect(await verifyCertificate(foreign.certificate, w.ctx())).toMatchObject({ error: "ISSUER_MISMATCH" });
  });

  it("returns MALFORMED for garbage input", async () => {
    const w = await makeWorld();
    expect(await verifyCertificate({} as Certificate, w.ctx())).toMatchObject({ error: "MALFORMED" });
    expect(await verifyCertificate(w.sita.certificate, { ...w.ctx(), anchor: {} as Certificate })).toMatchObject({ error: "MALFORMED" });
  });
});

describe("enrollment (proof of possession and role profiles)", () => {
  async function request(role: "CITIZEN" | "LRO_OFFICER" | "ROOT_CA" | "VERIFIER", usages: EnrollmentRequest["usages"], withEnc = true) {
    const signing = await generateSigningKeyPair(true);
    const enc = await generateEcdhKeyPair(true);
    return { signing, req: await createEnrollmentRequest({ id: "u1", name: "U", role }, usages, signing, withEnc ? enc.publicKey : null) };
  }

  it("issues when the request is valid", async () => {
    const w = await makeWorld();
    const { req } = await request("CITIZEN", ["transferSign", "dataEncrypt"]);
    expect((await w.ca.issue(req, at(3))).ok).toBe(true);
  });

  it("rejects a request for someone else's public key (no proof of possession)", async () => {
    const w = await makeWorld();
    const { req } = await request("CITIZEN", ["transferSign", "dataEncrypt"]);
    const stolen = { ...req, signKey: w.sita.certificate.body.signKey };
    expect(await w.ca.issue(stolen, at(3))).toMatchObject({ ok: false, error: "BAD_POP" });
  });

  it("rejects a request edited after signing (role escalation)", async () => {
    const w = await makeWorld();
    const { req } = await request("CITIZEN", ["transferSign", "dataEncrypt"]);
    const escalated = { ...req, subject: { ...req.subject, role: "LRO_OFFICER" as const }, usages: ["titleSign", "dataEncrypt"] as EnrollmentRequest["usages"] };
    expect(await w.ca.issue(escalated, at(3))).toMatchObject({ ok: false, error: "BAD_POP" });
  });

  it("rejects profile violations even with a valid signature", async () => {
    const w = await makeWorld();
    const cases = [
      await request("CITIZEN", ["transferSign", "dataEncrypt", "titleSign"]),
      await request("CITIZEN", ["transferSign"], false),
      await request("CITIZEN", ["transferSign", "dataEncrypt"], false),
      await request("ROOT_CA", ["certSign", "crlSign"], false),
      await request("VERIFIER", ["dataEncrypt", "dataEncrypt"]),
    ];
    for (const { req } of cases) {
      expect(await w.ca.issue(req, at(3))).toMatchObject({ ok: false, error: "PROFILE_VIOLATION" });
    }
  });

  it("rejects malformed requests", async () => {
    const w = await makeWorld();
    const { req } = await request("CITIZEN", ["transferSign", "dataEncrypt"]);
    expect(await w.ca.issue({ ...req, signKey: "AAAA" }, at(3))).toMatchObject({ error: "MALFORMED" });
    expect(await w.ca.issue({ ...req, popSignature: undefined } as unknown as EnrollmentRequest, at(3))).toMatchObject({ error: "MALFORMED" });
  });

  it("refuses to issue once the CA certificate has expired", async () => {
    const ca = await CertificateAuthority.createRoot("Short CA", T0, 1);
    const { req } = await request("CITIZEN", ["transferSign", "dataEncrypt"]);
    expect(await ca.issue(req, new Date(T0.getTime() + 2 * DAY))).toMatchObject({ ok: false, error: "EXPIRED" });
  });

  it("enrollIdentity throws on failure", async () => {
    const ca = await CertificateAuthority.createRoot("CA", T0, 1);
    await expect(enrollIdentity(ca, { id: "x", name: "X", role: "CITIZEN" }, new Date(T0.getTime() + 2 * DAY))).rejects.toThrow("enrollment failed");
  });

  it("enrollProtectedIdentity wraps keys and unlockProtectedIdentity restores non-extractable keys", async () => {
    const ca = await CertificateAuthority.createRoot("CA", T0);
    const pass = "correct horse battery staple";
    const protectedId = await enrollProtectedIdentity(ca, { id: "p1", name: "Protected", role: "CITIZEN" }, pass, at(1), 365, 1000);
    expect(protectedId.wrappedSigningKey.label).toBe(protectedId.certificate.body.serial);
    expect(protectedId.wrappedEncryptionKey).not.toBeNull();

    await expect(unlockProtectedIdentity(protectedId, "wrong passphrase!", 1000)).rejects.toThrow("wrong passphrase");

    const unlocked = await unlockProtectedIdentity(protectedId, pass, 1000);
    await expect(crypto.subtle.exportKey("pkcs8", unlocked.privateKey)).rejects.toThrow();
    expect(unlocked.encryption).not.toBeNull();
    if (unlocked.encryption) {
      await expect(crypto.subtle.exportKey("pkcs8", unlocked.encryption.privateKey)).rejects.toThrow();
      const env = await hybridEncrypt(unlocked.encryption.publicKey, utf8("secret"), utf8("aad"));
      expect(fromUtf8(await hybridDecrypt(unlocked.encryption, env, utf8("aad")))).toBe("secret");
    }

    const sig = await signMessage(unlocked.privateKey, "transfer-intent", "payload");
    expect(await verifyMessage(unlocked.signing.publicKey, "transfer-intent", "payload", sig)).toBe(true);

    // Covers the branch where no encryption key is wrapped
    const signOnly = await unlockProtectedIdentity({ ...protectedId, wrappedEncryptionKey: null }, pass, 1000);
    expect(signOnly.encryption).toBeNull();
  });
});

describe("revocation (CRL)", () => {
  it("rejects a revoked certificate once a fresh CRL is used", async () => {
    const w = await makeWorld();
    expect(w.ca.revoke(w.sita.certificate.body.serial, "keyCompromise", at(20))).toBe(true);
    const crl = await w.ca.publishCrl(at(21));
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), crl))).toMatchObject({ ok: false, error: "REVOKED", detail: "keyCompromise" });
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), w.crl))).toEqual({ ok: true }); // stale-but-valid CRL: documented limit
  });

  it("evaluates revocation as of the requested time", async () => {
    const w = await makeWorld();
    w.ca.revoke(w.sita.certificate.body.serial, "superseded", at(30));
    const crl = await w.ca.publishCrl(at(31));
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(32), crl), { at: at(29) })).toEqual({ ok: true });
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(32), crl), { at: at(30) })).toMatchObject({ error: "REVOKED" });
  });

  it("fails closed: missing and stale CRLs are errors unless explicitly waived", async () => {
    const w = await makeWorld();
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(10), null))).toMatchObject({ error: "CRL_MISSING" });
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(10), null), { requireCrl: false })).toEqual({ ok: true });
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(60 * 24 + 100)))).toMatchObject({ error: "CRL_STALE" });
  });

  it("rejects forged, edited and foreign CRLs", async () => {
    const w = await makeWorld();
    w.ca.revoke(w.sita.certificate.body.serial, "keyCompromise", at(20));
    const real = await w.ca.publishCrl(at(21));
    const edited: Crl = clone(real);
    edited.body.revoked = []; // attacker removes the revocation
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), edited))).toMatchObject({ error: "CRL_INVALID" });
    const other = await CertificateAuthority.createRoot("Other", T0);
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), await other.publishCrl(at(21))))).toMatchObject({ error: "CRL_INVALID" });
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), {} as Crl))).toMatchObject({ error: "CRL_INVALID" });
    const future = await w.ca.publishCrl(at(500));
    expect(await verifyCertificate(w.sita.certificate, w.ctx(at(22), future))).toMatchObject({ error: "CRL_INVALID" });
  });

  it("cannot revoke the root or an unknown serial; CRL numbers increase", async () => {
    const w = await makeWorld();
    expect(w.ca.revoke(w.ca.certificate.body.serial, "unspecified", at(5))).toBe(false);
    expect(w.ca.revoke("f".repeat(32), "unspecified", at(5))).toBe(false);
    const a = await w.ca.publishCrl(at(5));
    const b = await w.ca.publishCrl(at(6));
    expect(b.body.crlNumber).toBe(a.body.crlNumber + 1);
  });
});
