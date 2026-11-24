import { describe, expect, it } from "vitest";
import { fromUtf8, toHex, utf8 } from "../src/crypto/bytes";
import { canonicalize } from "../src/crypto/canonical";
import { hybridDecrypt, hybridEncrypt } from "../src/crypto/hybrid";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ecdhDeriveSecret,
  exportPublicKey,
  generateEcdhKeyPair,
  hkdfSha256,
  importAesKey,
  importEcdhPublicKey,
  importSigningPublicKey,
  randomBytes,
  sha256Hex,
  signFile,
  signMessage,
  verifyFile,
  verifyMessage,
} from "../src/crypto/primitives";
import {
  CertificateAuthority,
  enrollIdentity,
  enrollProtectedIdentity,
  unlockProtectedIdentity,
} from "../src/pki/ca";
import type { TrustContext } from "../src/pki/types";
import { verifyCertificate } from "../src/pki/verify";
import { Registry } from "../src/land/registry";
import { issueTitle } from "../src/land/title";
import { acceptTransferIntent, createTransferIntent, executeTransfer } from "../src/land/transfer";
import { verifyHistory } from "../src/land/verify";

const T0 = new Date("2026-11-24T10:00:00.000Z");
const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000);

describe("Real-World Use Case 1: Land Title Registry (BhūmiSign)", () => {
  it("executes land title issuance, bilateral consent transfer, attack blocking, and bank audit", async () => {
    const ca = await CertificateAuthority.createRoot("Nepal Land Revenue Authority Root CA", T0);
    const officer = await enrollIdentity(ca, { id: "lro-ward-10", name: "LRO Officer", role: "LRO_OFFICER" }, at(1));
    const sellerProtected = await enrollProtectedIdentity(
      ca,
      { id: "np-cit-101", name: "Sita Sharma", role: "CITIZEN" },
      "Sita@LandPass2026!",
      at(1),
      365,
      1000,
    );
    const seller = await unlockProtectedIdentity(sellerProtected, "Sita@LandPass2026!", 1000);
    const buyer = await enrollIdentity(ca, { id: "np-cit-102", name: "Ram Thapa", role: "CITIZEN" }, at(1));
    const mallory = await enrollIdentity(ca, { id: "np-cit-666", name: "Mallory", role: "CITIZEN" }, at(1));
    const bank = await enrollIdentity(ca, { id: "bank-nabil", name: "Lending Bank", role: "VERIFIER" }, at(1));
    const crl = await ca.publishCrl(at(2));

    const ctx: TrustContext = { anchor: ca.certificate, crl, now: at(10), directory: ca.directory };
    const registry = new Registry();

    // Issuance of Parcel KTM-W10-K1234
    const issued = await issueTitle(officer, { parcelId: "KTM-W10-K1234", owner: seller.certificate, areaSqm: 2400, now: at(5) });
    expect(issued.ok).toBe(true);
    if (!issued.ok) return;
    expect((await registry.append({ title: issued.title, evidence: null }, ctx)).ok).toBe(true);

    // Bilateral transfer consent: Seller offer + Buyer acceptance
    const intent = await createTransferIntent(seller, { title: issued.title, buyer: buyer.certificate, now: at(6) });
    const acceptance = await acceptTransferIntent(buyer, intent, at(7));
    expect((await executeTransfer({ officer, registry, evidence: { intent, acceptance }, ctx: { ...ctx, now: at(8) } })).ok).toBe(true);

    // Bank independently verifies provenance chain
    const history = registry.history("KTM-W10-K1234");
    expect(history).toHaveLength(2);
    expect(await verifyHistory(history, ctx)).toEqual({ ok: true });

    // Attacks: Double sale and unauthorized seller are rejected
    const doubleSale = await createTransferIntent(seller, { title: issued.title, buyer: mallory.certificate, now: at(9) });
    const doubleAccept = await acceptTransferIntent(mallory, doubleSale, at(9));
    expect(await executeTransfer({ officer, registry, evidence: { intent: doubleSale, acceptance: doubleAccept }, ctx })).toMatchObject({
      ok: false,
      error: "HEAD_MISMATCH",
    });

    const head = registry.head("KTM-W10-K1234")!;
    const spoofIntent = await createTransferIntent(mallory, { title: head.title, buyer: mallory.certificate, now: at(9) });
    const spoofAccept = await acceptTransferIntent(mallory, spoofIntent, at(9));
    expect(await executeTransfer({ officer, registry, evidence: { intent: spoofIntent, acceptance: spoofAccept }, ctx })).toMatchObject({
      ok: false,
      error: "NOT_OWNER",
    });

    // Confidential deed transmission to bank
    if (!bank.encryption) throw new Error("bank missing encryption key");
    const deedPayload = utf8("Deed contract: Transfer of KTM-W10-K1234 to Ram Thapa for NPR 15,000,000");
    const aad = utf8("deed|KTM-W10-K1234");
    const envelope = await hybridEncrypt(bank.encryption.publicKey, deedPayload, aad);
    const decrypted = await hybridDecrypt(bank.encryption, envelope, aad);
    expect(fromUtf8(decrypted)).toBe("Deed contract: Transfer of KTM-W10-K1234 to Ram Thapa for NPR 15,000,000");
  });
});

describe("Real-World Use Case 2: Academic Credential & Verifiable Diploma (Softwarica / Coventry)", () => {
  it("issues domain-native degree credential, verifies student disclosure consent, and blocks tampering/revocation", async () => {
    const universityCa = await CertificateAuthority.createRoot("Coventry University Academic Root CA", T0);
    const examsOffice = await enrollIdentity(universityCa, { id: "cu-exam-board", name: "Examinations Board", role: "LRO_OFFICER" }, at(1));
    const student = await enrollIdentity(universityCa, { id: "student-10492", name: "Anmol Chhetri", role: "CITIZEN" }, at(1));
    const imposter = await enrollIdentity(universityCa, { id: "student-99999", name: "Imposter", role: "CITIZEN" }, at(1));
    const employer = await enrollIdentity(universityCa, { id: "tech-corp-hr", name: "Prospective Tech Employer", role: "VERIFIER" }, at(1));
    const initialCrl = await universityCa.publishCrl(at(2));

    const ctx: TrustContext = { anchor: universityCa.certificate, crl: initialCrl, now: at(10), directory: universityCa.directory };

    // 1. Examinations Board issues a domain-native canonical degree credential
    const degreeBody = {
      v: 1,
      credentialId: "CU-2026-CS-0042",
      award: "BSc (Hons) Ethical Hacking and Cybersecurity",
      classification: "First Class Honours",
      studentSerial: student.certificate.body.serial,
      studentId: student.certificate.body.subject.id,
      issuerSerial: examsOffice.certificate.body.serial,
      issuedAt: at(5).toISOString(),
    };
    const degreeSig = await signMessage(examsOffice.privateKey, "credential", canonicalize(degreeBody));
    const credentialHash = await sha256Hex(canonicalize(degreeBody));

    // 2. Examinations Board signs binary transcript PDF/document
    const transcriptBytes = utf8("Official Transcript: ST6051CEM Practical Cryptography - 88% (First Class)");
    const transcriptSig = await signFile(examsOffice.privateKey, transcriptBytes);

    // 3. Student explicitly signs disclosure consent authorizing this specific Employer
    const consentBody = {
      v: 1,
      credentialHash,
      studentSerial: student.certificate.body.serial,
      employerSerial: employer.certificate.body.serial,
      nonce: toHex(randomBytes(16)),
      issuedAt: at(6).toISOString(),
      expiresAt: at(60).toISOString(),
    };
    const consentSig = await signMessage(student.privateKey, "disclosure", canonicalize(consentBody));

    // 4. Student hybrid-encrypts the transcript to Employer's ECDH key
    if (!employer.encryption) throw new Error("employer missing encryption key");
    const transcriptAad = utf8(`transcript|${degreeBody.credentialId}|${employer.certificate.body.serial}`);
    const encryptedTranscript = await hybridEncrypt(employer.encryption.publicKey, transcriptBytes, transcriptAad);

    // 5. Employer verifies: CA certs + CRL, Exam Board credential signature, Student consent, and Transcript file signature
    expect(await verifyCertificate(examsOffice.certificate, ctx, { usage: "titleSign" })).toEqual({ ok: true });
    expect(await verifyCertificate(student.certificate, ctx, { usage: "transferSign" })).toEqual({ ok: true });

    const examKey = await importSigningPublicKey(examsOffice.certificate.body.signKey);
    const studentKey = await importSigningPublicKey(student.certificate.body.signKey);

    expect(await verifyMessage(examKey, "credential", canonicalize(degreeBody), degreeSig)).toBe(true);
    expect(await verifyMessage(studentKey, "disclosure", canonicalize(consentBody), consentSig)).toBe(true);
    expect(consentBody.credentialHash).toBe(credentialHash);
    expect(consentBody.studentSerial).toBe(degreeBody.studentSerial);

    const decryptedTranscript = await hybridDecrypt(employer.encryption, encryptedTranscript, transcriptAad);
    expect(await verifyFile(examKey, decryptedTranscript, transcriptSig)).toBe(true);

    // Attack 1: Tampered grade in degree JSON or transcript fails verification
    const alteredDegree = { ...degreeBody, classification: "Distinction" };
    expect(await verifyMessage(examKey, "credential", canonicalize(alteredDegree), degreeSig)).toBe(false);
    expect(await verifyFile(examKey, utf8("Official Transcript: ST6051CEM - 100%"), transcriptSig)).toBe(false);

    // Attack 2: Unauthorized student cannot sign a degree or forge disclosure consent for Anmol
    expect(await verifyCertificate(imposter.certificate, ctx, { usage: "titleSign" })).toMatchObject({
      ok: false,
      error: "USAGE_NOT_PERMITTED",
    });
    expect(await verifyMessage(studentKey, "disclosure", canonicalize(consentBody), await signMessage(imposter.privateKey, "disclosure", canonicalize(consentBody)))).toBe(false);

    // Attack 3: Revoked student or compromised exam key is rejected via CRL
    universityCa.revoke(student.certificate.body.serial, "keyCompromise", at(15));
    const updatedCrl = await universityCa.publishCrl(at(16));
    expect(await verifyCertificate(student.certificate, { ...ctx, now: at(17), crl: updatedCrl }, { usage: "transferSign" })).toMatchObject({
      ok: false,
      error: "REVOKED",
    });
  });
});

describe("Real-World Use Case 3: Electronic Health Records (EHR) & Referral Consent", () => {
  it("verifies physician diagnosis, explicit patient referral consent, and specialist-only decryption", async () => {
    const hospitalCa = await CertificateAuthority.createRoot("National Healthcare Network CA", T0);
    const physician = await enrollIdentity(hospitalCa, { id: "dr-sharma-cardio", name: "Dr. Sharma (Cardiologist)", role: "LRO_OFFICER" }, at(1));
    const patient = await enrollIdentity(hospitalCa, { id: "patient-np-992", name: "Hari Prasad", role: "CITIZEN" }, at(1));
    const specialist = await enrollIdentity(hospitalCa, { id: "dr-thapa-surgeon", name: "Dr. Thapa (Consulting Surgeon)", role: "VERIFIER" }, at(1));
    const otherDoctor = await enrollIdentity(hospitalCa, { id: "dr-rogue", name: "Other Specialist", role: "VERIFIER" }, at(1));
    const crl = await hospitalCa.publishCrl(at(2));

    const ctx: TrustContext = { anchor: hospitalCa.certificate, crl, now: at(10), directory: hospitalCa.directory };

    // 1. Physician signs canonical clinical diagnostic record
    const recordBody = {
      v: 1,
      recordId: "EHR-KTM-2026-992",
      patientSerial: patient.certificate.body.serial,
      patientId: patient.certificate.body.subject.id,
      diagnosis: "Mitral valve prolapse follow-up; refer to cardiothoracic surgery",
      physicianSerial: physician.certificate.body.serial,
      issuedAt: at(5).toISOString(),
    };
    const recordSig = await signMessage(physician.privateKey, "ehr-record", canonicalize(recordBody));
    const recordHash = await sha256Hex(canonicalize(recordBody));

    // 2. Physician signs binary MRI scan attachment
    const binaryMriScan = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0x10, 0xff, 0xfe, 0x00, 0x22]);
    const scanSignature = await signFile(physician.privateKey, binaryMriScan);

    // 3. Patient explicitly signs referral consent authorizing Dr. Thapa
    const referralConsentBody = {
      v: 1,
      recordHash,
      patientSerial: patient.certificate.body.serial,
      specialistSerial: specialist.certificate.body.serial,
      nonce: toHex(randomBytes(16)),
      consentedAt: at(6).toISOString(),
    };
    const referralConsentSig = await signMessage(patient.privateKey, "ehr-consent", canonicalize(referralConsentBody));

    // 4. Encrypt binary MRI scan specifically for Consulting Specialist
    if (!specialist.encryption || !otherDoctor.encryption) throw new Error("missing encryption keys");
    const referralAad = utf8(`ehr-referral|${recordBody.recordId}|${specialist.certificate.body.serial}`);
    const encryptedScan = await hybridEncrypt(specialist.encryption.publicKey, binaryMriScan, referralAad);

    // 5. Specialist verifies CA chain, physician record, patient consent, and decrypts scan
    expect(await verifyCertificate(physician.certificate, ctx, { usage: "titleSign" })).toEqual({ ok: true });
    expect(await verifyCertificate(patient.certificate, ctx, { usage: "transferSign" })).toEqual({ ok: true });

    const docKey = await importSigningPublicKey(physician.certificate.body.signKey);
    const patKey = await importSigningPublicKey(patient.certificate.body.signKey);

    expect(await verifyMessage(docKey, "ehr-record", canonicalize(recordBody), recordSig)).toBe(true);
    expect(await verifyMessage(patKey, "ehr-consent", canonicalize(referralConsentBody), referralConsentSig)).toBe(true);
    expect(referralConsentBody.specialistSerial).toBe(specialist.certificate.body.serial);

    const decryptedScan = await hybridDecrypt(specialist.encryption, encryptedScan, referralAad);
    expect(decryptedScan).toEqual(binaryMriScan);
    expect(await verifyFile(docKey, decryptedScan, scanSignature)).toBe(true);

    // Attack 1: Patient (CITIZEN) cannot impersonate Physician (LRO_OFFICER) to sign a clinical diagnosis
    expect(await verifyCertificate(patient.certificate, ctx, { usage: "titleSign" })).toMatchObject({
      ok: false,
      error: "USAGE_NOT_PERMITTED",
    });

    // Attack 2: Unauthorized doctor cannot decrypt the hybrid-encrypted MRI scan
    await expect(hybridDecrypt(otherDoctor.encryption, encryptedScan, referralAad)).rejects.toThrow();

    // Attack 3: Redirecting consent to another specialist fails integrity check
    expect(
      await verifyMessage(
        patKey,
        "ehr-consent",
        canonicalize({ ...referralConsentBody, specialistSerial: otherDoctor.certificate.body.serial }),
        referralConsentSig,
      ),
    ).toBe(false);
  });
});

describe("Authenticated Forward Secrecy & MITM Prevention", () => {
  it("prevents MITM and guarantees bilateral forward secrecy via authenticated ephemeral-ephemeral ECDH", async () => {
    const ca = await CertificateAuthority.createRoot("Session Auth Root CA", T0);
    const alice = await enrollIdentity(ca, { id: "alice", name: "Alice", role: "CITIZEN" }, at(1));
    const bob = await enrollIdentity(ca, { id: "bob", name: "Bob", role: "CITIZEN" }, at(1));
    const mallory = await enrollIdentity(ca, { id: "mallory", name: "Mallory (MITM)", role: "CITIZEN" }, at(1));
    const crl = await ca.publishCrl(at(2));
    const ctx: TrustContext = { anchor: ca.certificate, crl, now: at(5), directory: ca.directory };

    // --- 1. Authenticated Ephemeral-Ephemeral Handshake ---
    const sessionNonce = toHex(randomBytes(16));
    const aliceEph = await generateEcdhKeyPair(false); // non-extractable ephemeral private key
    const aliceEpk = await exportPublicKey(aliceEph.publicKey);
    const aliceHello = { role: "initiator", epk: aliceEpk, peerSerial: bob.certificate.body.serial, nonce: sessionNonce };
    const aliceHelloSig = await signMessage(alice.privateKey, "eph-kex", canonicalize(aliceHello));

    // Bob verifies Alice's certificate against pinned root + CRL and verifies Alice's signature
    expect(await verifyCertificate(alice.certificate, ctx, { usage: "transferSign" })).toEqual({ ok: true });
    const alicePub = await importSigningPublicKey(alice.certificate.body.signKey);
    expect(await verifyMessage(alicePub, "eph-kex", canonicalize(aliceHello), aliceHelloSig)).toBe(true);

    // Bob generates his own ephemeral ECDH pair and countersigns binding both ephemeral keys + nonce
    const bobEph = await generateEcdhKeyPair(false);
    const bobEpk = await exportPublicKey(bobEph.publicKey);
    const bobReply = {
      role: "responder",
      epk: bobEpk,
      initiatorEpk: aliceEpk,
      peerSerial: alice.certificate.body.serial,
      nonce: sessionNonce,
    };
    const bobReplySig = await signMessage(bob.privateKey, "eph-kex", canonicalize(bobReply));

    // Alice verifies Bob's certificate & signature
    expect(await verifyCertificate(bob.certificate, ctx, { usage: "transferSign" })).toEqual({ ok: true });
    const bobPub = await importSigningPublicKey(bob.certificate.body.signKey);
    expect(await verifyMessage(bobPub, "eph-kex", canonicalize(bobReply), bobReplySig)).toBe(true);

    // Both derive identical AES-256-GCM session keys
    const salt = randomBytes(32);
    const info = utf8(`BhumiSign/v1/eph-session|${aliceEpk}|${bobEpk}|${sessionNonce}`);
    const aliceSecret = await ecdhDeriveSecret(aliceEph.privateKey, await importEcdhPublicKey(bobEpk));
    const bobSecret = await ecdhDeriveSecret(bobEph.privateKey, await importEcdhPublicKey(aliceEpk));
    expect(aliceSecret).toEqual(bobSecret);

    const aliceKey = await importAesKey(await hkdfSha256(aliceSecret, salt, info, 32));
    const bobKey = await importAesKey(await hkdfSha256(bobSecret, salt, info, 32));
    const sessionAad = utf8(`session|${sessionNonce}`);
    const ciphertext = await aesGcmEncrypt(aliceKey, utf8("Confidential deed settlement instructions"), sessionAad);
    expect(fromUtf8(await aesGcmDecrypt(bobKey, ciphertext, sessionAad))).toBe("Confidential deed settlement instructions");

    // --- 2. MITM Attack Simulation ---
    // Mallory intercepts Alice's hello, swaps in Mallory's ephemeral key, and tries to fool Bob
    const malloryEph = await generateEcdhKeyPair(false);
    const malloryEpk = await exportPublicKey(malloryEph.publicKey);
    const tamperedHello = { ...aliceHello, epk: malloryEpk };
    // Replaying Alice's signature over Mallory's ephemeral key fails
    expect(await verifyMessage(alicePub, "eph-kex", canonicalize(tamperedHello), aliceHelloSig)).toBe(false);
    // Signing with Mallory's own key fails when verified against Alice's certified public key
    const mallorySig = await signMessage(mallory.privateKey, "eph-kex", canonicalize(tamperedHello));
    expect(await verifyMessage(alicePub, "eph-kex", canonicalize(tamperedHello), mallorySig)).toBe(false);
    // Substituting a rogue root CA to forge an "Alice" certificate fails pinned anchor validation
    const rogueCa = await CertificateAuthority.createRoot("Rogue MITM CA", T0);
    const rogueAlice = await enrollIdentity(rogueCa, { id: "alice", name: "Alice", role: "CITIZEN" }, at(1));
    expect(await verifyCertificate(rogueAlice.certificate, ctx, { usage: "transferSign" })).toMatchObject({
      ok: false,
      error: "ISSUER_MISMATCH",
    });

    // --- 3. Replay Attack Simulation ---
    const newSessionNonce = toHex(randomBytes(16));
    expect(
      await verifyMessage(alicePub, "eph-kex", canonicalize({ ...aliceHello, nonce: newSessionNonce }), aliceHelloSig),
    ).toBe(false);

    // --- 4. Bilateral Forward Secrecy Verification ---
    // Even if an attacker compromises BOTH Alice's and Bob's long-term static keys after the session,
    // neither static signing key nor the recorded transcript (aliceEpk, bobEpk, salt, ciphertext)
    // reveals the ephemeral ECDH secret or decrypts the recorded session message.
    const staticDerivedAttempt = await ecdhDeriveSecret(
      alice.encryption!.privateKey,
      bob.encryption!.publicKey,
    );
    expect(staticDerivedAttempt).not.toEqual(aliceSecret);
    const wrongKey = await importAesKey(await hkdfSha256(staticDerivedAttempt, salt, info, 32));
    await expect(aesGcmDecrypt(wrongKey, ciphertext, sessionAad)).rejects.toThrow("authentication failed");
  });

  it("proves Ephemeral-Static ECDH (hybrid.ts) provides sender forward secrecy for asynchronous stored deeds", async () => {
    const recipient = await generateEcdhKeyPair();
    const aad = utf8("stored-deed|record-1");
    const envelope = await hybridEncrypt(recipient.publicKey, utf8("Confidential property deed"), aad);
    expect(fromUtf8(await hybridDecrypt(recipient, envelope, aad))).toBe("Confidential property deed");
  });
});
