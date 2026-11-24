import { createDecipheriv, createPublicKey, generateKeyPairSync, hkdfSync, pbkdf2Sync, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { fromBase64Url, fromHex, toBase64Url, toHex, utf8 } from "../src/crypto/bytes";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ecdhDeriveSecret,
  exportPublicKey,
  fingerprint,
  generateEcdhKeyPair,
  generateSigningKeyPair,
  hkdfSha256,
  importAesKey,
  importSigningPublicKey,
  pbkdf2Sha256,
  randomBytes,
  sha256Hex,
  signMessage,
  verifyMessage,
} from "../src/crypto/primitives";

describe("SHA-256 known-answer tests (FIPS 180-4 examples)", () => {
  it("empty string", async () => {
    expect(await sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  });
  it('"abc"', async () => {
    expect(await sha256Hex("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });
  it("56-byte two-block message", async () => {
    const msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect(await sha256Hex(msg)).toBe("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  });
});

describe("KDFs", () => {
  it("HKDF-SHA-256 matches RFC 5869 test case 1", async () => {
    const okm = await hkdfSha256(
      fromHex("0b".repeat(22)),
      fromHex("000102030405060708090a0b0c"),
      fromHex("f0f1f2f3f4f5f6f7f8f9"),
      42,
    );
    expect(toHex(okm)).toBe("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
  });

  it("HKDF agrees with Node's implementation", async () => {
    const ikm = randomBytes(32), salt = randomBytes(32), info = randomBytes(20);
    const mine = await hkdfSha256(ikm, salt, info, 64);
    expect(toHex(mine)).toBe(Buffer.from(hkdfSync("sha256", ikm, salt, info, 64)).toString("hex"));
  });

  it("PBKDF2-HMAC-SHA-256 matches the published 1-iteration vector", async () => {
    const dk = await pbkdf2Sha256("password", utf8("salt"), 1, 32);
    expect(toHex(dk)).toBe("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
  });

  it("PBKDF2 agrees with Node's implementation (NFKC-normalised passphrase)", async () => {
    const salt = randomBytes(16);
    const mine = await pbkdf2Sha256("pässword\u0301", salt, 4096, 32);
    const theirs = pbkdf2Sync("pässword\u0301".normalize("NFKC"), salt, 4096, 32, "sha256");
    expect(toHex(mine)).toBe(theirs.toString("hex"));
  });
});

describe("ECDSA P-256 with domain separation", () => {
  it("signs and verifies; signature is 64 raw bytes", async () => {
    const keys = await generateSigningKeyPair();
    const sig = await signMessage(keys.privateKey, "title", "payload");
    expect(fromBase64Url(sig)).toHaveLength(64);
    expect(await verifyMessage(keys.publicKey, "title", "payload", sig)).toBe(true);
  });

  it("rejects a changed payload, a different context and a different key", async () => {
    const a = await generateSigningKeyPair();
    const b = await generateSigningKeyPair();
    const sig = await signMessage(a.privateKey, "title", "payload");
    expect(await verifyMessage(a.publicKey, "title", "payload!", sig)).toBe(false);
    expect(await verifyMessage(a.publicKey, "cert", "payload", sig)).toBe(false);
    expect(await verifyMessage(b.publicKey, "title", "payload", sig)).toBe(false);
  });

  it("returns false (never throws) for malformed signatures and contexts", async () => {
    const keys = await generateSigningKeyPair();
    for (const bad of ["", "!!!", "AAAA", toBase64Url(new Uint8Array(63)), toBase64Url(new Uint8Array(65))]) {
      expect(await verifyMessage(keys.publicKey, "title", "p", bad)).toBe(false);
    }
    const sig = await signMessage(keys.privateKey, "title", "p");
    expect(await verifyMessage(keys.publicKey, "BAD CONTEXT", "p", sig)).toBe(false);
    await expect(signMessage(keys.privateKey, "bad\ncontext", "p")).rejects.toThrow("context");
  });

  it("interoperates with Node's crypto in both directions", async () => {
    const input = utf8("BhumiSign/v1/title\nhello");
    // Web Crypto signs, Node verifies
    const keys = await generateSigningKeyPair();
    const sig = fromBase64Url(await signMessage(keys.privateKey, "title", "hello"));
    const spki = fromBase64Url(await exportPublicKey(keys.publicKey));
    const nodePub = createPublicKey({ key: Buffer.from(spki), format: "der", type: "spki" });
    expect(nodeVerify("sha256", input, { key: nodePub, dsaEncoding: "ieee-p1363" }, sig)).toBe(true);
    // Node signs, Web Crypto verifies
    const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const nodeSig = nodeSign("sha256", input, { key: pair.privateKey, dsaEncoding: "ieee-p1363" });
    const imported = await importSigningPublicKey(toBase64Url(pair.publicKey.export({ format: "der", type: "spki" })));
    expect(await verifyMessage(imported, "title", "hello", toBase64Url(nodeSig))).toBe(true);
  });

  it("fingerprint is the SHA-256 of the SPKI bytes", async () => {
    const keys = await generateSigningKeyPair();
    const spki = await exportPublicKey(keys.publicKey);
    expect(await fingerprint(spki)).toBe(await sha256Hex(fromBase64Url(spki)));
  });
});

describe("AES-256-GCM", () => {
  const rawKey = randomBytes(32);
  const aad = utf8("context");

  it("round-trips", async () => {
    const key = await importAesKey(rawKey);
    const box = await aesGcmEncrypt(key, utf8("secret"), aad);
    expect(await aesGcmDecrypt(key, box, aad)).toEqual(utf8("secret"));
  });

  it("detects tampering with ciphertext, IV, AAD and key", async () => {
    const key = await importAesKey(rawKey);
    const box = await aesGcmEncrypt(key, utf8("secret"), aad);
    const flip = (s: string) => toBase64Url(fromBase64Url(s).map((b, i) => (i === 0 ? b ^ 1 : b)));
    await expect(aesGcmDecrypt(key, { ...box, ct: flip(box.ct) }, aad)).rejects.toThrow("authentication failed");
    await expect(aesGcmDecrypt(key, { ...box, iv: flip(box.iv) }, aad)).rejects.toThrow("authentication failed");
    await expect(aesGcmDecrypt(key, box, utf8("other"))).rejects.toThrow("authentication failed");
    await expect(aesGcmDecrypt(await importAesKey(randomBytes(32)), box, aad)).rejects.toThrow("authentication failed");
    await expect(aesGcmDecrypt(key, { ...box, iv: toBase64Url(new Uint8Array(8)) }, aad)).rejects.toThrow();
  });

  it("uses a fresh IV for every message", async () => {
    const key = await importAesKey(rawKey);
    const ivs = new Set<string>();
    for (let i = 0; i < 500; i++) ivs.add((await aesGcmEncrypt(key, utf8("x"), aad)).iv);
    expect(ivs.size).toBe(500);
  });

  it("output decrypts with Node's AES-256-GCM (ciphertext || tag layout)", async () => {
    const key = await importAesKey(rawKey);
    const box = await aesGcmEncrypt(key, utf8("interop"), aad);
    const ct = fromBase64Url(box.ct);
    const decipher = createDecipheriv("aes-256-gcm", rawKey, fromBase64Url(box.iv));
    decipher.setAAD(aad);
    decipher.setAuthTag(Buffer.from(ct.slice(-16)));
    const pt = Buffer.concat([decipher.update(ct.slice(0, -16)), decipher.final()]);
    expect(pt.toString()).toBe("interop");
  });

  it("rejects keys that are not 32 bytes", () => {
    expect(() => importAesKey(randomBytes(16))).toThrow("32 bytes");
  });
});

describe("ECDH", () => {
  it("both sides derive the same 32-byte secret", async () => {
    const a = await generateEcdhKeyPair();
    const b = await generateEcdhKeyPair();
    const s1 = await ecdhDeriveSecret(a.privateKey, b.publicKey);
    const s2 = await ecdhDeriveSecret(b.privateKey, a.publicKey);
    expect(s1).toHaveLength(32);
    expect(toHex(s1)).toBe(toHex(s2));
  });
});
