import { describe, expect, it } from "vitest";
import { concatBytes, fromBase64Url, toBase64Url, utf8, fromUtf8 } from "../src/crypto/bytes";
import { hybridDecrypt, hybridEncrypt } from "../src/crypto/hybrid";
import { unwrapPrivateKey, wrapPrivateKey } from "../src/crypto/keystore";
import {
  PBKDF2_ITERATIONS,
  aesGcmDecrypt,
  ecdhDeriveSecret,
  hkdfSha256,
  importAesKey,
  exportPublicKey,
  generateEcdhKeyPair,
  generateSigningKeyPair,
  importEcdhPublicKey,
  verifyMessage,
  signMessage,
} from "../src/crypto/primitives";

const PASS = "correct horse battery staple";
const FAST = 1000; // iterations used only to keep the test-suite fast

describe("key wrapping (PBKDF2 + AES-256-GCM, PKCS#8)", () => {
  it("uses 600,000 iterations by default", () => {
    expect(PBKDF2_ITERATIONS).toBe(600_000);
  });

  it("round-trips and the unwrapped key still signs correctly", async () => {
    const keys = await generateSigningKeyPair(true);
    const blob = await wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k1", FAST);
    const restored = await unwrapPrivateKey(blob, PASS, FAST);
    const sig = await signMessage(restored, "title", "hello");
    expect(await verifyMessage(keys.publicKey, "title", "hello", sig)).toBe(true);
  });

  it("works for ECDH keys too", async () => {
    const keys = await generateEcdhKeyPair(true);
    const blob = await wrapPrivateKey(keys.privateKey, "ECDH", PASS, "k2", FAST);
    const restored = await unwrapPrivateKey(blob, PASS, FAST);
    const env = await hybridEncrypt(keys.publicKey, utf8("x"), utf8("a"));
    expect(await hybridDecrypt({ publicKey: keys.publicKey, privateKey: restored }, env, utf8("a"))).toEqual(utf8("x"));
  });

  it("unwrapped keys are non-extractable", async () => {
    const keys = await generateSigningKeyPair(true);
    const restored = await unwrapPrivateKey(await wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k", FAST), PASS, FAST);
    await expect(crypto.subtle.exportKey("pkcs8", restored)).rejects.toThrow();
  });

  it("fails on a wrong passphrase", async () => {
    const keys = await generateSigningKeyPair(true);
    const blob = await wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k", FAST);
    await expect(unwrapPrivateKey(blob, PASS + "x", FAST)).rejects.toThrow("wrong passphrase");
  });

  it("fails if any field of the blob is tampered with (AAD binds kind and label)", async () => {
    const keys = await generateSigningKeyPair(true);
    const blob = await wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k", FAST);
    const flip = (s: string) => toBase64Url(fromBase64Url(s).map((b, i) => (i === 0 ? b ^ 1 : b)));
    await expect(unwrapPrivateKey({ ...blob, wrapped: flip(blob.wrapped) }, PASS, FAST)).rejects.toThrow();
    await expect(unwrapPrivateKey({ ...blob, iv: flip(blob.iv) }, PASS, FAST)).rejects.toThrow();
    await expect(unwrapPrivateKey({ ...blob, salt: flip(blob.salt) }, PASS, FAST)).rejects.toThrow();
    await expect(unwrapPrivateKey({ ...blob, label: "other" }, PASS, FAST)).rejects.toThrow();
    await expect(unwrapPrivateKey({ ...blob, kind: "ECDH" }, PASS, FAST)).rejects.toThrow();
  });

  it("enforces passphrase and iteration policy", async () => {
    const keys = await generateSigningKeyPair(true);
    await expect(wrapPrivateKey(keys.privateKey, "ECDSA", "short", "k", FAST)).rejects.toThrow("too short");
    const blob = await wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k", FAST);
    await expect(unwrapPrivateKey(blob, PASS)).rejects.toThrow("unsafe"); // below the default minimum
    await expect(unwrapPrivateKey({ ...blob, iterations: 2 ** 40 }, PASS, FAST)).rejects.toThrow("unsafe");
    await expect(unwrapPrivateKey({ ...blob, kdf: "scrypt" as never }, PASS, FAST)).rejects.toThrow("unsafe");
  });

  it("does not wrap non-extractable keys", async () => {
    const keys = await generateSigningKeyPair(false);
    await expect(wrapPrivateKey(keys.privateKey, "ECDSA", PASS, "k", FAST)).rejects.toThrow();
  });
});

describe("hybrid encryption (ECDH-ES + HKDF + AES-GCM)", () => {
  const aad = utf8("deed|KTM-W10-K1234");

  it("round-trips for the intended recipient", async () => {
    const bob = await generateEcdhKeyPair();
    const env = await hybridEncrypt(bob.publicKey, utf8("sale deed"), aad);
    expect(fromUtf8(await hybridDecrypt(bob, env, aad))).toBe("sale deed");
  });

  it("follows the documented construction (HKDF info binds both public keys)", async () => {
    const bob = await generateEcdhKeyPair();
    const env = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    const shared = await ecdhDeriveSecret(bob.privateKey, await importEcdhPublicKey(env.epk));
    const info = utf8(`BhumiSign/v1/hybrid|${env.epk}|${await exportPublicKey(bob.publicKey)}`);
    const key = await importAesKey(await hkdfSha256(shared, fromBase64Url(env.salt), info, 32));
    const pt = await aesGcmDecrypt(key, { iv: env.iv, ct: env.ct }, concatBytes(utf8("BhumiSign/v1/hybrid-aad|"), aad));
    expect(fromUtf8(pt)).toBe("m");
  });

  it("is randomised: same input gives different envelopes", async () => {
    const bob = await generateEcdhKeyPair();
    const a = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    const b = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    expect(a.epk).not.toBe(b.epk);
    expect(a.ct).not.toBe(b.ct);
  });

  it("fails for another recipient and for a different AAD", async () => {
    const bob = await generateEcdhKeyPair();
    const eve = await generateEcdhKeyPair();
    const env = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    await expect(hybridDecrypt(eve, env, aad)).rejects.toThrow();
    await expect(hybridDecrypt(bob, env, utf8("other"))).rejects.toThrow();
  });

  it("fails if the envelope is tampered with", async () => {
    const bob = await generateEcdhKeyPair();
    const env = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    const flip = (s: string) => toBase64Url(fromBase64Url(s).map((b, i) => (i === 0 ? b ^ 1 : b)));
    await expect(hybridDecrypt(bob, { ...env, ct: flip(env.ct) }, aad)).rejects.toThrow();
    await expect(hybridDecrypt(bob, { ...env, salt: flip(env.salt) }, aad)).rejects.toThrow();
    const other = await generateEcdhKeyPair();
    await expect(hybridDecrypt(bob, { ...env, epk: await exportPublicKey(other.publicKey) }, aad)).rejects.toThrow();
  });

  it("rejects an ephemeral public key that is not on the curve", async () => {
    const bob = await generateEcdhKeyPair();
    const env = await hybridEncrypt(bob.publicKey, utf8("m"), aad);
    const spki = fromBase64Url(env.epk);
    spki[spki.length - 1] = (spki[spki.length - 1] ?? 0) ^ 0xff; // corrupt the Y coordinate
    const bad = toBase64Url(spki);
    await expect(importEcdhPublicKey(bad)).rejects.toThrow();
    await expect(hybridDecrypt(bob, { ...env, epk: bad }, aad)).rejects.toThrow();
  });
});
