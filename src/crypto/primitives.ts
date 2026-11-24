import type { Bytes } from "./bytes";
import { fromBase64Url, toBase64Url, toHex, utf8 } from "./bytes";

const subtle = globalThis.crypto.subtle;

export class CryptoError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CryptoError";
  }
}

export const PBKDF2_ITERATIONS = 600_000; // OWASP guidance for PBKDF2-HMAC-SHA256
const GCM_TAG_BITS = 128;
const GCM_IV_BYTES = 12;
const ECDSA_PARAMS = { name: "ECDSA", hash: "SHA-256" } as const;

/* ---------- randomness & hashing ---------- */

export function randomBytes(length: number): Bytes {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

export async function sha256(data: Bytes): Promise<Bytes> {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

export async function sha256Hex(data: Bytes | string): Promise<string> {
  return toHex(await sha256(typeof data === "string" ? utf8(data) : data));
}

/* ---------- key generation / import / export ---------- */

export function generateSigningKeyPair(extractable = true): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, extractable, ["sign", "verify"]);
}

export function generateEcdhKeyPair(extractable = true): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, extractable, ["deriveBits"]);
}

/** Public keys travel as base64url SPKI (DER) strings. */
export async function exportPublicKey(key: CryptoKey): Promise<string> {
  return toBase64Url(new Uint8Array(await subtle.exportKey("spki", key)));
}

export function importSigningPublicKey(spki: string): Promise<CryptoKey> {
  return subtle.importKey("spki", fromBase64Url(spki), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
}

/** Import validates that the point is on the P-256 curve (invalid-curve defence). */
export function importEcdhPublicKey(spki: string): Promise<CryptoKey> {
  return subtle.importKey("spki", fromBase64Url(spki), { name: "ECDH", namedCurve: "P-256" }, true, []);
}

export async function fingerprint(spki: string): Promise<string> {
  return sha256Hex(fromBase64Url(spki));
}

/* ---------- ECDSA P-256 / SHA-256 with domain separation ---------- */

const CONTEXT_RE = /^[a-z][a-z0-9-]{0,31}$/;

function signingInput(context: string, payload: string): Bytes {
  if (!CONTEXT_RE.test(context)) throw new CryptoError("invalid signature context");
  return utf8(`BhumiSign/v1/${context}\n${payload}`);
}

/** Signature = 64 raw bytes (r || s, IEEE P1363) as base64url. */
export async function signMessage(privateKey: CryptoKey, context: string, payload: string): Promise<string> {
  const sig = await subtle.sign(ECDSA_PARAMS, privateKey, signingInput(context, payload));
  return toBase64Url(new Uint8Array(sig));
}

/** Never throws: any malformed input is simply "not valid". */
export async function verifyMessage(
  publicKey: CryptoKey,
  context: string,
  payload: string,
  signature: string,
): Promise<boolean> {
  try {
    const sig = fromBase64Url(signature);
    if (sig.length !== 64) return false;
    return await subtle.verify(ECDSA_PARAMS, publicKey, sig, signingInput(context, payload));
  } catch {
    return false;
  }
}

/* ---------- AES-256-GCM ---------- */

export interface GcmBox {
  iv: string; // base64url, 12 bytes, fresh random per message
  ct: string; // base64url, ciphertext || 16-byte tag
}

export function importAesKey(raw: Bytes, usages: KeyUsage[] = ["encrypt", "decrypt"]): Promise<CryptoKey> {
  if (raw.length !== 32) throw new CryptoError("AES-256 key must be 32 bytes");
  return subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
}

export async function aesGcmEncrypt(key: CryptoKey, plaintext: Bytes, aad: Bytes): Promise<GcmBox> {
  const iv = randomBytes(GCM_IV_BYTES);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad, tagLength: GCM_TAG_BITS },
    key,
    plaintext,
  );
  return { iv: toBase64Url(iv), ct: toBase64Url(new Uint8Array(ct)) };
}

export async function aesGcmDecrypt(key: CryptoKey, box: GcmBox, aad: Bytes): Promise<Bytes> {
  try {
    const iv = fromBase64Url(box.iv);
    if (iv.length !== GCM_IV_BYTES) throw new Error("bad iv length");
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv, additionalData: aad, tagLength: GCM_TAG_BITS },
      key,
      fromBase64Url(box.ct),
    );
    return new Uint8Array(pt);
  } catch {
    throw new CryptoError("authentication failed");
  }
}

/* ---------- KDFs and key agreement ---------- */

export async function hkdfSha256(ikm: Bytes, salt: Bytes, info: Bytes, length: number): Promise<Bytes> {
  const base = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(
    await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, base, length * 8),
  );
}

export async function pbkdf2Sha256(
  passphrase: string,
  salt: Bytes,
  iterations: number,
  length: number,
): Promise<Bytes> {
  const base = await subtle.importKey("raw", utf8(passphrase.normalize("NFKC")), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, length * 8),
  );
}

export async function ecdhDeriveSecret(privateKey: CryptoKey, publicKey: CryptoKey): Promise<Bytes> {
  return new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256));
}
