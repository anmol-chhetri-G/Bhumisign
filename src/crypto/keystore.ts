import { fromBase64Url, toBase64Url, utf8 } from "./bytes";
import { CryptoError, PBKDF2_ITERATIONS, importAesKey, pbkdf2Sha256, randomBytes } from "./primitives";

export type KeyKind = "ECDSA" | "ECDH";

/** What gets stored on disk / IndexedDB: the private key is only ever stored wrapped. */
export interface WrappedKey {
  v: 1;
  kind: KeyKind;
  kdf: "PBKDF2-HMAC-SHA256";
  iterations: number;
  salt: string;
  iv: string;
  wrapped: string;
  label: string; // e.g. the public-key fingerprint; bound into the AES-GCM AAD
}

const MIN_PASSPHRASE_LENGTH = 12;
const MAX_ITERATIONS = 10_000_000;
const subtle = globalThis.crypto.subtle;

const aad = (kind: KeyKind, label: string) => utf8(`BhumiSign/v1/keywrap|${kind}|${label}`);

async function deriveKek(passphrase: string, salt: Uint8Array<ArrayBuffer>, iterations: number) {
  const raw = await pbkdf2Sha256(passphrase, salt, iterations, 32);
  return importAesKey(raw, ["wrapKey", "unwrapKey"]);
}

export async function wrapPrivateKey(
  privateKey: CryptoKey,
  kind: KeyKind,
  passphrase: string,
  label: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<WrappedKey> {
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) throw new CryptoError("passphrase too short");
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const kek = await deriveKek(passphrase, salt, iterations);
  const wrapped = await subtle.wrapKey("pkcs8", privateKey, kek, {
    name: "AES-GCM",
    iv,
    additionalData: aad(kind, label),
    tagLength: 128,
  });
  return {
    v: 1,
    kind,
    kdf: "PBKDF2-HMAC-SHA256",
    iterations,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    wrapped: toBase64Url(new Uint8Array(wrapped)),
    label,
  };
}

/** Returns a NON-extractable key; throws CryptoError on a wrong passphrase or any tampering. */
export async function unwrapPrivateKey(
  blob: WrappedKey,
  passphrase: string,
  minIterations = 100_000,
): Promise<CryptoKey> {
  if (
    blob.v !== 1 ||
    blob.kdf !== "PBKDF2-HMAC-SHA256" ||
    (blob.kind !== "ECDSA" && blob.kind !== "ECDH") ||
    !Number.isInteger(blob.iterations) ||
    blob.iterations < minIterations ||
    blob.iterations > MAX_ITERATIONS
  ) {
    throw new CryptoError("unsupported or unsafe key blob parameters");
  }
  try {
    const kek = await deriveKek(passphrase, fromBase64Url(blob.salt), blob.iterations);
    const algorithm = { name: blob.kind, namedCurve: "P-256" } as const;
    return await subtle.unwrapKey(
      "pkcs8",
      fromBase64Url(blob.wrapped),
      kek,
      {
        name: "AES-GCM",
        iv: fromBase64Url(blob.iv),
        additionalData: aad(blob.kind, blob.label),
        tagLength: 128,
      },
      algorithm,
      false,
      blob.kind === "ECDSA" ? ["sign"] : ["deriveBits"],
    );
  } catch {
    throw new CryptoError("wrong passphrase or corrupted key blob");
  }
}
