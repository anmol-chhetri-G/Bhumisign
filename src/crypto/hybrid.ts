import { concatBytes, fromBase64Url, toBase64Url, utf8 } from "./bytes";
import type { Bytes } from "./bytes";
import {
  aesGcmDecrypt,
  aesGcmEncrypt,
  ecdhDeriveSecret,
  exportPublicKey,
  generateEcdhKeyPair,
  hkdfSha256,
  importAesKey,
  importEcdhPublicKey,
  randomBytes,
} from "./primitives";

/** ECDH-ES (ephemeral-static) + HKDF-SHA-256 + AES-256-GCM. */
export interface HybridEnvelope {
  v: 1;
  epk: string; // ephemeral public key (SPKI, base64url)
  salt: string;
  iv: string;
  ct: string;
}

async function deriveContentKey(shared: Bytes, salt: Bytes, epk: string, recipientSpki: string) {
  // Both public keys are bound into the KDF input, so the key is tied to this exact exchange.
  const info = utf8(`BhumiSign/v1/hybrid|${epk}|${recipientSpki}`);
  return importAesKey(await hkdfSha256(shared, salt, info, 32));
}

export async function hybridEncrypt(
  recipientPublicKey: CryptoKey,
  plaintext: Bytes,
  aad: Bytes,
): Promise<HybridEnvelope> {
  const ephemeral = await generateEcdhKeyPair(false);
  const shared = await ecdhDeriveSecret(ephemeral.privateKey, recipientPublicKey);
  const epk = await exportPublicKey(ephemeral.publicKey);
  const recipientSpki = await exportPublicKey(recipientPublicKey);
  const salt = randomBytes(32);
  const key = await deriveContentKey(shared, salt, epk, recipientSpki);
  const box = await aesGcmEncrypt(key, plaintext, concatBytes(utf8("BhumiSign/v1/hybrid-aad|"), aad));
  return { v: 1, epk, salt: toBase64Url(salt), iv: box.iv, ct: box.ct };
}

export async function hybridDecrypt(
  recipient: CryptoKeyPair,
  envelope: HybridEnvelope,
  aad: Bytes,
): Promise<Bytes> {
  const ephemeralPublic = await importEcdhPublicKey(envelope.epk); // rejects off-curve points
  const shared = await ecdhDeriveSecret(recipient.privateKey, ephemeralPublic);
  const recipientSpki = await exportPublicKey(recipient.publicKey);
  const key = await deriveContentKey(shared, fromBase64Url(envelope.salt), envelope.epk, recipientSpki);
  return aesGcmDecrypt(
    key,
    { iv: envelope.iv, ct: envelope.ct },
    concatBytes(utf8("BhumiSign/v1/hybrid-aad|"), aad),
  );
}
