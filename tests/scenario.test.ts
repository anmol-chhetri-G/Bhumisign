import { mkdirSync, writeFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runScenario } from "../src/demo/scenario";
import { generateSigningKeyPair, signMessage, verifyMessage } from "../src/crypto/primitives";
import { toBase64Url, fromBase64Url } from "../src/crypto/bytes";
import { verifyCertificate } from "../src/pki/verify";
import { PARCEL, makeWorld } from "./helpers";

describe("end-to-end scenario", () => {
  it("every honest step is accepted and every attack is rejected, with the expected reason", async () => {
    const log = await runScenario(new Date("2026-11-24T09:00:00.000Z"));
    expect(log).toHaveLength(14);
    expect(log.filter((e) => !e.pass)).toEqual([]);
    const reason = (prefix: string) => log.find((e) => e.step.startsWith(prefix))?.detail ?? "";
    expect(reason("Keystore: Incorrect")).toContain("BAD_PASSPHRASE");
    expect(reason("Double sale")).toContain("HEAD_MISMATCH");
    expect(reason("Replay")).toContain("HEAD_MISMATCH");
    expect(reason("Mallory sells")).toContain("NOT_OWNER");
    expect(reason("Bank detects")).toContain("BAD_SIGNATURE");
    expect(reason("A citizen certificate")).toContain("USAGE_NOT_PERMITTED");
    expect(reason("Revoked")).toContain("REVOKED");
  });
});

describe("randomised tamper tests", () => {
  it("flipping any single bit of a signature invalidates it (all 512 bits)", async () => {
    const keys = await generateSigningKeyPair();
    const sig = fromBase64Url(await signMessage(keys.privateKey, "title", "payload"));
    for (let bit = 0; bit < sig.length * 8; bit++) {
      const copy = new Uint8Array(sig);
      copy[bit >> 3] = (copy[bit >> 3] ?? 0) ^ (1 << (bit & 7));
      expect(await verifyMessage(keys.publicKey, "title", "payload", toBase64Url(copy))).toBe(false);
    }
  });

  it("mutating any top-level field of a certificate body is detected", async () => {
    const w = await makeWorld();
    for (const key of Object.keys(w.sita.certificate.body)) {
      const copy = structuredClone(w.sita.certificate) as unknown as { body: Record<string, unknown>; signature: string };
      const v = copy.body[key];
      copy.body[key] = typeof v === "string" ? v + "x" : typeof v === "number" ? v + 1 : Array.isArray(v) ? [...v, "certSign"] : v === null ? "x" : { ...(v as object), id: "zz" };
      const result = await verifyCertificate(copy as never, w.ctx());
      expect(result.ok, `field ${key}`).toBe(false);
    }
  });
});

describe.skipIf(process.env.DUMP !== "1")("sample artefacts for the report", () => {
  it("writes JSON samples to ./out", async () => {
    const w = await makeWorld();
    mkdirSync("out", { recursive: true });
    writeFileSync("out/sample-root.json", JSON.stringify(w.ca.certificate, null, 2));
    writeFileSync("out/sample-certificate.json", JSON.stringify(w.sita.certificate, null, 2));
    writeFileSync("out/sample-crl.json", JSON.stringify(w.crl, null, 2));
    writeFileSync("out/sample-title.json", JSON.stringify(w.registry.history(PARCEL), null, 2));
    expect(true).toBe(true);
  });
});
