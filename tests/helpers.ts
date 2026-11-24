import { expect } from "vitest";
import { CertificateAuthority, enrollIdentity } from "../src/pki/ca";
import type { Identity } from "../src/pki/ca";
import type { Crl, TrustContext } from "../src/pki/types";
import { Registry } from "../src/land/registry";
import { issueTitle } from "../src/land/title";
import type { Title } from "../src/land/types";

export const T0 = new Date("2026-11-24T09:00:00.000Z");
export const at = (minutes: number) => new Date(T0.getTime() + minutes * 60_000);
export const PARCEL = "KTM-W10-K1234";

export interface World {
  ca: CertificateAuthority;
  officer: Identity;
  sita: Identity;
  ram: Identity;
  mallory: Identity;
  bank: Identity;
  registry: Registry;
  title: Title;
  crl: Crl;
  /** Trust context at `now` (default T0+10min) with the given CRL (default: the empty one). */
  ctx: (now?: Date, crl?: Crl | null) => TrustContext;
}

/** Root CA + officer + 3 citizens + bank, an empty CRL, and parcel KTM-W10-K1234 owned by Sita. */
export async function makeWorld(): Promise<World> {
  const ca = await CertificateAuthority.createRoot("Test Root CA", T0);
  const officer = await enrollIdentity(ca, { id: "lro-1", name: "Officer", role: "LRO_OFFICER" }, at(1));
  const sita = await enrollIdentity(ca, { id: "np-1", name: "Sita", role: "CITIZEN" }, at(1));
  const ram = await enrollIdentity(ca, { id: "np-2", name: "Ram", role: "CITIZEN" }, at(1));
  const mallory = await enrollIdentity(ca, { id: "np-3", name: "Mallory", role: "CITIZEN" }, at(1));
  const bank = await enrollIdentity(ca, { id: "bank-1", name: "Bank", role: "VERIFIER" }, at(1));
  const crl = await ca.publishCrl(at(2));
  const ctx = (now: Date = at(10), c: Crl | null = crl): TrustContext => ({
    anchor: ca.certificate,
    crl: c,
    now,
    directory: ca.directory,
  });
  const registry = new Registry();
  const issued = await issueTitle(officer, { parcelId: PARCEL, owner: sita.certificate, areaSqm: 2400, now: at(5) });
  expect(issued.ok).toBe(true);
  if (!issued.ok) throw new Error("setup failed");
  expect((await registry.append({ title: issued.title, evidence: null }, ctx())).ok).toBe(true);
  return { ca, officer, sita, ram, mallory, bank, registry, title: issued.title, crl, ctx };
}
