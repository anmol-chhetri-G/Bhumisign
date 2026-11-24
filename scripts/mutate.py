#!/usr/bin/env python3
"""Mutation check: break the code on purpose and confirm the test-suite notices.

Usage:  python3 scripts/mutate.py          (about 1-2 minutes)
Each mutant is applied to a temporary copy of the repo; your working tree is never touched.
Exit code 0 = every mutant was caught or is listed in EQUIVALENT.
"""
import json, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EQUIVALENT = {"M26"}  # redundant with the signature check: only the CA key could produce such a CRL

MUTANTS = [
    ("M1", "Skip the CRL revocation check", "src/pki/verify.ts",
     "if (entry && (parseUtc(entry.revokedAt) ?? Infinity) <= at.getTime())", "if (false as boolean && entry)"),
    ("M2", "Drop signature domain separation", "src/crypto/primitives.ts",
     "return utf8(`BhumiSign/v1/${context}\\n${payload}`);", "return utf8(`BhumiSign/v1/\\n${payload}`);"),
    ("M3", "Remove registry compare-and-swap", "src/land/registry.ts",
     "if (current.length !== before.length) {", "if (false as boolean) {"),
    ("M4", "Skip proof of possession at enrolment", "src/pki/ca.ts",
     'if (!(await verifyMessage(requesterKey, "enroll", popPayload(rest), popSignature))) return fail("BAD_POP");', ""),
    ("M5", "Use a constant AES-GCM IV", "src/crypto/primitives.ts",
     "const iv = randomBytes(GCM_IV_BYTES);", "const iv = new Uint8Array(GCM_IV_BYTES);"),
    ("M6", "Skip the prevHash link check", "src/land/verify.ts",
     'if (t.prevHash !== (await hashBody(p))) return fail("BROKEN_CHAIN", "prevHash");', ""),
    ("M7", "Key-wrap AAD ignores the label", "src/crypto/keystore.ts",
     "const aad = (kind: KeyKind, label: string) => utf8(`BhumiSign/v1/keywrap|${kind}|${label}`);",
     "const aad = (kind: KeyKind, _label: string) => utf8(`BhumiSign/v1/keywrap|${kind}`);"),
    ("M8", "Check signer certificates at the signer-claimed time", "src/land/verify.ts",
     'ctx.directory.get(intent.body.sellerSerial), ctx, "transferSign", issuedAt,',
     'ctx.directory.get(intent.body.sellerSerial), ctx, "transferSign", new Date(intentAt),'),
    ("M9", "Accept an expired CRL", "src/pki/verify.ts",
     'if (now.getTime() > nextUpdate) return fail("CRL_STALE"); // fail closed', ""),
    ("M10", "Do not enforce key usage", "src/pki/verify.ts",
     'if (options.usage && !cert.body.usages.includes(options.usage)) return fail("USAGE_NOT_PERMITTED", options.usage);', ""),
    ("M11", "Skip the sequence-number check", "src/land/verify.ts", " || t.seq !== p.seq + 1", ""),
    ("M12", "Skip the parcel-id continuity check", "src/land/verify.ts", "t.parcelId !== p.parcelId ||", ""),
    ("M13", "Skip the evidenceHash check", "src/land/verify.ts",
     'if (t.evidenceHash !== (await hashBody({ intent: intent.body, acceptance: acceptance.body }))) {', "if (false as boolean) {"),
    ("M14", "Skip the buyer-equals-new-owner check", "src/land/verify.ts", "intent.body.buyerSerial !== t.ownerSerial ||", ""),
    ("M15", "Skip the consent-refers-to-previous-version check", "src/land/verify.ts", "intent.body.titleHash !== t.prevHash ||", ""),
    ("M16", "Skip the acceptance-refers-to-intent check", "src/land/verify.ts",
     "acceptance.body.intentHash !== intentHash", "false as boolean"),
    ("M17", "Skip the seller-is-previous-owner check", "src/land/verify.ts", "intent.body.sellerSerial !== p.ownerSerial ||", ""),
    ("M18", "Never record used nonces", "src/land/registry.ts", "this.usedNonces.add(nonce);", ""),
    ("M19", "Skip the clock-skew check", "src/land/registry.ts",
     'if (Math.abs(ctx.now.getTime() - issuedAt) > MAX_CLOCK_SKEW_MS) return fail("CLOCK_SKEW");', ""),
    ("M20", "Drop the PBKDF2 iteration floor", "src/crypto/keystore.ts", "blob.iterations < minIterations ||", ""),
    ("M21", "Do not sort keys when canonicalising", "src/crypto/canonical.ts", "Object.keys(record).sort()", "Object.keys(record)"),
    ("M22", "Do not cap leaf validity at the CA expiry", "src/pki/ca.ts",
     "const notAfter = Math.min(\n      notBefore + validityDays * DAY_MS,\n      Date.parse(this.certificate.body.notAfter),\n    );",
     "const notAfter = notBefore + validityDays * DAY_MS;"),
    ("M23", "Make unwrapped private keys extractable", "src/crypto/keystore.ts",
     "      algorithm,\n      false,", "      algorithm,\n      true,"),
    ("M24", "Drop the DUPLICATE_PARCEL guard", "src/land/registry.ts",
     'if (prev && record.title.body.seq === 0) return fail("DUPLICATE_PARCEL");', ""),
    ("M25", "Do not bind public keys into the hybrid KDF", "src/crypto/hybrid.ts",
     "const info = utf8(`BhumiSign/v1/hybrid|${epk}|${recipientSpki}`);", 'const info = utf8("BhumiSign/v1/hybrid");'),
    ("M26", "Do not verify the CRL issuer field", "src/pki/verify.ts",
     'if (crl.body.issuerSerial !== anchor.body.serial) return fail("CRL_INVALID", "wrong issuer");', ""),
]


def main() -> int:
    work = tempfile.mkdtemp(prefix="mutants-")
    for name in ("src", "tests", "package.json", "tsconfig.json", "vite.config.ts", "index.html"):
        src, dst = os.path.join(ROOT, name), os.path.join(work, name)
        shutil.copytree(src, dst) if os.path.isdir(src) else shutil.copy(src, dst)
    os.symlink(os.path.join(ROOT, "node_modules"), os.path.join(work, "node_modules"))
    report, survivors = os.path.join(work, "report.json"), []
    for mid, desc, rel, old, new in MUTANTS:
        path = os.path.join(work, rel)
        original = open(path, encoding="utf-8").read()
        if old not in original:
            print(f"{mid}: pattern not found in {rel} (did the code change?)")
            return 2
        open(path, "w", encoding="utf-8").write(original.replace(old, new, 1))
        try:
            subprocess.run(["npx", "vitest", "run", "--reporter=json", f"--outputFile={report}"],
                           cwd=work, capture_output=True, text=True)
            data = json.load(open(report))
            caught = [a["fullName"] for t in data["testResults"] for a in t["assertionResults"] if a["status"] == "failed"]
            caught += [t["name"] for t in data["testResults"] if t["status"] == "failed" and not t["assertionResults"]]
        finally:
            open(path, "w", encoding="utf-8").write(original)
        verdict = "caught  " if caught else ("equivalent" if mid in EQUIVALENT else "SURVIVED")
        print(f"{mid:>3} {verdict:<10} {desc}" + (f"  <- {caught[0]}" if caught else ""))
        if not caught and mid not in EQUIVALENT:
            survivors.append(mid)
    shutil.rmtree(work, ignore_errors=True)
    print(f"\n{len(MUTANTS) - len(survivors)} of {len(MUTANTS)} mutants caught or equivalent; survivors: {survivors or 'none'}")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
