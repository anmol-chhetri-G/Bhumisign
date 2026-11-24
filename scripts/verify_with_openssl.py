#!/usr/bin/env python3
"""Independent check: verify a BhumiSign certificate signature with OpenSSL (not Web Crypto).

Usage:  python3 scripts/verify_with_openssl.py out/sample-root.json out/sample-certificate.json
"""
import base64, json, subprocess, sys, tempfile, os


def b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def der_int(raw: bytes) -> bytes:
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def p1363_to_der(sig: bytes) -> bytes:
    body = der_int(sig[:32]) + der_int(sig[32:])
    return b"\x30" + bytes([len(body)]) + body


def canonical(obj) -> str:  # same rules as src/crypto/canonical.ts for our (ASCII, integer-only) data
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def openssl_verify(issuer_spki: str, body: dict, signature: str, context: str) -> bool:
    with tempfile.TemporaryDirectory() as d:
        der, pem, sig, msg = (os.path.join(d, n) for n in ("k.der", "k.pem", "s.der", "m.bin"))
        open(der, "wb").write(b64u(issuer_spki))
        subprocess.run(["openssl", "pkey", "-pubin", "-inform", "DER", "-in", der, "-out", pem], check=True)
        open(sig, "wb").write(p1363_to_der(b64u(signature)))
        open(msg, "wb").write(f"BhumiSign/v1/{context}\n{canonical(body)}".encode())
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", pem, "-signature", sig, msg],
                           capture_output=True, text=True)
        return r.returncode == 0 and "Verified OK" in r.stdout


root = json.load(open(sys.argv[1]))
cert = json.load(open(sys.argv[2]))
print("root self-signature :", openssl_verify(root["body"]["signKey"], root["body"], root["signature"], "cert"))
print("certificate         :", openssl_verify(root["body"]["signKey"], cert["body"], cert["signature"], "cert"))
cert["body"]["subject"]["name"] += "x"
print("tampered certificate:", openssl_verify(root["body"]["signKey"], cert["body"], cert["signature"], "cert"), "(expected False)")
