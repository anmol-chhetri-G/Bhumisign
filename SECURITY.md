# Security Policy for BhūmiSign

## 🛡️ Supported Versions

BhūmiSign is an educational and reference prototype demonstrating client-side cryptographic protocols for land-title provenance.

| Version | Supported |
|---|---|
| 0.1.x | Yes |

---

## 🔒 Security Invariants & Boundaries

BhūmiSign implements the following design guarantees and threat assumptions:

1. **Trust Anchor Pinning**: In production deployments, the root certificate must be distributed out-of-band (e.g., pinned in the client application package or platform trust store). In the browser demo (`scenario.ts`), a root CA is generated at setup and supplied as the pinned `anchor` within that session's `TrustContext`; substituted anchors are rejected.
2. **Domain-Separated Cryptography**: Every signature payload is explicitly prefixed with `BhumiSign/v1/<context>\n` to prevent cross-protocol signature substitution.
3. **Fail-Closed Revocation**: Missing, stale, or forged Certificate Revocation Lists (CRLs) cause certificate verification to fail closed.
4. **As-of-Issuance Time Semantics**: Signatures and certificates are evaluated as of the registry-attested issuance timestamp, preventing signers from bypassing revocation using back-dated claims.
5. **Single-Instance Atomic Compare-and-Swap**: Double-sale race conditions are prevented within a single execution instance of the in-memory `Registry` by validating chain continuity synchronously before updating state. Distributed multi-node consensus and Byzantine fault tolerance are out of scope.

### Documented Threat Boundaries
- **In-Memory Ledger**: The prototype registry resides client-side in browser memory without persistent replication. An operator cannot forge bilateral consent, but could withhold recent records from verifiers.
- **Client Runtime Limits**: JavaScript runtimes cannot guarantee constant-time execution, memory zeroization, or protection against compromised browser extensions.
- **Identity Proofing**: Physical identity verification is simulated via `subject.id`.

---

## 🐛 Reporting a Vulnerability

If you discover a security vulnerability in BhūmiSign, please report it privately:

- **Channel**: Submit a private advisory via GitHub Security Advisories on this repository or contact the maintainer through their GitHub profile ([@anmol-chhetri-G](https://github.com/anmol-chhetri-G)).
- Please include reproduction steps, affected functions, and test evidence if available.
