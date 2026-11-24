# Contributing to BhūmiSign

Thank you for your interest in contributing to BhūmiSign. This project implements a browser-only Public Key Infrastructure (PKI) for land-title transfers using native Web Crypto API primitives.

---

## 🏛️ Architecture Overview

The codebase is structured into three distinct layers:

1. **`src/crypto/`**: Pure Web Crypto API primitives.
   - Zero external third-party dependencies.
   - Implements ECDSA P-256 signatures, ECDH key agreement, AES-256-GCM authenticated encryption, HKDF, PBKDF2 key wrapping, generic file signing, and canonical JSON serialization.
2. **`src/pki/`**: Identity and trust governance.
   - Pinned root trust anchor, proof-of-possession (PoP) enrollment, role profiles (`ROLE_PROFILE`), and fail-closed CRL revocation.
3. **`src/land/`**: Ownership and title ledger logic.
   - Sequential title chaining, bilateral mutual consent, evidence hashing, and atomic compare-and-swap registry operations.

---

## 🚀 Extending the Project

### 1. Adding New Participant Roles
To introduce a new role (e.g., `SURVEYOR` or `AUDITOR`):
- Add the role identifier to the `Role` union type and `ROLES` array in `src/pki/types.ts`.
- Define its required and allowed usages in `ROLE_PROFILE` (`src/pki/types.ts`). A new `CertUsage` is only needed if the role exercises a novel cryptographic capability.
- Update `DEFAULT_USAGES` in `src/pki/ca.ts` and add corresponding test cases in `tests/pki.test.ts`.

### 2. Persistent Storage (Future Work)
The current `Registry` class (`src/land/registry.ts`) is an in-memory implementation designed for zero-setup browser demonstrations; `executeTransfer()` currently takes this concrete class directly. Introducing persistent backends (such as IndexedDB, OPFS, or an append-only verifiable transparency log) is planned as future architectural work.

### 3. Adding Domain Verification Rules
Custom validation predicates can be added to `src/land/validate.ts` and checked during `verifyLink()` in `src/land/verify.ts`.

---

## 🛠️ Development & Quality Standards

Every pull request must pass the full test and verification suite:

- **Type Safety**: `npm run typecheck` (strict TypeScript with `noUncheckedIndexedAccess`).
- **Unit & Integration Tests**: `npm test` (all tests passing).
- **Code Coverage**: `npm run coverage` (thresholds: $\ge 90\%$ lines/statements/functions, $\ge 80\%$ branches).
- **Mutation Verification**: `python3 scripts/mutate.py` (all mutants caught or documented equivalent).
- **OpenSSL Cross-Verification**: Verify signatures against an independent OpenSSL implementation:
  ```bash
  env DUMP=1 npx vitest run tests/scenario.test.ts
  python3 scripts/verify_with_openssl.py out/sample-root.json out/sample-certificate.json
  ```

---

## 📝 Code Conventions

- **Verification Result Types**: High-level domain verifiers (`verifyCertificate`, `verifyCrl`, `verifyLink`, `verifyHistory`) return structured `VerifyResult` (`{ ok: true } | Failure`) rather than throwing exceptions. Low-level cryptographic functions in `src/crypto/` (`verifyMessage`, `verifyFile`) return a `boolean` and never throw on malformed inputs.
- **Explicit Domain Separation**: Every signature context must have a unique, strict prefix: `BhumiSign/v1/<context>\n`.
- **Hashes Cover Bodies Only**: ECDSA signatures are malleable; identity and linking hashes must only cover canonical JSON bodies, never signatures.
