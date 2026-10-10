# Incognito — Architecture & Identity Separation Specification
**Classification**: Security Architecture Document  
**Version**: 2.2  
**Status**: Implemented  

---

## 1. Core Trust Boundary & Separation Principle

The paramount design goal of **Incognito** is that no institutional administrator, database administrator, network observer, or compromised subsystem can associate a submitted report with the individual who authored it.

```text
                  ┌──────────────────────────────────────────────┐
                  │          College Identity Domain             │
                  │  - Real Student / Staff Identity             │
                  │  - SSO / Institutional JWT Session           │
                  └──────────────────────┬───────────────────────┘
                                         │
                             authenticated enrollment
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │       Credential / Group Issuance            │
                  │  - Registers public commitment to Tree Root R│
                  │  - Private Identity held ONLY by Member      │
                  └──────────────────────────────────────────────┘
                                         │
                        [ STRICT ARCHITECTURAL AIR-GAP ]
                  Zero Shared Identifiers / Zero Database Joins
                  No /reports/:id/identity mapping API permitted
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │        Anonymous Reporting Gateway           │
                  │  - Unauthenticated endpoint (No Student SSO) │
                  │  - Accepts Groth16 Semaphore ZK Proof        │
                  │  - Topic-Scoped External Nullifiers          │
                  │  - Authenticated AES-256-GCM Payload at Rest │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────────┐
                  │          Encrypted Report Storage            │
                  │  Columns: id, reference, status_secret_hash, │
                  │  category_id, encrypted_body, priority,      │
                  │  status, moderation_result, nullifier_hash   │
                  │  (NO student_id, NO member_id, NO IP)        │
                  └──────────────────────────────────────────────┘
```

---

## 2. Six Pillars of Identity Separation

### Pillar 1: Zero Identity Columns in Report Storage
The `reports` table in SQLite contains **zero foreign keys** or relational links to `members` or `credentials`:
- No `member_id`
- No `student_id`
- No `email`
- No `ip_address`
- No `user_agent`
- No `session_id`

An SQL `JOIN` between reports and members is structurally impossible because no matching foreign key exists.

### Pillar 2: Distinct Session Contexts
- **Enrollment Phase**: Requires standard institutional login (`Authorization: Bearer <token>`). The user registers their public `identityCommitment` in the membership tree and downloads their private credential secret export. The session terminates.
- **Reporting Phase**: Completely decoupled from institutional authentication. The client makes an unauthenticated HTTP `POST /api/reports` carrying only the zero-knowledge proof, topic scope, and encrypted body. Ordinary student auth tokens are neither sent nor accepted.

### Pillar 3: Prohibition of Identity Lookup Endpoints
Both `reportsRouter` and `moderatorRouter` explicitly prohibit identity inspection. Any request to:
- `GET /api/reports/:id/identity`
- `GET /api/moderator/reports/:id/identity`

immediately yields `403 Forbidden` (`forbidden_operation`). No code or SQL query exists to resolve a report back to a student.

### Pillar 4: Topic-Scoped External Nullifiers
Nullifiers are derived via Semaphore v4 as:
$$\text{Nullifier} = \text{Poseidon}(\text{nullifierSecret}, \text{scope})$$
- Even if a student files reports in two different categories (e.g. `cat-safety` and `cat-harassment`), the two nullifiers are mutually uncorrelated random outputs on the BN254 curve.
- No observer can link distinct reports back to the same author.

### Pillar 5: KeyProvider Abstraction & KMS Enforcement
Cryptographic key management is abstracted into the `KeyProvider` interface:
```text
KeyProvider
    ├── DevelopmentKeyProvider (ephemeral development session entropy)
    └── ProductionKMSProvider (strict validation: >= 32 bytes from KMS/vault)
```
- In production, missing, default, or insecure keys cause immediate startup termination (fail-closed).
- Report contents are encrypted at rest with authenticated `AES-256-GCM` using 12-byte IVs and 16-byte authentication tags.

### Pillar 6: High-Entropy Status Secrets
- Status tracking does **not** rely on student authentication.
- Instead, each submission generates a high-entropy tracking secret ($\ge 128$ bits of cryptographic entropy: `"sec_" + 32 hex chars`).
- The server stores only the SHA-256 hash of this secret.
- Verification uses constant-time comparison (`crypto.timingSafeEqual`) to defend against timing side-channel attacks.
- Status secrets are never placed in URLs, HTTP referrers, or unencrypted local storage.

---

## 3. Metadata Minimization & Logging Policy

1. **Request Headers**: No `User-Agent`, `Referer`, or client device fingerprints are stored.
2. **Gateway Logs**: Request bodies, credentials, proofs, and status secrets are strictly excluded from all application loggers.
3. **HTTP Security Headers**:
   - `Cache-Control: no-store, no-cache, must-revalidate`
   - `X-Frame-Options: DENY`
   - `Content-Security-Policy: default-src 'self'`
   - `Referrer-Policy: no-referrer`
   - `X-Content-Type-Options: nosniff`

---

## 4. Implementation Status Breakdown

### Implemented
- Physical and logical separation between institutional members and reports.
- Zero identity columns / zero foreign keys in the `reports` schema.
- Explicit `403 Forbidden` rejection on `/reports/:id/identity` routes.
- `KeyProvider` abstraction (`DevelopmentKeyProvider` and `ProductionKMSProvider`).
- Fail-closed production KMS enforcement.
- Authenticated AES-256-GCM encryption with timing-safe status secret comparison.
- Strict logging filters redacting request bodies, authorization tokens, and credentials.

### Partial
- Single SQLite instance in development; production environments should deploy physically separate database instances for the Institutional Identity Service and the Anonymous Reporting Gateway.

### Simulated
- None.

### Not Implemented
- Blind signatures for issuance (Semaphore Groth16 membership proofs provide sufficient anonymity set without requiring blind signature schemes).
