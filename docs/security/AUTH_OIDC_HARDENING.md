# Incognito — Authentication & OIDC Security Hardening Report
**Scope: Issues 1 & 2 Hardening (Authentication, Staging Equivalency, Cryptographic OIDC Integration)**

---

## 1. Previous Vulnerabilities Identified

During the rigorous security review of Incognito's authentication and institutional identity layers, the following architectural weaknesses and development shortcuts were identified:

1. **Insecure NODE_ENV Checks Allowing Staging Shortcuts**:
   - Multiple core security boundaries previously checked `if (NODE_ENV !== "production")` or `if (NODE_ENV === "production")`.
   - Consequently, in `NODE_ENV=staging`, the backend:
     - Permitted development token issuance (`/api/auth/dev-token`).
     - Allowed unauthenticated requests to fall back to `"demo-member-01"` or caller-controlled `x-member-ref`, `req.query.ref`, and `req.body.memberRef`.
     - Allowed reports to be submitted without cryptographic zero-knowledge proofs.
     - Allowed member revocation without verified administrator authorization.
     - Seeded mock demo members into storage.

2. **Caller-Controlled Member References on Protected Routes**:
   - Routes `GET /membership/status`, `POST /membership/enroll`, and `GET /credential/status` accepted caller-supplied identity values when unauthenticated in non-production environments.

3. **Weak OIDC Verification & Hardcoded Fallback Secrets**:
   - `oidcService.ts` previously relied on manual string splitting (`idToken.split(".")`) and custom HMAC signature verification with a hardcoded fallback secret (`"institutional-oidc-signing-secret-key-32b!"`).
   - Algorithmic rotation and dynamic JWKS discovery from institutional Identity Providers (`/.well-known/openid-configuration`) were absent.
   - Deployed environments did not fail closed if OIDC configuration was missing.
   - Institutional OIDC token verification was not natively integrated into the real `/membership/enroll` and authentication session flows.

---

## 2. Exact Fixes Implemented

### Fix 1: Universal Deployed Environment Hardening (Staging = Production)
- **Unified Environment Capabilities (`backend/config/env.ts`)**:
  - Defined explicit flags: `isProduction`, `isStaging`, `isDeployedEnv = isProduction || isStaging`, `isDevelopment`, and `allowDevAuth`.
  - Development shortcuts require **two explicit prerequisites**: `isDevelopment` **AND** (`ALLOW_DEV_AUTH=true` || `DEV_AUTH_ENABLED=true`).
  - Added `assertEnvironmentSecurity()` which runs during application initialization (`createApp()`):
    - **Fails closed immediately** (throws fatal exception and refuses to start) if `ALLOW_DEV_AUTH` or `DEV_AUTH_ENABLED` is configured in staging or production.
    - Requires securely injected `AUTH_SECRET` (>= 32 chars, no dev placeholders) in all deployed environments.
    - Requires securely injected `ENCRYPTION_KEY` (>= 32 chars, no dev placeholders) in all deployed environments.
    - Requires `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID` in all deployed environments.

### Fix 2: Complete Elimination of Development Shortcuts in Deployed Environments
- **`/api/auth/dev-token` Endpoint (`backend/app.ts`)**:
  - Now strictly checks `isDeployed` and `devAuthAllowed`. If called in staging, production, or in development without explicit `ALLOW_DEV_AUTH=true`, it immediately responds with `403 dev_auth_disabled`.
- **Membership & Credential Resolution (`backend/routes/membership.ts`, `backend/routes/credential.ts`)**:
  - `resolveMemberRef(req)` now requires cryptographic authentication (either an internal Bearer JWT or institutional OIDC ID token).
  - In all deployed environments (`env.isDeployedEnv`), unauthenticated requests **fail closed immediately** with `401 unauthenticated`.
  - Caller-supplied identifiers (`x-member-ref`, `req.query.ref`, `req.body.memberRef`) and `"demo-member-01"` are completely ignored in staging and production.
- **Member Revocation Route (`backend/routes/membership.ts`)**:
  - `POST /membership/revoke` enforces administrator Bearer authentication in all deployed environments (`env.isDeployedEnv`). Unauthenticated requests receive `401`, non-admins receive `403`.
- **Mandatory ZK Proofs in Staging (`backend/services/reportService.ts`)**:
  - Report submission now checks `isDeployed`. Submissions without a valid Semaphore Groth16 ZK proof in staging or production are rejected with `400 invalid_proof`.
- **Database Seeding Isolation (`backend/db.ts`)**:
  - Seeding of `"demo-member-01"` is strictly isolated to local development when `ALLOW_DEV_AUTH=true` is enabled. It is never executed in staging or production.
- **Mock Authentication Provider Isolation (`backend/services/authService.ts`)**:
  - `MockAuthProvider` fails closed and refuses instantiation in all deployed environments (`env.isDeployedEnv`).

### Fix 3: Cryptographic Institutional OIDC Verification with `jose`
- **Replaced Custom Verification with Maintained Standard Library**:
  - Completely rewritten using `jose` (v6.2.12).
  - Removed all hardcoded fallback signing secrets and symmetric development defaults.
  - Deployed environments strictly fail closed if OIDC configuration is absent.
- **Dynamic Discovery & JWKS Caching with Key Rotation**:
  - Discovers trusted provider metadata dynamically via `${issuerUrl}/.well-known/openid-configuration` if `jwksUri` is not explicitly set.
  - Utilizes `jose.createRemoteJWKSet(new URL(jwksUri), { cacheMaxAge: 600000, cooldownDuration: 30000 })`.
  - Seamlessly handles **signing-key rotation**: when a token arrives with an unknown `kid`, the remote keyset automatically initiates a cache refresh before evaluating.
- **Strict JWT Verification Boundary**:
  - Cryptographically verifies RSA / ECDSA signatures against the keyset.
  - Rejects `alg: "none"`, unsigned tokens, and algorithms outside the institutional allowlist (`["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"]`).
  - Verifies exact issuer (`iss`), client ID audience (`aud`), expiration (`exp`), and not-before (`nbf`).
- **Institutional Domain & Role Eligibility**:
  - Validates account domain against configured `allowedEmailDomains`.
  - Optional `requireEmailVerified` enforcement for IdPs providing email verification claims.
  - Derives role (`student`, `staff`, `faculty`) from verified institutional claims.
- **Zero-PII Identity Barrier**:
  - Derives a deterministic one-way HMAC pseudonym hash: `HMAC-SHA256(salt, domain + ":" + sub)`.
  - Student names, email addresses, and real student IDs are **never** logged, transmitted, or stored in the membership or reporting pipelines.

### Fix 4: Real OIDC Enrollment & Authentication Flow Integration
- **`POST /api/auth/oidc/verify`**:
  - Accepts `{ idToken }` or `Authorization: Bearer <idToken>`.
  - Performs full cryptographic OIDC verification and eligibility check.
  - Issues an authenticated member session JWT bound to the anonymous eligibility hash.
- **`POST /membership/enroll`**:
  - Accepts institutional OIDC `idToken` directly or an authenticated session token.
  - Binds the Semaphore client commitment to the verified member record without exposing student PII.

---

## 3. Authentication Architecture & OIDC Trust Model

```
+-------------------------------------------------------------+
|                   Institutional IdP (OIDC)                  |
|    - Authenticates Student / Staff                          |
|    - Issues Signed ID Token (RS256/ES256)                   |
|    - Hosts /.well-known/openid-configuration & JWKS URI      |
+-------------------------------------------------------------+
                               |
                               | ID Token (OIDC)
                               v
+-------------------------------------------------------------+
|               Incognito Backend OIDC Service                |
|    - Resolves JWKS from Discovery / Cache with Key Rotation |
|    - Cryptographically verifies signature with jose         |
|    - Validates iss, aud, exp, nbf, and institutional domain  |
|    - Rejects alg:none, unsigned, tampered, expired tokens   |
+-------------------------------------------------------------+
                               |
                               | Eligibility Verified (No PII)
                               v
+-------------------------------------------------------------+
|               Zero-PII Identity Separation Barrier          |
|    - Derives one-way pseudonym: HMAC-SHA256(salt, dom:sub)  |
|    - Drops student name, email, student ID                  |
+-------------------------------------------------------------+
                               |
                               | Eligibility Hash
                               v
+-------------------------------------------------------------+
|                  Anonymous Enrollment Flow                  |
|    - Enrolls client Semaphore Commitment into Group Tree    |
|    - Zero relationship between Institutional Id & Commitment|
+-------------------------------------------------------------+
                               |
                               | Client-side Groth16 ZK Proof
                               v
+-------------------------------------------------------------+
|                 Report Submission Pipeline                  |
|    - Verifies Semaphore Proof against Merkle Root           |
|    - Checks Nullifier uniqueness (atomic consume)           |
|    - Encrypts report with authenticated AES-256-GCM         |
|    - ZERO OIDC identity in report record                    |
+-------------------------------------------------------------+
```

---

## 4. Route Authorization Matrix

| Endpoint | HTTP Method | Authentication Requirement | Authorized Roles / Principals | Unauthorized Response |
| :--- | :--- | :--- | :--- | :--- |
| `/api/health` | `GET` | Public | Any client | None |
| `/api/auth/dev-token` | `POST` | Development Only (`ALLOW_DEV_AUTH=true`) | Development client | `403 Forbidden` in deployed environments |
| `/api/auth/oidc/verify` | `POST` | Institutional OIDC ID Token | Eligible institutional student/staff | `401 Unauthenticated` / `403 Forbidden` |
| `/api/membership/status` | `GET` | Authenticated Bearer JWT or OIDC Token | Authenticated member | `401 Unauthenticated` |
| `/api/membership/enroll` | `POST` | Authenticated Bearer JWT or OIDC Token | Eligible institutional member | `401 Unauthenticated` / `403 Forbidden` |
| `/api/membership/revoke` | `POST` | Cryptographically Verified Admin JWT | Administrator (`role: "admin"`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/membership/validate` | `POST` | Authenticated Bearer JWT or OIDC Token | Authenticated member | `401 Unauthenticated` |
| `/api/credential/status` | `GET` | Authenticated Bearer JWT or OIDC Token | Authenticated member | `401 Unauthenticated` |
| `/api/reports` | `POST` | Cryptographic Semaphore Groth16 ZK Proof | Anonymous group member | `400 Bad Request (invalid_proof)` |
| `/api/reports/status` | `POST` | 128-bit Status Secret + Reference | Report owner | `400 Bad Request` / `404 Not Found` |
| `/api/reports/:id/identity` | `ALL` | Prohibited Operation | None (Architecturally forbidden) | `403 Forbidden` |
| `/api/moderator/reports` | `GET` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/moderator/reports/:id` | `GET` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/moderator/reports/:id/action` | `POST` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/moderator/metrics` | `GET` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/security/tests` | `GET`/`POST` | Cryptographically Verified Admin JWT | Administrator (`role: "admin"`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/audit/batches` | `GET` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |
| `/api/audit/verify/:batchId` | `POST` | Cryptographically Verified Staff JWT | Moderator or Admin (`moderator`, `admin`) | `401 Unauthenticated` / `403 Forbidden` |

---

## 5. Security Invariants Verification Summary

1. **Staging is Security-Equivalent to Production**:
   - `assertEnvironmentSecurity()` enforces identical security invariant checks on both staging and production.
   - Bypasses of authentication, authorization, ZK proofs, or membership revocation are strictly blocked in staging.
2. **Caller-Controlled Values Cannot Establish Identity**:
   - `req.body.memberRef`, `req.query.ref`, `x-member-ref`, and `demo-member-01` are completely ignored for identity establishment in deployed environments.
3. **Client Headers Cannot Establish Role**:
   - `X-Staff-Role` is completely ignored; authorization is derived strictly from server-side cryptographic JWT verification.
4. **Missing Authentication Never Creates a Fallback Identity**:
   - Requests without valid bearer credentials receive `401 unauthenticated`.
5. **Cryptographic JWT & OIDC Verification**:
   - Signatures, algorithms, issuers, audiences, expiration, and not-before are verified with standard cryptography.
   - Algorithms `none`, symmetric fallback secrets, and mismatched keysets are rejected.
6. **Key Rotation & JWKS Resilience**:
   - Dynamic keyset resolution with caching and automatic key refresh on unknown `kid`.
7. **Identity Separation Preserved**:
   - Zero institutional identity details (name, email, subject) are attached to submitted reports.

---

## 6. Tests Added & Executed

A dedicated security hardening suite (`backend/tests/authOidcSecurity.test.ts`) was implemented and added to the automated test pipeline, executing 8 comprehensive test suites:

1. **Environment Safety & Startup Guards**:
   - Verifies `ALLOW_DEV_AUTH=true` crashes startup in staging and production.
   - Verifies missing OIDC configuration crashes startup in staging and production.
2. **Dev Token Endpoint Environment Enforcement**:
   - Verifies `/api/auth/dev-token` works ONLY when `ALLOW_DEV_AUTH=true` in development.
   - Verifies `/api/auth/dev-token` is rejected with `403` in development when flag is missing.
   - Verifies `/api/auth/dev-token` is rejected with `403` in staging.
   - Verifies `/api/auth/dev-token` is rejected with `403` in production.
3. **Membership Routes Caller-Controlled Identity & Demo Fallback Rejection**:
   - Tests `GET /membership/status`, `GET /credential/status`, `POST /membership/enroll`, and `POST /membership/revoke` against staging and production.
   - Proves caller-supplied `x-member-ref`, query params, and body references return `401`.
   - Proves unauthenticated requests never fall back to `"demo-member-01"`.
   - Proves non-admin member revocation receives `403`.
4. **ZK Proof Enforcement in Staging**:
   - Proves report submission without ZK proof fails with `400 invalid_proof` in staging.
5. **Moderator & RBAC Header Forgery Rejection**:
   - Proves forged `X-Staff-Role` headers are rejected with `401`.
   - Proves moderator tokens cannot access admin endpoints (`403`).
   - Proves admin tokens succeed (`200`).
6. **JWT Signature, Algorithm & Claims Verification**:
   - Valid signed token succeeds.
   - Modified payload fails signature validation (`invalid_signature`).
   - Tampered signature fails (`invalid_signature`).
   - Algorithm `none` fails (`invalid_algorithm`).
   - Wrong algorithm fails (`invalid_algorithm`).
   - Expired token fails (`token_expired`).
   - Wrong issuer fails (`invalid_issuer`).
   - Wrong audience fails (`invalid_audience`).
   - Missing required claims fails (`invalid_claims`).
   - Malformed JWT fails (`malformed_token`).
7. **Institutional OIDC Verification with `jose`, JWKS & Key Rotation**:
   - Valid institutional token succeeds and derives zero-PII pseudonym hash.
   - Unknown key ID fails (`unknown_key_id`).
   - Key rotation: rotated key succeeds once present in JWKS.
   - Expired OIDC token fails (`token_expired`).
   - Wrong issuer fails (`invalid_issuer`).
   - Wrong audience fails (`invalid_audience`).
   - Unauthorized domain fails (`unauthorized_domain`).
   - Unavailable JWKS fails safely (`provider_unavailable`, HTTP 503).
8. **End-to-End OIDC Verification & Enrollment Route Integration**:
   - Full HTTP flow: `POST /api/auth/oidc/verify` -> verified session token -> `POST /membership/enroll` with Semaphore client commitment -> `GET /credential/status` -> anonymous report submission with Semaphore ZK proof -> `GET /reports/:id/identity` verified strictly forbidden (`403`).

### Complete Test Results Summary:
- **Backend Tests (`npm run test:backend`)**: **97 / 97 passing** (0 failures, duration ~27s).
- **Frontend Tests (`npm run test:frontend`)**: **6 / 6 passing** (0 failures).
- **Blockchain Tests (`npm run blockchain:test`)**: **5 / 5 passing** (0 failures).
- **TypeScript & Production Build (`npm run build`)**: **1521 modules transformed, 0 TypeScript errors, build clean**.

---

## 7. Remaining Limitations & Operational Considerations

1. **External IdP Availability**:
   - Institutional user authentication depends on the availability of the external university/enterprise identity provider. If the IdP is unreachable, the system fails closed (HTTP 503 `provider_unavailable`) without degrading security.
2. **Key Rotation Propagation Delay**:
   - In accordance with OIDC specifications, new signing keys published by the IdP may take up to the configured cooldown duration (30 seconds) to be fetched if a rapid series of unknown key IDs occurs, protecting against JWKS endpoint cache-stampede DoS.
3. **Reporter Free-Text Privacy**:
   - Cryptographic identity separation prevents systemic linking between reports and institutional accounts; however, the platform cannot prevent users from voluntarily including self-identifying details in the report body prose (mitigated via frontend privacy advisories and AI PII scrubbing).
