# Incognito — Authentication & OIDC Security Hardening Report
**Scope: Issues 1 & 2 Hardening (Authentication, Staging Equivalency, Cryptographic OIDC Integration)**

---

## 1. Previous Vulnerabilities Identified & Remaining Gaps Closed

During the thorough security audit and follow-up review of Incognito's authentication and institutional identity layers, the following issues were identified and closed:

1. **Insecure NODE_ENV Checks & Staging Discrepancies**:
   - Core security boundaries previously evaluated `if (NODE_ENV !== "production")`. In `NODE_ENV=staging`, developer bypasses, demo members, and unauthenticated routes were previously reachable.
2. **Internal Session JWT Validation Discrepancy**:
   - `generateToken` previously omitted the `aud` claim while `verifyToken` accepted missing `iss` and `aud` conditionally. Missing claims could silently bypass strict trust boundaries.
3. **Hardcoded Pseudonym Salt**:
   - `oidcService.ts` previously derived member eligibility hashes using a hardcoded public constant salt (`"incognito-institutional-domain-eligibility-salt"`), exposing cross-environment pseudonym predictability.
4. **Server-Side Semaphore Identity Generation**:
   - `credentialService.ts` generated Semaphore `Identity` instances server-side when a client commitment was absent, returning `identitySecretExport` in enrollment responses. This violated the core zero-knowledge invariant that the server must never know or transmit member identity secrets.
5. **OIDC Discovery Metadata & Error Leakage**:
   - Discovery metadata was not checked for exact issuer equality (`metadata.issuer === issuerUrl`), non-HTTPS endpoints were not rejected in deployed environments, and error handlers leaked expected issuers, audiences, and raw library internals to clients.
6. **Domain-Only Role Inference**:
   - Student eligibility was inferred solely from email domain matching without checking authoritative institutional roles/affiliations, allowing ineligible accounts (e.g. guests, alumni, contractors) to enroll.

---

## 2. Exact Fixes Implemented

### Fix 1: Universal Deployed Environment Hardening (Staging = Production)
- **Unified Environment Capabilities (`backend/config/env.ts`)**:
  - Defined explicit flags: `isProduction`, `isStaging`, `isDeployedEnv = isProduction || isStaging`, `isDevelopment`, and `allowDevAuth`.
  - Development shortcuts require two explicit prerequisites: `isDevelopment` **AND** (`ALLOW_DEV_AUTH=true` || `DEV_AUTH_ENABLED=true`).
  - Added `assertEnvironmentSecurity()` which runs during application initialization (`createApp()`):
    - Fails closed immediately if `ALLOW_DEV_AUTH` or `DEV_AUTH_ENABLED` is configured in staging or production.
    - Requires securely injected `AUTH_SECRET` (>= 32 chars, no dev placeholders) in all deployed environments.
    - Requires securely injected `ENCRYPTION_KEY` (>= 32 chars, no dev placeholders) in all deployed environments.
    - Requires securely injected `PSEUDONYM_SECRET` (>= 32 chars, no dev placeholders) in all deployed environments.
    - Requires HTTPS for `OIDC_ISSUER_URL` and `OIDC_JWKS_URI` in all deployed environments.
    - Requires `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID` in all deployed environments.

### Fix 2: Strict Internal Session JWT Validation (`backend/services/authService.ts`)
- **Explicit Constants & Claim Requirements**:
  - Defined `INTERNAL_JWT_ISSUER = "incognito-auth-service"` and `INTERNAL_JWT_AUDIENCE = "incognito-app"`.
  - Added `iss` and `aud` to `AuthClaims` and `TokenParams`.
  - `generateToken()` unconditionally injects `iss: INTERNAL_JWT_ISSUER` and `aud: INTERNAL_JWT_AUDIENCE`.
  - `verifyToken()` unconditionally requires and verifies both claims:
    - Missing issuer throws `AuthError("missing_issuer", ..., 401)`.
    - Mismatched issuer throws `AuthError("invalid_issuer", ..., 401)`.
    - Missing audience throws `AuthError("missing_audience", ..., 401)`.
    - Mismatched audience throws `AuthError("invalid_audience", ..., 401)`.
    - Future `nbf` throws `AuthError("token_not_active", ..., 401)`.
    - Expired `exp` throws `AuthError("token_expired", ..., 401)`.
    - Malformed non-JSON payload throws `AuthError("malformed_payload", ..., 401)`.
    - Tampered HMAC signatures fail constant-time comparison and throw `AuthError("invalid_signature", ..., 401)`.

### Fix 3: Secure Pseudonym Secret Management & Versioning (`backend/services/oidcService.ts`, `backend/config/env.ts`)
- **Removed Hardcoded Salt**:
  - Removed `"incognito-institutional-domain-eligibility-salt"`.
  - Securely injects `env.pseudonymSecret` / `process.env.PSEUDONYM_SECRET`.
  - In deployed environments (staging & production), missing or short (< 32 chars) secrets fail closed during startup and verification.
  - Implemented versioned derivation: `HMAC-SHA256(secret, version + ":" + domain + ":" + sub)` with `version = "v1"`.
  - Supports safe key rotation without collision or silent cross-version reference corruption.

### Fix 4: Client-Owned Semaphore Identity Architecture (`backend/services/credentialService.ts`, `backend/services/membershipService.ts`, `backend/routes/membership.ts`)
- **Removed Server-Side Identity Generation**:
  - Removed `import { Identity }` from `credentialService.ts`.
  - The client must generate and retain its Semaphore identity secret locally and submit only its public commitment.
  - Server validates scalar commitment: `isValidSemaphoreCommitment()` enforces scalar range strictly within the BN254 snark scalar field (`0 < commitment < 21888242871839275222246405745257275088548364400416034343698204186575808495617n`).
  - Missing or malformed commitments on enrollment fail closed with `400 invalid_commitment`.
  - Completely eliminated `identitySecretExport` from models (`EnrollMemberResponse`), services (`CredentialEnrollmentResult`), and HTTP route responses.

### Fix 5: Authoritative Institutional Eligibility Enforcement (`backend/services/oidcService.ts`)
- **Authoritative Role Inspection**:
  - Inspects institutional token claims: `roles`, `role`, `groups`, `affiliation`, `eduPersonAffiliation`, `eduPersonPrimaryAffiliation`.
  - Explicitly rejects ineligible roles (`guest`, `visitor`, `alumni`, `former_student`, `contractor`, `external`, `suspended`, `inactive`) with `403 ineligible_role`.
  - Enforces verified email status (`requireEmailVerified`) when required by institutional policy.
  - Strictly separates institutional identity from anonymous report records and Groth16 zero-knowledge proofs.

### Fix 6: OIDC Discovery, JWKS Validation & Error Sanitization (`backend/services/oidcService.ts`)
- **Discovery Validation**:
  - Validates `metadata.issuer === this.config.issuerUrl` (exact match; throws `discovery_issuer_mismatch`).
  - Requires HTTPS for discovery and JWKS endpoints in all deployed environments.
  - Rejects malformed metadata or non-HTTPS JWKS URIs (`invalid_jwks_uri`).
- **Generic Public Errors**:
  - Error messages across public boundaries are sanitized: zero leaked provider internals, zero leaked expected issuers/audiences, zero stack traces, and generic user-facing messages.
- **Provider Status Labeling**:
  - Live external institutional IdP integration is explicitly labeled as **unverified in deployment until configured with production credentials**. Local verification is provided via synthetic in-memory keypairs and ephemeral discovery servers.

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
