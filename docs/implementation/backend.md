# Backend Implementation Architecture

The Incognito backend is a Node.js + Express service built in TypeScript, utilizing native Node.js SQLite (`node:sqlite` DatabaseSync) for local persistence without binary build dependencies.

---

## 1. Directory Structure

- **Server Core & Environment**:
  - [backend/server.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/server.ts): Express server bootstrap listening on port 4000.
  - [backend/app.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/app.ts): Middleware stack, security headers, route mounting, and safe error handling.
  - [backend/config/env.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/config/env.ts): Port, database path, CORS origins, and blockchain network settings.
  - [backend/db.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/db.ts): SQLite schema migration, index creation, foreign keys, and seed data.
- **Data Models**:
  - [backend/models/membership.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/membership.ts): Member records and credential commitment interfaces.
  - [backend/models/report.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/report.ts): Anonymous report schema, status enum, and moderation actions.
  - [backend/models/moderation.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/moderation.ts): Rule engine and NLP classifier configuration interfaces.
  - [backend/models/audit.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/audit.ts): Audit batch, Merkle root, and verification contracts.
  - [backend/models/security.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/security.ts): Security test assertions and posture report models.
  - [backend/models/health.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/models/health.ts): Component readiness probe schemas.
- **Business & Cryptographic Services**:
  - [backend/services/membershipService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/membershipService.ts): Member enrollment, validation, and revocation.
  - [backend/services/credentialService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/credentialService.ts): Cryptographic commitment generation and validation.
  - [backend/services/reportService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/reportService.ts): Report ingestion, nullifier duplicate checking, status lookup, and moderator query filtering.
  - [backend/services/moderationService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/moderationService.ts): Safety signal detection, urgency scoring, and policy retrieval.
  - [backend/services/auditService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/auditService.ts): Merkle tree construction, leaf hashing, and batch verification.
  - [backend/services/securityService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/securityService.ts): Automated security audit assertions runner.
  - [backend/services/healthService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/healthService.ts): Deep component health probes.
- **Route Handlers**:
  - [backend/routes/health.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/health.ts): `/health` & `/api/system/health`.
  - [backend/routes/membership.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/membership.ts): `/api/membership/status`, `/enroll`, `/validate`, `/revoke`.
  - [backend/routes/credential.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/credential.ts): `/api/credential/status`.
  - [backend/routes/reports.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/reports.ts): `/api/reports/categories`, `/reports`, `/reports/status`.
  - [backend/routes/moderator.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/moderator.ts): `/api/moderator/reports`, `/reports/:id`, `/action`, `/metrics`, `/moderation`.
  - [backend/routes/audit.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/audit.ts): `/api/audit/batches`, `/verify/:batchId`, `/status`.
  - [backend/routes/security.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/security.ts): `/api/security/tests`, `/tests/run`.
- **Testing**:
  - [backend/tests/backend.test.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/tests/backend.test.ts): 8 comprehensive automated unit and integration tests.

---

## 2. Database Schema (`incognito.sqlite`)

The database architecture guarantees zero linkage between membership verification and report submission:

```sql
-- 1. Institutional Member Registry (Identity Domain)
CREATE TABLE members (
  id TEXT PRIMARY KEY,
  member_ref TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT
);

-- 2. Credential Commitments (Separation Boundary)
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  member_id TEXT NOT NULL,
  commitment TEXT UNIQUE NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending', 'registered', 'revoked', 'expired')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  expires_at TEXT,
  FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE
);

-- 3. Anonymous Reporting Categories
CREATE TABLE categories (
  id TEXT PRIMARY KEY,
  name TEXT UNIQUE NOT NULL,
  description TEXT NOT NULL,
  risk_tier TEXT NOT NULL CHECK(risk_tier IN ('standard', 'elevated', 'urgent'))
);

-- 4. Anonymous Reports (Zero PII Columns)
CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  reference TEXT UNIQUE NOT NULL,
  status_secret_hash TEXT NOT NULL,
  category_id TEXT NOT NULL,
  encrypted_body TEXT NOT NULL,
  priority TEXT NOT NULL CHECK(priority IN ('low', 'medium', 'high', 'critical')),
  status TEXT NOT NULL CHECK(status IN ('received', 'under_review', 'moderation_review', 'assigned', 'action_taken', 'closed')),
  moderation_result TEXT NOT NULL,
  nullifier_hash TEXT UNIQUE NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  assigned_moderator TEXT,
  audit_committed INTEGER DEFAULT 0,
  audit_batch_id TEXT,
  FOREIGN KEY(category_id) REFERENCES categories(id)
);

-- 5. Moderator Actions Audit Trail
CREATE TABLE moderation_actions (
  id TEXT PRIMARY KEY,
  report_id TEXT NOT NULL,
  action TEXT NOT NULL,
  previous_status TEXT NOT NULL,
  new_status TEXT NOT NULL,
  reason TEXT NOT NULL,
  moderator_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
);

-- 6. Audit Merkle Batches
CREATE TABLE audit_batches (
  id TEXT PRIMARY KEY,
  sequence INTEGER UNIQUE NOT NULL,
  merkle_root TEXT NOT NULL,
  report_count INTEGER NOT NULL,
  status TEXT NOT NULL,
  contract_address TEXT NOT NULL,
  network TEXT NOT NULL,
  tx_hash TEXT,
  block_number INTEGER,
  created_at TEXT NOT NULL,
  published_at TEXT
);
```

---

## 3. Security & Operational Hygiene

1. **Header Hygiene**: [backend/app.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/app.ts) applies:
   - `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`
   - `Pragma: no-cache`
   - `Expires: 0`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: no-referrer`
   - Disables `x-powered-by` header
2. **Zero Request Body Logging**: The error handler logs only sanitized error messages (`err.message`), never request bodies, authorization headers, or decrypted payload contents.
3. **Idempotency & Replay Resistance**: `POST /api/reports` enforces topic nullifier uniqueness and supports `Idempotency-Key` headers.
