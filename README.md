# Incognito — Privacy Infrastructure Platform
> **Speak Without Being Seen.** Institutional privacy, separated verification, and cryptographic auditing.

Incognito separates institutional membership verification from report submission. Eligible members obtain a privacy-preserving credential to submit sensitive safety, academic, or conduct concerns without attaching their student ID, staff account, or network identity to the reporting database.

---

## Architecture & Implementation Documentation

- [System Architecture Overview](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/architecture/overview.md): High-level system topology and domain boundaries.
- [Frontend Implementation Guide](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/implementation/frontend.md): Component structure, routing, design system, and accessibility.
- [Backend Implementation Guide](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/implementation/backend.md): Express services, native SQLite schema, and security headers.
- [Cryptographic Specifications](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/implementation/cryptography.md): Identity commitments, topic nullifiers, and Merkle tree proofs.
- [API Reference & Endpoints](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/api/endpoints.md): Complete REST endpoint contracts and parameters.
- [Threat Model & Security Disclosures](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/security/threat-model.md): Adversary assumptions, defenses, and technical limitations.
- [Local Development & Setup Guide](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/development/setup.md): Environment configuration and testing instructions.

---

## Key Platform Capabilities

1. **Identity Decoupling**: Institutional Single Sign-On confirms membership status via [backend/routes/membership.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/routes/membership.ts); the reporting gateway receives only anonymous cryptographic proofs.
2. **Topic-Scoped Nullifiers**: Prevents duplicate submissions within the same incident scope via [backend/services/reportService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/reportService.ts) without linking reports across different topics.
3. **Encrypted Storage**: Reports are encrypted at rest with authenticated AES-256-GCM.
4. **AI Safety Moderation**: Automated rule engine + NLP classifier evaluates urgency and hazard signals via [backend/services/moderationService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/moderationService.ts).
5. **Tamper-Evident Blockchain Audits**: Batch commitments are constructed as deterministic SHA-256 Merkle trees anchored to Sepolia contracts via [backend/services/auditService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/auditService.ts).
6. **Single-View Status Secrets**: Reporters receive a random public reference (`INC-XXXXXX`) and a high-entropy secret (`sec_xxxxxxxx`) stored exclusively in client memory and hashed with SHA-256 on the server.

---

## Project Structure & File Reference

```text
incognito-v2/
├── backend/
│   ├── app.ts                  # Express application with security headers
│   ├── server.ts               # Server bootstrap on port 4000
│   ├── db.ts                   # SQLite schema initialization and seed data
│   ├── config/env.ts           # Runtime environment parameters
│   ├── models/                 # TypeScript data contracts
│   │   ├── membership.ts       # Member and credential models
│   │   ├── report.ts           # Report, category, and action models
│   │   ├── moderation.ts       # AI moderation policy models
│   │   ├── audit.ts            # Merkle tree and audit batch models
│   │   ├── security.ts         # Automated security test models
│   │   └── health.ts           # System component readiness models
│   ├── routes/                 # Express route controllers
│   │   ├── health.ts           # /health and /api/system/health
│   │   ├── membership.ts       # /api/membership/*
│   │   ├── credential.ts       # /api/credential/*
│   │   ├── reports.ts          # /api/reports, /categories, /status
│   │   ├── moderator.ts        # /api/moderator/reports, /action, /metrics
│   │   ├── audit.ts            # /api/audit/batches, /verify/:id
│   │   └── security.ts         # /api/security/tests, /tests/run
│   ├── services/               # Cryptographic & business logic
│   │   ├── membershipService.ts# Member enrollment & validation
│   │   ├── credentialService.ts# Cryptographic commitment generation
│   │   ├── reportService.ts    # Anonymous report ingestion & querying
│   │   ├── moderationService.ts# Safety signal detection & rules
│   │   ├── auditService.ts     # Merkle root calculation & verification
│   │   ├── securityService.ts  # Automated security assertions runner
│   │   └── healthService.ts    # Component health telemetry
│   └── tests/
│       └── backend.test.ts     # 8 backend unit and integration tests
│
├── src/
│   ├── api/
│   │   ├── client.ts           # Typed API client with normalized ApiError
│   │   ├── types.ts            # Frontend TypeScript data interfaces
│   │   └── services.ts         # Unified service layer
│   ├── components/
│   │   ├── ui.tsx              # Reusable UI primitives (StatusBadge, PageHeader, etc.)
│   │   ├── Layouts.tsx         # PublicHeader, PublicLayout, DashboardLayout
│   │   ├── TrustBoundaryDiagram.tsx # Interactive trust boundary diagram
│   │   └── AuditPipelineDiagram.tsx # 6-stage off-chain to on-chain pipeline
│   ├── pages/
│   │   ├── Public.tsx          # Landing, HowItWorks, Security, Help, Privacy
│   │   ├── Enroll.tsx          # Multi-step eligibility & credential UI
│   │   ├── Report.tsx          # Report wizard, Submitted receipt, Status lookup
│   │   ├── Moderator/          # Staff console
│   │   │   ├── ModeratorDashboard.tsx # Overview metrics & recent queue
│   │   │   ├── ReportQueue.tsx        # Searchable, filterable queue table
│   │   │   ├── ReportReview.tsx       # Two-panel review & action execution
│   │   │   └── ModerationPolicies.tsx # Active safety rules & NLP config
│   │   └── Admin/              # Admin console
│   │       ├── AdminDashboard.tsx     # Infrastructure telemetry overview
│   │       ├── AuditDashboard.tsx     # Merkle batches & live proof verifier
│   │       ├── SecurityTests.tsx      # Automated security test runner
│   │       └── SystemHealth.tsx       # Component readiness probes
│   ├── styles/
│   │   ├── tokens.css          # Institutional color, surface, and radius tokens
│   │   └── global.css          # Global accessible styles, buttons, and tables
│   ├── tests/
│   │   └── frontend.test.ts    # 6 frontend unit and contract tests
│   ├── App.tsx                 # Full route declarations
│   └── main.tsx                # Client entry point
│
├── docs/                       # Technical architecture & implementation guides
├── .gitignore                  # Git ignore rules for node, sqlite, dist, and logs
├── index.html                  # HTML entry point
├── vite.config.ts              # Vite config with backend proxy on /api
└── package.json                # Project dependencies and test scripts
```

---

## Git & Repository Configuration

The repository includes a comprehensive [.gitignore](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/.gitignore) configured for institutional security:
- **Database Isolation**: Ignores `*.sqlite`, `*.sqlite-wal`, `*.db`, and `incognito.sqlite` to prevent committing operational report records.
- **Environment & Secrets**: Ignores `.env`, `.env.local`, and custom deployment environment files.
- **Build Artifacts**: Ignores `node_modules/`, `dist/`, and build caches.
- **Log Hygiene**: Ignores all log outputs (`*.log`, `npm-debug.log`).

> **Note**: This project is maintained locally and is not connected to any remote repository.

---

## Quick Start & Local Execution

### 1. Install Dependencies
```bash
npm install
```

### 2. Start the Backend API Server
Runs on `http://localhost:4000`:
```bash
npm run server
```

### 3. Start the Frontend Development Server
Runs on `http://localhost:5173` with automated reverse-proxying of `/api` and `/health` to port 4000:
```bash
npm run dev
```

### 4. Build for Production
Compiles TypeScript and produces an optimized static bundle in `dist/`:
```bash
npm run build
```

---

## Test Execution

Run all automated test suites (14 tests total):
```bash
npm test
```

### Backend Tests (`npm run test:backend`)
Tests run using the native Node.js test runner in [backend/tests/backend.test.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/tests/backend.test.ts):
1. **System Health Report**: Probes operational components across API, database, and membership services.
2. **Membership & Credential Lifecycle**: Verifies initial enrollment, rejection of duplicates, validation, and revocation.
3. **Anonymous Report Submission & Separation**: Asserts that reports require valid bodies (20-5000 chars), generates random `INC-` references and `sec_` secrets, enforces topic-scoped duplicate rejection, and validates status lookup.
4. **Moderator Queue & Review Actions**: Tests case retrieval, detailed payload inspection, and status transitions with audit logging.
5. **Moderation Rule Engine & NLP Classifier**: Asserts that hazard and safety signals trigger priority escalation.
6. **Audit Batches & Merkle Root Verification**: Validates deterministic SHA-256 Merkle tree calculation and proof verification.
7. **Security & Privacy Assertions**: Inspects live database schema confirming zero identity columns (`student_id`, `email`, `ip_address`).

### Frontend Tests (`npm run test:frontend`)
Tests run in [src/tests/frontend.test.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/tests/frontend.test.ts):
1. **Normalized API Errors**: Confirms `ApiError` code mapping.
2. **Character Bounds Validation**: Asserts 20-character minimum and 5000-character maximum limits.
3. **Prohibited Copy Audit**: Scans source code ensuring zero unsupported claims (such as "100% anonymous" or "completely untraceable").
4. **Protocol Lifecycle Ordering**: Asserts correct sequential progression across investigation stages.
5. **Secret Hygiene**: Verifies that access secrets are never exposed in URL query parameters or persisted in local storage.
