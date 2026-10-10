# Incognito API Reference

Base URL (Dev): `http://localhost:4000` (or `/api` via Vite dev proxy on `http://localhost:5173`).

## Health & Telemetry
- `GET /health` / `GET /api/health`: System component readiness probes (API, Database, Membership, Moderation, Audit, Blockchain).

## Membership & Verification
- `GET /api/membership/status?ref={memberRef}`: Return active status and credential status.
- `POST /api/membership/enroll`: Register member and generate credential commitment.
- `POST /api/membership/validate`: Authoritatively validate active credential.
- `POST /api/membership/revoke`: Administrative credential revocation.
- `GET /api/credential/status`: Query caller credential state.

## Reporting Gateway
- `GET /api/reports/categories`: List reporting categories and risk tiers.
- `POST /api/reports`: Submit encrypted anonymous report.
  - Body: `{ categoryId: string, body: string, proofNullifier?: string }`
  - Headers: `Idempotency-Key: <UUID>`
  - Returns: `{ reference: string, status: string, statusSecret: string, priority: string }`
- `POST /api/reports/status`: Authenticated status lookup.
  - Body: `{ reference: string, statusSecret: string }`

## Moderation Console
- `GET /api/moderator/reports`: List reports with query filters (`status`, `categoryId`, `priority`, `search`).
- `GET /api/moderator/reports/:id`: Retrieve single report with decrypted narrative and timeline.
- `POST /api/moderator/reports/:id/action`: Execute moderation action (`confirm`, `reclassify`, `escalate`, `request_review`, `close`).
- `GET /api/moderator/metrics`: Aggregate counts (total, received, under review, closed, flagged).
- `GET /api/moderation/policies`: Active rule engine rules, NLP model parameters, and metrics.

## Cryptographic Audit
- `GET /api/audit/batches`: List committed Merkle batches.
- `POST /api/audit/verify/:batchId`: Independently recompute Merkle root and verify match.
- `GET /api/audit/status`: Off-chain queue status and next scheduled batch.

## Security Test Runner
- `GET /api/security/tests`: Retrieve recent security posture test scan.
- `POST /api/security/tests/run`: Execute live test suite against database and transport layers.
