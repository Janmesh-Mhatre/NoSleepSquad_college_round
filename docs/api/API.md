# Incognito — Backend API Reference

## 1. Overview & Security Rules

All Incognito API endpoints enforce:
- **No-Cache & Security Headers**: Strict `no-store, no-cache`, `X-Content-Type-Options: nosniff`, and strict CSP.
- **Payload Limits**: JSON bodies strictly capped at `64kb`.
- **Zero Identity Egress**: Endpoints never accept or return student IDs, emails, or personal identifiers.
- **Identity Lookup Prohibition**: Requests to `/api/moderator/reports/:id/identity` return HTTP `403 Forbidden` with an architectural guarantee that identity association is impossible.

---

## 2. Public / Reporting Endpoints

### `GET /api/health`
Returns operational status of database, KMS key provider, ZK proof verifier, AI moderation pipeline, and blockchain audit adapter.

### `GET /api/categories`
Returns available disclosure categories and risk tiers (`standard`, `elevated`, `urgent`).

### `POST /api/reports`
Submits an encrypted anonymous report.
- **Rate Limit**: 30 requests / minute per IP.
- **Request Body**:
  ```json
  {
    "categoryId": "cat-harassment",
    "body": "Detailed disclosure narrative...",
    "proof": {
      "merkleTreeDepth": 16,
      "merkleTreeRoot": "123456...",
      "nullifier": "987654...",
      "message": "canonical-signal-hash",
      "scope": "cat-harassment",
      "points": ["p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"]
    }
  }
  ```
- **Response**:
  ```json
  {
    "reference": "INC-A849204",
    "status": "received",
    "statusSecret": "sec_9fa8120b34...",
    "priority": "high"
  }
  ```

### `POST /api/reports/status`
Queries report status using the 128-bit status secret. Constant-time timing-safe comparison.
- **Rate Limit**: 60 requests / minute.
- **Request Body**: `{ "reference": "INC-A849204", "statusSecret": "sec_9fa8120b34..." }`
- **Response**: `{ "status": "under_review", "categoryName": "Harassment", "createdAt": "...", "priority": "high" }`

---

## 3. Moderator Endpoints (Requires `moderator` or `admin` JWT)

### `GET /api/moderator/reports`
Lists anonymous reports with status, priority, and moderation results.

### `GET /api/moderator/reports/:id`
Retrieves decrypted report content and moderation audit trail. Excludes all reporter identity.

### `POST /api/moderator/reports/:id/action`
Records a review transition or human override (`confirm`, `reclassify`, `escalate`, `close`). Requires authenticated moderator session and documented reason (>= 5 chars).

### `GET /api/moderator/metrics`
Returns verified counts of active reports, reviews, flagged items, and audit commitments.

---

## 4. Audit & Integrity Endpoints

### `GET /api/audit/batches`
Lists public Merkle roots, transaction hashes, block numbers, and confirmation status.

### `POST /api/audit/batches/:id/verify`
Reconciles local database leaves against the on-chain Merkle root.
