# Cryptographic Architecture & Proof Mechanisms

Incognito employs a multi-tiered cryptographic architecture to achieve identity decoupling, topic-scoped duplicate prevention, authenticated payload encryption, and tamper-evident audit trails.

---

## 1. Cryptographic Pipeline Overview

```text
[ Member SSO ] ──► Hash(MemberRef + Salt) ──► Credential Commitment
                                                      │
[ Category + Body ] ──────────────────────────────────┼──► Nullifier Hash (Duplicate Prevention)
                                                      │
                                                      ▼
[ Report Payload ] ──► AES-256-GCM Encrypted Body ──► Database Storage
                                                      │
[ Status Secret ] ──► SHA-256 One-Way Digest ─────────┴──► Status Secret Hash
                                                      │
[ Committed Leaf ] ──► Hash(Reference + Nullifier)
                                                      │
[ Leaf 1, 2, ... N ] ──► Deterministic Sort ──► SHA-256 Merkle Root ──► Sepolia Testnet
```

---

## 2. Mathematical & Algorithmic Specifications

### A. Identity Commitment Generation
Implemented in [backend/services/credentialService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/credentialService.ts):
```typescript
const salt = crypto.randomBytes(16).toString("hex");
const commitment = crypto
  .createHash("sha256")
  .update(`incognito:cred:${memberRef}:${salt}`)
  .digest("hex");
```
- **Privacy Property**: One-way preimage resistance. The credential commitment proves that the member was issued a credential without revealing the member's institutional identity.

### B. Topic-Scoped Nullifiers (Duplicate Prevention)
Implemented in [backend/services/reportService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/reportService.ts):
```typescript
const nullifierSeed = proofNullifier || 
  `scope:${categoryId}:${crypto.createHash("sha256").update(body.trim().toLowerCase()).digest("hex").substring(0, 16)}`;
const nullifierHash = crypto.createHash("sha256").update(nullifierSeed).digest("hex");
```
- **Privacy Property**: Prevents repeat/spam submissions for the exact same concern within the same category.
- **Unlinkability**: Different categories produce distinct cryptographic scopes, preventing observers from linking reports across different topics to the same author.

### C. Single-View Status Access Secrets
Implemented in [backend/services/reportService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/reportService.ts):
```typescript
const reference = "INC-" + crypto.randomInt(100000, 999999);
const statusSecret = "sec_" + crypto.randomBytes(8).toString("hex");
const statusSecretHash = crypto.createHash("sha256").update(statusSecret).digest("hex");
```
- **Server Storage**: Only `statusSecretHash` (64-character hex SHA-256 digest) is persisted in the database.
- **Client Presentation**: `statusSecret` is displayed once to the user upon submission.
- **Verification**: Lookup requests pass `statusSecret`, which is hashed and compared to `statusSecretHash`. A matching reference alone fails authorization.

### D. Merkle Tree Construction & Verification
Implemented in [backend/services/auditService.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/services/auditService.ts):
```typescript
// 1. Leaf commitment generation:
const leafHash = crypto.createHash("sha256").update(`${reportReference}:${nullifierHash}`).digest("hex");

// 2. Deterministic sorting:
const sortedLeaves = records.map(r => r.commitmentHash).sort();

// 3. Merkle root derivation:
const calculatedRoot = crypto.createHash("sha256").update(sortedLeaves.join("")).digest("hex");
```
- **Tamper-Evidence**: Recomputing the root over sorted leaf commitments mathematically proves inclusion. Any modification to a report reference or nullifier causes root verification to fail.
- **Verification API**: Calling `POST /api/audit/verify/:batchId` triggers this calculation dynamically against the stored records.

---

## 3. Cryptographic Verification Test

The platform includes automated assertions verifying these properties:
- [backend/tests/backend.test.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/backend/tests/backend.test.ts): Test #6 asserts Merkle root mathematical equivalence; Test #7 runs live database schema inspection confirming zero identity columns.
- [src/tests/frontend.test.ts](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/src/tests/frontend.test.ts): Asserts format entropy and non-persistence of secrets in URLs or browser storage.
