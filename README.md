# Incognito — Privacy Infrastructure Platform
> **Speak Without Being Seen.** Institutional privacy, zero-knowledge verification, and cryptographic auditing.

Incognito separates institutional membership verification from report submission. Eligible students and employees prove their authorized enrollment using **real Semaphore Groth16 Zero-Knowledge Proofs** to submit sensitive safety, academic, or conduct disclosures without attaching their student ID, staff account, or network identity to the reporting database.

---

## Master Architecture & Security Documentation

- **[Master Final Project Audit](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/FINAL_PROJECT_AUDIT.md)**: Full completion matrix across Phases A through I with evidence, test results, and residual risk assessments.
- **[System Architecture](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/architecture/ARCHITECTURE.md)**: High-level topology, component layout, and cryptographic primitives.
- **[Comprehensive Threat Model](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/security/THREAT_MODEL.md)**: Analysis of 10 adversary classes, defenses, and technical limitations.
- **[Adversarial Security Test Report](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/security/SECURITY_TEST_REPORT.md)**: Detailed results from penetration testing and adversarial attacks.
- **[Privacy Model & Boundary Analysis](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/privacy/PRIVACY_MODEL.md)**: Technical disclosures of what the system protects and what it does not.
- **[AI Moderation & Provider Pipeline](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/moderation/MODERATION.md)**: Normalization (Hindi/Hinglish/homoglyphs), prompt injection defense, and provider independence (Gemini / OpenAI / Mock).
- **[Data Retention & Backup Procedures](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/architecture/DATA_RETENTION_AND_BACKUP.md)**: Right-to-be-forgotten purges and disaster recovery verification.
- **[Blockchain Audit Architecture](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/blockchain/BLOCKCHAIN.md)**: Multi-RPC failover, pairwise balanced Merkle trees, and `AuditRegistry.sol` smart contract integration.
- **[Production Deployment Guide](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/deployment/DEPLOYMENT.md)**: Docker containerization, Vercel frontend, and environment segregation.
- **[API Reference](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/api/API.md)**: Complete REST endpoint documentation and security invariants.
- **[Technical Limitations](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/development/LIMITATIONS.md)**: Traffic analysis, stylometry, and endpoint assumptions.
- **[Incident Response Plan](file:///c:/Users/Janmesh%20Mhatre/Desktop/Programmes/Projects/incognito-v2/docs/development/INCIDENT_RESPONSE.md)**: Triage protocols and disaster recovery actions.

---

## Core Security & Privacy Guarantees

1. **Zero Relational Linkage**: The database schema strictly isolates identity. The `reports` table contains no `student_id`, `name`, `email`, `member_id`, or IP address columns. Database joins to student accounts are architecturally impossible.
2. **Real Semaphore Zero-Knowledge Proofs**: Built on Circom / Groth16 via `@semaphore-protocol/core`. A report sender proves membership in an institutional group without revealing their identity or leaf position.
3. **Signal & Scope Binding**: The proof signal cryptographically binds to $\text{Poseidon}(\text{SHA256}(\text{body}))$. Altering the report text invalidates the proof.
4. **Topic-Scoped Unlinkable Nullifiers**: Submitting a second report in the same category produces the identical nullifier and is rejected (preventing double-reporting spam). Submitting reports in different categories produces pseudorandomly independent nullifiers that cannot be correlated.
5. **Authenticated AES-256-GCM Encryption**: Disclosures are encrypted at rest using a 12-byte random IV and 16-byte authentication tag with KMS-managed keys.
6. **Provider-Independent AI Safety**: Contextual moderation runs with minimal data. Raw PII is pre-scrubbed; untrusted inputs are wrapped in isolation delimiters. Provider outages degrade safely to human review.
7. **Immutable Public Audit**: Batches of report commitments are anchored to an EVM smart contract (`AuditRegistry.sol`). Any historical modification of database records triggers an immediate `tampered_mismatch` warning upon reconciliation.

---

## Quickstart & Verification

### Install Dependencies
```bash
npm install
```

### Run Full Test Suite (Phases A–I)
```bash
# Runs contract tests, backend security tests (A-I), and frontend tests
npm test
```

### Run Blockchain Hardhat Tests
```bash
npm run blockchain:test
```

### Build Production Bundle
```bash
npm run build
```

### Run Local Development Server
```bash
# Terminal 1: Backend API
npm run server

# Terminal 2: Frontend Vite SPA
npm run dev
```
