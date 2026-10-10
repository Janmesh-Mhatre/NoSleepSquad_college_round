# Incognito — Full System Architecture

## 1. Architectural Philosophy

Incognito enables verified students and employees to report institutional misconduct, harassment, or safety hazards **without fear of retaliation**.

The platform is designed around four technical invariants:
1. **Zero Relational Link**: Reports contain no student ID, name, email, or IP address.
2. **Real Semaphore Zero-Knowledge Proofs**: Membership in the institution is proven via zk-SNARKs without revealing which member generated the proof.
3. **Multi-Provider AI Moderation**: Independent safety filtering with prompt injection defenses and fail-safe degradation to human review.
4. **Immutable Public Blockchain Audit**: Batches of report commitments are anchored to an EVM smart contract (`AuditRegistry.sol`) so administrators cannot delete or manipulate historical cases.

---

## 2. Component Layout

```
incognito/
├── backend/
│   ├── app.ts                         # Express 5 server configuration & security headers
│   ├── db.ts                          # Database layer (SQLite local/test & PostgreSQL production pool)
│   ├── config/
│   │   └── env.ts                     # Environment configuration & fallbacks
│   ├── middleware/
│   │   ├── auth.ts                    # Strict RBAC middleware
│   │   └── rateLimiter.ts             # Sliding window rate limiter
│   ├── migrations/                    # PostgreSQL DDL migrations & runner
│   │   ├── 001_initial_schema.sql
│   │   ├── 002_retention_and_audit.sql
│   │   └── runner.ts
│   ├── moderation/                    # AI Moderation Engine & Provider Architecture
│   │   ├── providers/                 # Base, Deterministic, Gemini, OpenAI, Mock
│   │   ├── rules/                     # Multilingual deterministic safety rules
│   │   ├── normalizer.ts              # Unicode NFKC, leetspeak, homoglyphs, PII scrubbing
│   │   ├── injectionDefense.ts        # Prompt injection detection & isolation delimiters
│   │   ├── pipeline.ts                # End-to-end multi-provider orchestrator
│   │   └── evaluationDataset.ts       # Synthetic evaluation fixtures
│   ├── services/
│   │   ├── authService.ts             # Cryptographic JWT authentication
│   │   ├── keyService.ts              # KMS Key Provider & AES-256-GCM cipher
│   │   ├── zkProofService.ts          # Semaphore Groth16 ZK proof verification
│   │   ├── reportService.ts           # Anonymous report lifecycle & encryption
│   │   ├── blockchainService.ts       # Multi-RPC adapter & AuditRegistry anchor
│   │   ├── oidcService.ts             # Institutional OpenID Connect verification
│   │   ├── retentionService.ts        # Data retention & right-to-be-forgotten purges
│   │   └── metricsService.ts          # Operational telemetry without PII
│   └── tests/                         # Full automated test suite (Phases A–I)
├── blockchain/
│   ├── contracts/AuditRegistry.sol    # Smart contract for batch Merkle root publishing
│   └── test/                          # Hardhat contract tests
├── src/                               # React 18 Frontend UI & Client State
└── docs/                              # Architecture, Security, Privacy, Deployment docs
```

---

## 3. Cryptographic Primitives

- **Zero-Knowledge Proofs**: Circom 2.0 / Groth16 snark via `@semaphore-protocol/core` v4.
- **Group Membership Tree**: Poseidon-hashed binary Merkle tree of depth 16 (capacity 65,536 members).
- **Encryption at Rest**: Authenticated AES-256-GCM with 12-byte random IV and 16-byte authentication tag (`gcm:<IV>:<Tag>:<Ciphertext>`).
- **Audit Tree**: Pairwise binary Merkle tree with SHA-256 leaf commitments.
- **Status Access Secret**: 128-bit cryptographically secure pseudorandom token (`sec_...`) verified in constant-time via `crypto.timingSafeEqual`.
