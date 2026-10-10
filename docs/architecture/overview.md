# Incognito — Architecture & System Overview

## Institutional Mission
Incognito is a privacy infrastructure platform designed for institutional environments (universities, research centers, healthcare institutions) to decouple membership verification from report submission. It allows community members to report critical safety, misconduct, and governance concerns without routinely transmitting their institutional identities to the reporting database.

## System Topology

```text
[ Institutional Member ]
           │
           ▼
[ Identity Service (SSO) ] ── (Verifies enrollment, returns status)
           │
           ▼ (Separation Boundary)
[ Anonymous Credential ] ──── (Scoped commitment, no PII)
           │
           ▼
[ Reporting Gateway ] ─────── (Validates proof + topic nullifier)
           │
           ├──► [ AI Moderation Engine ] ── (Rule-based triage & NLP)
           │
           ├──► [ Encrypted SQLite Store ] ─ (AES-256-GCM at rest)
           │
           └──► [ Off-chain Audit Queue ] ──► [ Merkle Tree ] ──► [ Sepolia Contract ]
```

## Core Boundaries
1. **Verification Domain (`/enroll`)**: Authorizes active status without linking to report submissions.
2. **Submission Domain (`/report`)**: Accepts reports accompanied only by topic-scoped nullifier proofs.
3. **Investigation Domain (`/moderator`)**: Exposes sanitized case narratives, AI safety signals, and action controls.
4. **Audit Domain (`/admin/audit`)**: Proves inclusion through public cryptographic commitments on Sepolia testnet.
