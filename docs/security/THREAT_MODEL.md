# Incognito — Comprehensive Threat Model
**Protocol Version**: 2.1  
**Classification**: Public Threat Assessment  
**Status**: Implemented  

---

## 1. System Scope & Assets Protected

Incognito protects four high-value security assets:
1. **Reporter Anonymity**: The association between an institutional individual ($ID_{\text{member}}$) and a submitted report ($R$).
2. **Report Confidentiality**: The sensitive text alleging institutional misconduct, harassment, or safety hazards.
3. **Sybil Resistance & Anti-Spam**: Preventing malicious actors from flooding report categories while preserving privacy.
4. **Historical Audit Integrity**: Ensuring published case statistics and moderation actions cannot be silently altered or deleted.

---

## 2. Adversary Models & Attack Scenarios

### Adversary A: Compromised Database / Rogue DBA
- **Capabilities**: Full read/write access to SQLite/Postgres storage.
- **Defenses**:
  - The `reports` table contains **zero identity columns** (no student IDs, emails, IP addresses, or foreign keys to `members`).
  - Report payloads are encrypted with authenticated `AES-256-GCM` using keys stored outside the database.
  - Status access secrets are stored strictly as SHA-256 one-way hashes with 128-bit entropy.
- **Outcome**: The attacker cannot deanonymize reporters or read report plaintext without KMS keys.

### Adversary B: Malicious Institution Administrator / Moderator
- **Capabilities**: Staff privileges attempting to identify whistleblower identity or tamper with cases.
- **Defenses**:
  - Identity separation ensures the backend never has student IDs associated with reports.
  - Role-Based Access Control (RBAC) enforces cryptographically signed JWT tokens and rejects client-provided role headers or client-provided `moderatorId`.
  - All moderator transitions require immutable rationale records and are anchored to public Merkle trees.
- **Outcome**: Administrators cannot link reports to students or forge moderation actions without detection.

### Adversary C: Compromised Credential Issuer
- **Capabilities**: The institutional directory service verifying student enrollment.
- **Defenses**:
  - The issuer registers only public identity commitments ($C_{\text{id}}$) in the Merkle tree.
  - The issuer never receives the private `trapdoor`, `nullifierSecret`, report category, or report body.
- **Outcome**: The issuer cannot determine which enrolled student filed which report.

### Adversary D: Sybil Attacker / Front-Running Observer
- **Capabilities**: An attacker attempting to submit multiple duplicate reports or intercept another user's ZK proof in transit.
- **Defenses**:
  - The proof binds cryptographically to $\text{Signal} = \text{SHA256}(\text{ReportPayload})$.
  - Intercepting a proof and submitting it with different report text causes an immediate signal mismatch rejection.
  - Submitting multiple reports in the same topic reuses the same nullifier and is rejected with HTTP `409 Duplicate`.

---

## 3. Explicit Status of System Capabilities

| Capability | Status | Implementation Details |
| :--- | :--- | :--- |
| **RBAC Hardening** | `IMPLEMENTED` | Cryptographic JWT claims verification; no client-controlled headers. |
| **AES-256-GCM Encryption** | `IMPLEMENTED` | Authenticated symmetric cipher with 12-byte IV and 16-byte GCM tag. |
| **Semaphore ZK Proofs** | `IMPLEMENTED` | Merkle membership validation and topic nullifier derivation. |
| **Identity Separation** | `IMPLEMENTED` | Zero relational link between member and report tables. |
| **Real Merkle Audit Tree** | `IMPLEMENTED` | Pairwise balanced binary Merkle tree with SHA-256 and proof generation. |
| **Smart Contract Anchor** | `IMPLEMENTED` | `AuditRegistry.sol` EVM contract for public batch commitments. |
| **Network Traffic Obfuscation**| `NOT PROTECTED`| Application layer cannot prevent TCP/IP packet timing correlation. |
| **Stylometric Self-Deduction**| `NOT PROTECTED`| Voluntary self-identifying statements in text require user caution. |
