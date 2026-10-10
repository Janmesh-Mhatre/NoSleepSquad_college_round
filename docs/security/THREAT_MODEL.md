# Incognito — Comprehensive Threat Model & Security Posture
**Protocol Version**: 2.5 (Production Hardened)  
**Classification**: Public Adversarial Security & Privacy Evaluation  
**Status**: Formally Implemented & Audited  

---

## 1. System Scope & Core Assets Protected

Incognito protects four high-value security assets:
1. **Reporter Anonymity**: Complete architectural and cryptographic decoupling between an individual student/employee identity ($ID_{\text{member}}$) and a submitted report ($R$).
2. **Report Confidentiality**: Whistleblower disclosures alleging institutional misconduct, harassment, or safety hazards are protected with authenticated AES-256-GCM encryption at rest.
3. **Sybil Resistance & Rate-Limiting**: Enforcing Semaphore ZK group membership and deterministic topic-scoped nullifiers to prevent duplicate report flooding while ensuring cross-topic unlinkability.
4. **Historical Audit Integrity**: Public anchoring of pairwise Merkle roots to the `AuditRegistry.sol` smart contract, ensuring reports and statistics cannot be silently altered or deleted post-facto.

---

## 2. Adversary Models & Threat Analysis

### 2.1 Adversary 1: Malicious Reporter (Sybil, Spam & Proof Forgery)
- **Attack Vectors**:
  - Submitting forged or synthetic ZK proof points.
  - Replaying a valid proof from another student's report.
  - Flooding a topic with duplicate reports.
  - Front-running another student's submission by altering the body while reusing the intercepted proof.
- **Defenses**:
  - Groth16 zk-SNARK verification verifies the proof cryptographically against the Semaphore institutional Merkle root.
  - Signal binding enforces $\text{Signal} = \text{SHA256}(\text{ReportPayload})$. Modifying even a single character in the report invalidates the proof.
  - Topic-scoped nullifiers ensure any duplicate submission in the same topic reproduces the identical nullifier hash and is rejected with HTTP `409 Duplicate`.

### 2.2 Adversary 2: Malicious Institutional Administrator
- **Attack Vectors**:
  - Attempting to query database joins between reports and member accounts.
  - Deleting unflattering reports to conceal administrative wrongdoing.
  - Arbitrarily altering historical case metrics.
- **Defenses**:
  - **Zero identity columns**: The `reports` table contains no `student_id`, `name`, `email`, `member_id`, or IP address columns. Foreign keys to members do not exist.
  - Reports are cryptographically anchored to blockchain audit batches. Deleting a report leaves an orphaned leaf in the immutable on-chain Merkle root, resulting in immediate `tampered_mismatch` detection.

### 2.3 Adversary 3: Compromised Staff Moderator
- **Attack Vectors**:
  - Calling administrative or identity endpoints (e.g. `GET /api/moderator/reports/:id/identity`).
  - Overriding safety classifications to suppress serious misconduct disclosures.
  - Forging moderator action records under another staff member's name.
- **Defenses**:
  - `/api/moderator/reports/:id/identity` returns HTTP `403 Forbidden` with an architectural guarantee that identity association is impossible.
  - Strict server-side RBAC ignores client-provided role headers (e.g., `X-Staff-Role`) and derives moderator identity strictly from cryptographically verified server-side JWT claims.
  - All review overrides require authenticated signatures, mandatory reasons (>= 5 chars), and are permanently recorded in `moderation_actions`.

### 2.4 Adversary 4: Malicious Credential Issuer
- **Attack Vectors**:
  - Tracking student identity during the initial verification process to link students to future reports.
- **Defenses**:
  - The client generates their Semaphore identity secret (`trapdoor` and `nullifierSecret`) locally in browser memory.
  - The issuer receives only the public `commitment` ($C_{\text{id}} = \text{Poseidon}(\text{nullifierSecret}, \text{trapdoor})$).
  - Because Poseidon is a one-way cryptographic hash function, the issuer cannot reconstruct the trapdoor or derive future nullifiers.

### 2.5 Adversary 5: Compromised Browser / Client Endpoint
- **Attack Vectors**:
  - Inspecting local storage or session cookies for secret status keys.
  - Extracting credentials from browser history or URL query strings.
- **Defenses**:
  - **Zero credential persistence**: Status secrets (`sec_...`) and Semaphore identity secrets are NEVER stored in `localStorage`, `sessionStorage`, or cookies.
  - Status lookups use POST bodies rather than URL parameters to avoid caching in browser history or reverse-proxy logs.
  - Status access secrets possess 128 bits of entropy and are compared using constant-time `crypto.timingSafeEqual`.

### 2.6 Adversary 6: Database Compromise / Rogue DBA
- **Attack Vectors**:
  - Obtaining a complete raw SQL dump of the database.
- **Defenses**:
  - All report bodies are stored in authenticated `gcm:<IV>:<Tag>:<Ciphertext>` format.
  - Encryption keys are externalized through `KeyProvider` (KMS abstraction) and never stored in the database.
  - Status access secrets are stored strictly as SHA-256 one-way hashes.

### 2.7 Adversary 7: External AI Provider Compromise (Gemini / OpenAI)
- **Attack Vectors**:
  - AI provider logs intercepting student whistleblower disclosures.
  - Prompt injection inside report text tricking the AI into marking threats as "cleared".
- **Defenses**:
  - **Minimal-Data Principle**: No student IDs, tokens, nullifiers, IPs, or metadata are ever transmitted to external AI providers.
  - Normalization scrubs PII (emails, phone numbers, IDs) before evaluation.
  - Prompt injection defense detects adversarial jailbreak patterns and encloses inputs in isolation delimiters (`<<<BEGIN_UNTRUSTED...>>>`).
  - External provider failure **fails safely** to `review_required` / human review, never failing open.

### 2.8 Adversary 8: Blockchain Observer
- **Attack Vectors**:
  - Analyzing public transactions on the EVM `AuditRegistry` contract to infer report content.
- **Defenses**:
  - The smart contract receives ONLY the 32-byte Merkle root, the batch sequence integer, and the record count integer.
  - Zero plaintext, zero report references, and zero nullifiers are ever published to the blockchain calldata.

### 2.9 Adversary 9: Network Observer / ISP / Traffic Analyst
- **Attack Vectors**:
  - Correlating IP packets and timestamps between student credential issuance and report submission.
- **Known Limitations & Defenses**:
  - Application applies HTTP security headers (`no-cache`, `no-store`, `nosniff`, `DENY`).
  - *Technical limitation*: Transport-layer packet timing analysis cannot be prevented solely by application code. Users under intense surveillance should use Tor or VPNs to decouple network-level transport metadata.

### 2.10 Adversary 10: Colluding Operators (Issuer + Moderator)
- **Attack Vectors**:
  - The issuer shares the membership list with the moderator to cross-reference reporting times.
- **Defenses**:
  - The membership tree is a Merkle tree of hundreds/thousands of students. A proof merely proves membership somewhere in the tree without revealing leaf index or path.
  - Reports submitted within an active group are indistinguishable among all enrolled members in that group.

---

## 3. Explicit Status of System Security Guarantees

| Guarantee | Status | Implementation Details |
| :--- | :--- | :--- |
| **Strict RBAC Enforcement** | `IMPLEMENTED` | Cryptographic JWT verification; client-controlled headers strictly rejected. |
| **Semaphore Groth16 Proofs** | `IMPLEMENTED` | Genuine Circom/Groth16 ZK snark proofs using `@semaphore-protocol/core`. |
| **Zero Relational Identity Link** | `IMPLEMENTED` | Reports table contains 0 identity columns; DB foreign keys to members impossible. |
| **AES-256-GCM Encryption at Rest**| `IMPLEMENTED` | 12-byte IV, 16-byte authentication tag, KMS-managed keys. |
| **Topic Nullifier Unlinkability** | `IMPLEMENTED` | Deterministic within topic; cryptographically pseudorandom across topics. |
| **Pairwise Merkle Tree Audit** | `IMPLEMENTED` | Binary balanced Merkle tree with SHA-256 leaf commitments. |
| **Smart Contract Anchoring** | `IMPLEMENTED` | `AuditRegistry.sol` on Sepolia/EVM with on-chain root verification and retry queue. |
| **AI Provider Independence & Defense** | `IMPLEMENTED` | Minimal data, PII scrubbing, injection delimiters, safe degradation. |
| **Data Retention Purging** | `IMPLEMENTED` | Closed reports purged at 365 days; blockchain audit logs permanently immutable. |
| **Network Traffic Obfuscation** | `NOT PROTECTED` | Physical/ISP traffic-analysis requires external VPN/Tor. |
| **Stylometric Self-Deduction** | `NOT PROTECTED` | Voluntary self-revealing phrases in whistleblower text require user discretion. |
