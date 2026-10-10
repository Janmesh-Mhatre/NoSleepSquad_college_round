# Incognito — Comprehensive Privacy Model

## 1. Core Principle: Defense-in-Depth Privacy Without Absolute Claims

> [!WARNING]
> **No System is "100% Anonymous" or "Untraceable".**
> Incognito provides technically defensible privacy guarantees by minimizing data collection, decoupling identity verification from disclosure submission, using zero-knowledge group proofs, and employing authenticated encryption. However, privacy is a spectrum governed by cryptographic boundaries and physical network realities.

---

## 2. Who Knows What? (Information Exposure Matrix)

| Entity | What They Know | What They CANNOT Know |
| :--- | :--- | :--- |
| **Institutional Identity Provider** (e.g., Azure AD / Google Workspace) | - That student $X$ authenticated to obtain an eligibility token at timestamp $T$. | - Which report, if any, the student submitted.<br>- The report category, text, or reference code.<br>- The student's private Semaphore trapdoor or nullifiers. |
| **Incognito Reporting Service** | - The category, encrypted text, and timestamp of the report.<br>- The cryptographic Semaphore ZK proof and topic nullifier.<br>- The SHA-256 hash of the status secret. | - The student's name, email, student ID, or IP address.<br>- Which member in the group generated the proof. |
| **Staff Moderators** | - Decrypted report narrative and category.<br>- Automated moderation flags and urgency score.<br>- Case action history. | - **Zero reporter identity**.<br>- Status access secret.<br>- Relational student identifiers (no DB joins exist). |
| **External AI Providers** (Gemini / OpenAI) | - Scrubbed, normalized report text enclosed in isolation delimiters. | - Student identity, email, phone number, ID.<br>- Session tokens, credentials, nullifiers, or IP addresses. |
| **Blockchain Observers** (Public EVM Explorer) | - 32-byte Merkle root, sequence number, and batch record count.<br>- Publisher relayer address and block timestamp. | - Report text, categories, or references.<br>- Reporter identities or Semaphore nullifiers. |

---

## 3. Residual Risks & Adversary Capabilities

### 3.1 Network-Layer Traffic Analysis
- If an adversary monitors the campus LAN router or ISP, they can correlate outgoing packet timestamps between an OIDC authentication request and an anonymous report submission.
- **Protection**: Whistleblowers under active physical network surveillance must route traffic through Tor or trusted non-institutional VPNs.

### 3.2 Stylometry & Narrative Specificity
- If a reporter includes unique circumstantial statements (e.g. "I am the only third-year intern in Lab 4 on Tuesday afternoons"), readers can deduce identity through context alone regardless of cryptographic protections.
- **Protection**: Reporters are cautioned in the UI to omit identifying personal schedules.

### 3.3 Anonymity Set Size
- A zero-knowledge membership proof proves that the sender is a member of the active group.
- If an institutional group contains only 2 members, the anonymity set is 2. If it contains 10,000 students, the anonymity set is 10,000.
- **Protection**: Incognito enforces minimum institutional group tree thresholds before enabling reporting.
