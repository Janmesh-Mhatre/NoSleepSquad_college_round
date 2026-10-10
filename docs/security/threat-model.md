# Incognito Threat Model & Security Posture

## 1. Adversary Assumptions & Defenses
- **Compromised Gateway / Database**: An attacker gaining full read access to the SQLite storage discovers only encrypted texts (AES-256-GCM), random references (`INC-XXXXXX`), and SHA-256 hashed status secrets. No student IDs, emails, IP addresses, or hardware fingerprints exist in the schema.
- **Malicious Administrator**: Administrators cannot decrypt or read reports without authorized role credentials. System action history logs all status transitions and requires explicit rationale strings.
- **Credential Issuer Malice**: The credential issuer observes that an institutional member verified eligibility; it never receives report text, chosen categories, or timing of report submissions.
- **Denial-of-Service / Spam**: Mitigated through topic-scoped cryptographic nullifiers. A user cannot flood the system with identical reports in the same scope, yet their submissions remain unlinkable across different scopes.

## 2. Technical Limitations & Non-Claims
- **No 100% Guarantee**: Incognito makes no claims of "complete untraceability" or "100% anonymity".
- **Endpoint Compromise**: Keyloggers or endpoint monitoring software on institutional computers can observe report text prior to browser encryption.
- **Stylometry & Content Disclosures**: If a reporter voluntarily writes unique names, specific dorm rooms, or distinct linguistic patterns in their narrative, readers may infer identity.
- **Blockchain Limitations**: On-chain Merkle commitments prove that an audit record existed at a specific block number; they cannot prove that the statement is factually accurate.
