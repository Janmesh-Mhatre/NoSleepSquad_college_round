# Incognito — Security & Privacy Guarantees
**Document Classification**: Trust & Cryptographic Policy  
**Version**: 2.2  
**Status**: Implemented  

---

## 1. Precise Statement of Security & Anonymity

> The application separates institutional identity from anonymous reporting through privacy-preserving membership proofs. This protects against direct application-level identity disclosure, but does not eliminate risks from compromised devices, malicious infrastructure operators, traffic analysis, institutional identity-service compromise, or collusion between trusted components.

---

## 2. Cryptographic & Architectural Guarantees

### Guarantee 1: Groth16 Zero-Knowledge Membership Proofs
- Implemented via `@semaphore-protocol/core` v4.14.3.
- A verified student or staff member proves membership in the institutional eligibility group without disclosing their name, student reference, email, identity secret, or which leaf commitment belongs to them.
- Verification is performed mathematically using Groth16 bilinear pairings over the BN254 elliptic curve against the active Poseidon Merkle root.

### Guarantee 2: Cross-Topic Unlinkability
- Nullifiers are domain-separated by canonical category scope:
  $$\text{Nullifier} = \text{Poseidon}(\text{nullifierSecret}, \text{scope})$$
- Submissions across different categories cannot be linked together by database administrators or network observers.
- Submissions under the same category produce identical nullifiers, enabling deterministic double-submission rejection.

### Guarantee 3: Storage Confidentiality & Integrity
- All report payloads are encrypted with authenticated `AES-256-GCM` before storage in SQLite.
- Tampering with ciphertext or authentication tags causes immediate decryption failure.
- Status access secrets possess 128 bits of cryptographic entropy and are verified using constant-time comparison (`timingSafeEqual`).

### Guarantee 4: Tamper-Evident Audit Trail
- Case lifecycles and audit commitments are hashed into a deterministic pairwise balanced binary Merkle tree.
- Batch commitments ($R_{\text{batch}}$) are published to the deployed `AuditRegistry.sol` smart contract via real `ethers` transactions.
- Any unauthorized deletion or modification of historical records causes an immediate Merkle root mismatch during on-chain reconciliation.

### Guarantee 5: Strict Role-Based Access Control (RBAC)
- Client-provided role headers (`X-Staff-Role`) and client-controlled identities (`moderatorId`) are completely rejected.
- Staff endpoints require signed JWT bearer tokens with server-side claim verification.

---

## 3. Implementation Status Matrix

### Implemented
- JWT Bearer Authentication & Strict RBAC (`authService.ts`, `middleware/auth.ts`).
- Server-derived moderator identity context from verified claims.
- Authenticated AES-256-GCM Payload Cipher (`reportService.ts`).
- Real `@semaphore-protocol/core` Groth16 Zero-Knowledge Proof Service (`zkProofService.ts`).
- Domain-Separated Topic Nullifiers & Replay Prevention (`used_nullifiers`).
- Zero Identity Columns in Report Database (`reports` table).
- Explicit `403 Forbidden` rejection on `/reports/:id/identity` routes.
- Constant-Time Status Secret Verification (`crypto.timingSafeEqual`).
- Real Pairwise Merkle Tree & `AuditRegistry.sol` contract deployed via Hardhat.
- Real `ethers` JsonRpcProvider, Wallet Signer, and transaction receipt handling (`blockchainService.ts`).
- Outage resilience (`pending_retry`) and contract root reconciliation (`MATCH` vs `MISMATCH`).
- Fail-Closed Key Management & Mock Provider Prohibitions in Production (`keyService.ts`).

### Partial
- Single SQLite instance in development; production environments should deploy physically separate database instances for the Institutional Identity Service and the Anonymous Reporting Gateway.

### Simulated
- None remaining. All cryptographic and blockchain operations execute against real libraries (`@semaphore-protocol/core`, `ethers`, Hardhat).

### Not Implemented
- Network-layer Tor hidden service / onion routing (network-level anonymity must be provided by user transport).
