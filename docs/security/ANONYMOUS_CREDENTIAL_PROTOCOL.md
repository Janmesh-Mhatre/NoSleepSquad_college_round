# Incognito — Anonymous Credential & ZK Proof Protocol Specification
**Protocol Version**: Semaphore-v4-Core-Groth16  
**Implementation Package**: `@semaphore-protocol/core` v4.14.3  
**Cryptographic Engine**: Groth16 zk-SNARK / SnarkJS / BN254 Curve / Poseidon Hash  
**Status**: Implemented  

---

## 1. System Overview & Architecture

The **Incognito Privacy Protocol** establishes cryptographic eligibility verification for institutional members (students, faculty, employees) submitting confidential misconduct reports without linking the reporter's real identity to the report.

```text
Institution Identity Service                 Credential / Group Issuance
        │                                                │
 1. Authenticated Enrollment                             │
 (Student proves institutional ID)                       │
        │                                                │
        ▼                                                ▼
Anonymous Identity Generation ───────────────► Identity Commitment Registered
(Client creates private Identity)             (Public commitment added to Group)
                                              (Poseidon Merkle Tree Root R)
                                                         │
                                                         ▼
─────────────────────────────────────────────────────────────────────────────
(Identity Session Terminated / Logical Air-Gap)
─────────────────────────────────────────────────────────────────────────────
                                                         │
Anonymous Member Prover                                  ▼
        │                                     Anonymous Reporting Gateway
 2. Generates Semaphore zk-SNARK Proof                   │
 ├── Private witness: Identity secret scalar             │
 ├── Group membership in active Root R                   │
 ├── Topic scope: canonical topic hash                   │
 └── Signal: canonical report hash                       │
        │                                                │
        └─────────────── 3. Semaphore Proof ────────────►│
                         (Root R, Nullifier, Scope,      │
                          Signal, Groth16 Points)        │
                                                         ▼
                                              4. Verification Pipeline
                                              ├── verifyProof(semaphoreProof)
                                              ├── Root active in registry
                                              ├── Scope matches category
                                              ├── Signal matches report body
                                              └── Nullifier unused in scope
                                                         │
                                                         ▼
                                              5. Report Accepted & Encrypted
```

---

## 2. Cryptographic Protocol Roles

| Role | Entity | Knowledge State |
| :--- | :--- | :--- |
| **Issuer** | Institutional Membership Service | Authenticates institutional identity ($ID_{\text{member}}$). Registers the member's public commitment ($C_{\text{id}} \in \mathbb{G}$) into the group. Does **NOT** receive private identity secrets or report content. |
| **Holder** | Member Client Application | Generates and retains private identity secret scalar (`secretScalar`, `privateKey`). Generates zero-knowledge proofs locally. |
| **Verifier** | Anonymous Reporting Gateway | Verifies membership in active root $R$, topic-scoped nullifier validity, signal binding integrity, and replay resistance. Does **NOT** learn holder identity or which commitment belongs to the prover. |

---

## 3. Cryptographic Primitives & Derivations

### 3.1 Identity Creation (`@semaphore-protocol/core`)
Members generate an anonymous identity locally using Baby Jubjub EdDSA and Poseidon hashing:
1. $\text{privateKey} \in \{0, 1\}^{256}$ (ephemeral seed entropy)
2. $\text{secretScalar} = \text{Poseidon}(\text{privateKey})$
3. $\text{publicKey} = \text{secretScalar} \cdot G$ (Baby Jubjub elliptic curve scalar multiplication)
4. $\text{commitment} = \text{Poseidon}(\text{publicKey})$

The private key and secret scalar are **never transmitted** to the server. Only the public `commitment` scalar is registered in the institutional group tree.

### 3.2 Membership Group (`Group`)
- **Structure**: Incremental Poseidon Merkle Tree.
- **Tree Depth**: Dynamic (depth 1 to 20, supporting up to $2^{20} = 1,048,576$ members).
- **Group Root**:
  $$R = \text{MerkleTree}(\text{commitments}, \text{hash}=\text{Poseidon})$$

### 3.3 Topic-Scoped External Nullifiers (`scope`)
To guarantee cross-topic unlinkability while preventing double-submission spam within the same topic:
$$\text{scopeScalar} = \text{BigInt}(\text{SHA-256}(\text{"INCOGNITO-SCOPE-V2:"} \parallel \text{topicCategory})) \gg 8$$
- **Cross-topic unlinkability**:
  $$\text{Poseidon}(\text{nullifierSecret}, \text{scope}_A) \neq \text{Poseidon}(\text{nullifierSecret}, \text{scope}_B)$$
  An observer cannot link reports submitted by the same member across different categories.
- **Same-topic duplicate prevention**:
  Submitting under the same category reproduces the identical nullifier, which is rejected by the database.

### 3.4 Signal Binding (`message`)
To bind the report payload to the proof and prevent front-running:
$$\text{signalScalar} = \text{BigInt}(\text{SHA-256}(\text{"INCOGNITO-SIGNAL-V2:"} \parallel \text{reportBody})) \gg 8$$
The Groth16 circuit verifies that the proof was computed specifically for this signal.

---

## 4. Verification Pipeline

The reporting gateway verifies:
1. **Groth16 zk-SNARK Pairing**: `verifyProof(proof)` verifies elliptic curve pairings over BN254.
2. **Active Group Root**: Checks that `proof.merkleTreeRoot` is active in `membership_roots`.
3. **Scope Match**: Verifies `proof.scope == computeCanonicalScope(category).toString()`.
4. **Signal Match**: Verifies `proof.message == computeCanonicalSignal(body).toString()`.
5. **Replay Check**: Verifies `proof.nullifier` is not in `used_nullifiers` for this topic.

---

## 5. Implementation Status Breakdown

### Implemented
- `@semaphore-protocol/core` v4.14.3 integration.
- Real Groth16 zk-SNARK zero-knowledge proof generation and verification.
- Poseidon Incremental Merkle Tree membership groups.
- Baby Jubjub EdDSA identity commitments.
- Canonical 248-bit topic-scoped external nullifiers.
- Canonical 248-bit report signal binding.
- Database-backed nullifier replay protection table (`used_nullifiers`).
- Active group root tracking and revocation root rotation (`membership_roots`).

### Partial
- Browser WebAssembly proving pipeline: Proofs can be generated on the client via `@semaphore-protocol/core` in browser environments supporting Web Workers and WASM; automated tests currently validate Node.js runtime proving.

### Simulated
- None in Phase B. All pseudo-ZK HMAC prototypes have been replaced with genuine Groth16 SNARK proofs.

### Not Implemented
- Recursive SNARK proofs / folding schemes (not required for single-layer anonymous signaling).
