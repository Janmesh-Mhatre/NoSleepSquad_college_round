# Incognito — Blockchain Audit Architecture & Integrity Layer
**Classification**: Security Architecture Document  
**Version**: 2.2  
**Implementation**: `ethers` v6 + Hardhat + `AuditRegistry.sol`  
**Status**: Implemented  

---

## 1. System Role: The Blockchain as an Integrity Anchor

In the **Incognito** architecture, the blockchain is exclusively an **immutable public integrity layer**, **NOT** a report database.

```text
Backend Publisher
        │
        ├─ 1. Assembles audit record leaf commitments
        ├─ 2. Computes pairwise balanced SHA-256 Merkle root
        ▼
ethers.js Provider & Signer
        │
        ├─ 3. Signs transaction to AuditRegistry.sol
        ├─ 4. Submits publishBatch(batchId, merkleRoot, recordCount)
        ▼
AuditRegistry Smart Contract
        │
        ├─ 5. Validates publisher authorization
        ├─ 6. Enforces duplicate batch rejection
        ├─ 7. Emits BatchPublished event
        ▼
Transaction Receipt
        │
        ├─ 8. Returns real txHash and real blockNumber
        ▼
Database Persistence & Admin Dashboard
        │
        └─ 9. Reconciles on-chain root against local Merkle tree
```

---

## 2. On-Chain Data Minimization: What Goes On-Chain vs What Stays Off-Chain

| Attribute | State | Location | Rationale |
| :--- | :--- | :--- | :--- |
| **Report Narrative / Plaintext** | **STRICTLY FORBIDDEN** | Nowhere on-chain | Absolute privacy requirement. |
| **Encrypted Report Ciphertext** | **STRICTLY FORBIDDEN** | Nowhere on-chain | Ciphertext on-chain is vulnerable to future cryptanalysis. |
| **Student / Member Identity** | **STRICTLY FORBIDDEN** | Nowhere on-chain | Privacy air-gap requirement. |
| **IP Address / Client Metadata** | **STRICTLY FORBIDDEN** | Nowhere on-chain | Network metadata elimination. |
| **Nullifier Secrets / Trapdoors** | **STRICTLY FORBIDDEN** | Nowhere on-chain | Cryptographic secret protection. |
| **Batch Identifier** | **PUBLISHED** | On-chain string | For indexing and tracking. |
| **Pairwise Merkle Root** | **PUBLISHED** | On-chain `bytes32` | Cryptographic tamper evidence. |
| **Report Count** | **PUBLISHED** | On-chain `uint256` | Volume consistency check. |
| **Publication Timestamp** | **PUBLISHED** | On-chain `uint256` | Verifiable publication date. |
| **Authorized Publisher** | **PUBLISHED** | On-chain `address` | Prevents unauthorized spoofing. |

---

## 3. Pairwise Balanced Merkle Tree Specification

### 3.1 Leaf Construction
Each audit record generates a deterministic leaf:
$$L_i = \text{SHA256}(\text{"INCOGNITO-AUDIT-LEAF:"} \parallel \text{reportReference} \parallel \text{nullifierHash})$$

### 3.2 Pairwise Balanced Hashing
At each layer $k$:
$$\text{Parent}(j) = \text{SHA256}(\text{"INCOGNITO-MERKLE-PAIR:"} \parallel \text{Node}_{2j} \parallel \text{Node}_{2j+1})$$
If the layer contains an odd number of nodes, the trailing odd node is duplicated: $\text{Node}_{2j+1} = \text{Node}_{2j}$.

### 3.3 Root Anchor
The apex of the tree produces a single deterministic 256-bit root ($R_{\text{batch}}$), serialized canonically as a `bytes32` hex scalar (`0x...`).

---

## 4. Smart Contract Specification: `AuditRegistry.sol`

- **Contract Address**: Loaded via `CONTRACT_ADDRESS` environment variable.
- **Publisher Authorization**: Enforced via `onlyPublisher` modifier. Only institutional keys approved by the owner can commit official audit batches.
- **Duplicate Prevention**: Re-publishing an existing `batchId` reverts with `"AuditRegistry: batch already published"`.
- **Integrity Verification**: `verifyBatch(batchId, expectedRoot)` returns boolean match status, publication timestamp, and publisher address.

---

## 5. Resilience: Outage & Failure Recovery

The platform guarantees that an RPC timeout or blockchain network congestion **never prevents a member from submitting an urgent report**.

1. When a report is received, it is immediately encrypted and acknowledged.
2. The audit commitment is queued locally with `audit_committed = 0`.
3. If publication to the blockchain fails or RPC is down:
   - Batch status is saved as `pending_retry`.
   - The error is logged without crashing report submission.
4. `retryBatch(batchId)` and `retryPendingBatches()` retry publication when the RPC provider recovers.

---

## 6. Tampering Detection & Off-Chain Reconciliation

To verify historical institutional integrity:
1. An auditor requests verification for `batchId`.
2. The server loads all constituent leaf commitments from off-chain storage.
3. The server computes the true pairwise Merkle root.
4. The contract function `verifyBatch(batchId, expectedRoot)` is called:
   - **MATCH**: The off-chain audit logs are mathematically proven unmodified since publication.
   - **MISMATCH**: A tampering event is detected, flagged, and highlighted in the admin audit dashboard without silent overwrite.

---

## 7. Implementation Status Breakdown

### Implemented
- `AuditRegistry.sol` compiled and tested with 100% passing tests.
- `ethers` v6 provider and wallet signer integration.
- Real transaction submission and real receipt handling.
- Real `txHash` and real `blockNumber` storage in SQLite `audit_batches`.
- Deployment automation storing deployment artifacts to `blockchain/deployment.json`.
- Non-blocking outage handling (`pending_retry`).
- Batch retry and contract root reconciliation (`MATCH` vs `MISMATCH`).

### Partial
- Automated cron worker for background batch commits (currently exposed as callable service methods `publishBatchCommitment`, `retryPendingBatches`, and manual triggers).

### Simulated
- None in Phase D. The previous mock transaction hash generator and fabricated block numbers have been completely replaced with real `ethers` calls and Hardhat deployment.

### Not Implemented
- Multi-signature contract ownership (standard `Ownable` single-admin contract used for development/testing).
