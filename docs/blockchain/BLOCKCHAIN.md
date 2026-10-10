# Incognito — Blockchain Audit Architecture & Smart Contract Integration

## 1. Overview

Incognito provides cryptographic proof that reports and case metrics cannot be retroactively deleted, suppressed, or modified by administrators. This is accomplished by publishing binary Merkle roots of audit commitment hashes to the `AuditRegistry.sol` EVM smart contract.

---

## 2. On-Chain Data Minimization

> [!IMPORTANT]
> **Strict Privacy Guarantee**: Calldata sent to the blockchain contains **zero whistleblower disclosures**, zero student names or IDs, and zero nullifiers.

The contract stores only:
- `batchId`: String identifier (e.g., `batch-101`)
- `merkleRoot`: 32-byte cryptographic scalar ($H$)
- `recordCount`: Integer count of cases in the batch
- `timestamp`: Block timestamp
- `publisher`: Institutional relayer wallet address

---

## 3. Pairwise Balanced Merkle Tree

Leaves are constructed off-chain as:
$$\text{Leaf}_i = \text{SHA256}(\text{ReportReference}_i \parallel \text{Nullifier}_i)$$

Leaves are paired iteratively to compute a balanced binary Merkle tree root:
$$\text{Parent} = \text{SHA256}(\text{Left} \parallel \text{Right})$$

---

## 4. Multi-RPC Failover & Outage Resilience

The `BlockchainAuditAdapter` handles network failures gracefully:
1. **Primary & Backup RPC**: Automatically fails over from primary RPC (Alchemy) to secondary backup RPC (Infura) upon connection error.
2. **Offline Queuing**: If all RPCs are unavailable, the batch is marked as `pending_retry` in the database without failing report submission.
3. **Reconciliation**: Automated reconciliation recomputes the Merkle root from stored leaves and compares it with the on-chain value. Any database tampering immediately results in a `tampered_mismatch` alert.
