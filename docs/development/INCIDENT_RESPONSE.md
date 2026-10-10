# Incognito — Security Incident Response Protocol

## 1. Incident Classification

| Severity | Definition | Examples | Response SLA |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | Potential reporter deanonymization or encryption key compromise | KMS master key leaked, ZK verification bypass discovered, unauthorized DB join possible | **Immediate (< 1 hour)** |
| **HIGH** | Outage of cryptographic audit anchoring or moderation bypass | On-chain Merkle root mismatch, automated prompt injection jailbreak in wild, multi-RPC failure | **< 4 hours** |
| **MEDIUM** | Performance degradation or failover triggering | Primary RPC failed to backup RPC, AI provider rate-limited falling back to human review | **< 12 hours** |
| **LOW** | Minor policy discrepancy or UI anomaly | Formatting glitch on audit explorer, benign false-positive signal | **< 48 hours** |

---

## 2. Response Procedures

### 2.1 KMS Key Compromise (CRITICAL)
1. Immediately rotate KMS master key in Google Cloud KMS / AWS KMS / Azure Key Vault.
2. Invalidate existing backend container credentials.
3. Re-encrypt all active database records using the new key version via `KeyManagementService.deriveSubkey()`.
4. Publish an incident disclosure notice on the public institutional status page.

### 2.2 On-Chain Merkle Root Mismatch (CRITICAL)
1. Run automated reconciliation audit: `blockchainAuditAdapter.verifyBatchIntegrity(batchId)`.
2. Compare local database leaves against cold storage snapshots.
3. Isolate the affected database replica from production traffic to prevent further tampering.
4. Notify the institutional ombudsperson and independent ethics board.

### 2.3 External Provider Outage (AI / Blockchain)
1. The backend automatically switches AI evaluation to `review_required` / human review queue.
2. The backend automatically queues audit roots as `pending_retry`.
3. Operations team monitors `metricsService.getSnapshot()` for queue depth and triggers `retryPendingBatches()` once upstream connectivity is restored.
