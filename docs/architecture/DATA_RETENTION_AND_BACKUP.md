# Incognito: Data Retention, Backup & Disaster Recovery Architecture

## 1. Overview & Privacy Design Principles

Incognito implements privacy by design. A fundamental requirement of this architecture is **data minimization** and the **right-to-be-forgotten**, balanced with **tamper-evident auditability**.

---

## 2. Retention Schedules

| Data Entity | Retention Duration | Disposal Action | Technical Guarantee |
| :--- | :--- | :--- | :--- |
| **Active Reports (`received`, `under_review`)** | Until resolution + 365 days | Kept encrypted at rest | Authenticated AES-256-GCM with KMS key |
| **Closed Reports (`closed`, `action_taken`)** | 365 days post-closure | Redact `encrypted_body` -> `[PURGED]` | Nullifier, reference, and Merkle leaf retained for tamper audit; raw body irrecoverably destroyed |
| **Blockchain Audit Batches** | **Permanent (Immutable)** | **NEVER DELETED** | Published as 32-byte Merkle root on Ethereum / Sepolia smart contract |
| **Audit Leaf Records** | Permanent | Maintained for proof reconciliation | Off-chain commitment hash `H(reference || nullifier)` matches on-chain root |
| **Security Events & Outage Logs** | 90 days | Truncated / Rotated | Contains zero user PII, credentials, or report bodies |
| **Ephemeral Session Secrets / Nonces** | 24 hours | Expired & memory purged | Used only during ZK proof generation and status checks |

---

## 3. Immutable On-Chain Evidence vs. Ephemeral Data

> [!IMPORTANT]
> **What Can Be Deleted:**
> - Encrypted report bodies after resolution retention window (365 days).
> - Ephemeral tokens, dev credentials, and rotated keys.
> - Diagnostic logs and transient metrics.

> [!CAUTION]
> **What CANNOT Be Deleted:**
> - On-chain Merkle root commitments stored in the `AuditRegistry.sol` contract.
> - Transaction hashes, block numbers, and sequencer timestamps.
> - Topic nullifiers in the registry (required indefinitely to prevent retroactive double-reporting replay attacks).

---

## 4. PostgreSQL Backup Procedures

### 4.1 Automated Daily Encrypted Snapshots

```bash
# 1. Take consistent binary snapshot with custom format
pg_dump -U incognito_app -h localhost -p 5432 -d incognito_db -Fc -f /backup/incognito_$(date +%Y%m%d_%H%M%S).dump

# 2. Encrypt backup archive using AES-256 with KMS-managed backup key
openssl enc -aes-256-gcm -salt -in /backup/incognito_*.dump -out /backup/encrypted/incognito_*.dump.enc -pass file:/etc/incognito/backup_key.bin

# 3. Ship encrypted archive to air-gapped immutable cloud storage (e.g., AWS S3 Glacier with Object Lock or GCS Bucket Lock)
```

### 4.2 Backup Encryption & Key Management
- Backups are encrypted **before** leaving the database host.
- Backup encryption keys are managed separately in Google Cloud KMS / AWS KMS / Azure Key Vault.
- Database credentials and application KMS keys are never stored in the database dump.

---

## 5. Disaster Recovery & Restoration Verification

### 5.1 Step-by-Step Restoration Procedure

1. **Provision Clean PostgreSQL Instance:**
   ```bash
   docker compose up -d postgres
   ```
2. **Decrypt Archive:**
   ```bash
   openssl enc -d -aes-256-gcm -in backup.dump.enc -out restored.dump -pass file:/etc/incognito/backup_key.bin
   ```
3. **Restore Database:**
   ```bash
   pg_restore -U incognito_app -d incognito_db -c --if-exists restored.dump
   ```
4. **Run On-Chain Reconciliation Check:**
   ```bash
   # Recompute Merkle root for all restored batches and compare with deployed AuditRegistry smart contract
   npm run test:backend
   ```
   If any database tampering occurred during recovery, the on-chain root mismatch will immediately be flagged with status `tampered_mismatch`.

---

## 6. Production Database Security Controls

1. **Least-Privilege User:** Application connects as `incognito_app`, which owns tables in `incognito_db` but has no superuser privileges and cannot access other database clusters.
2. **No Public Internet Exposure:** Database binds strictly to private VPC / localhost (`127.0.0.1`).
3. **TLS Enforcement:** All production database connections must specify `sslmode=require` or `sslmode=verify-full`.
4. **Connection Pooling:** Controlled via `pg.Pool` (max 20 connections, idle timeout 30s) to prevent resource starvation.
