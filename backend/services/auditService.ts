import crypto from "node:crypto";
import { getDatabase } from "../db.js";
import type { AuditBatchRecord, AuditRecordItem, AuditVerificationResult } from "../models/audit.js";
import { MerkleTree } from "./merkleTree.js";

export class AuditService {
  getBatches(): AuditBatchRecord[] {
    const db = getDatabase();
    const rows = db.prepare(`
      SELECT 
        id, 
        sequence, 
        merkle_root as merkleRoot, 
        report_count as reportCount, 
        status, 
        contract_address as contractAddress, 
        network, 
        tx_hash as txHash, 
        block_number as blockNumber, 
        created_at as createdAt, 
        published_at as publishedAt
      FROM audit_batches
      ORDER BY sequence DESC
    `).all() as unknown as AuditBatchRecord[];

    return rows;
  }

  getBatchRecords(batchId: string): AuditRecordItem[] {
    const db = getDatabase();
    const rows = db.prepare(`
      SELECT 
        id, 
        batch_id as batchId, 
        report_reference as reportReference, 
        commitment_hash as commitmentHash, 
        created_at as createdAt
      FROM audit_records
      WHERE batch_id = ?
    `).all(batchId) as unknown as AuditRecordItem[];

    return rows;
  }

  verifyBatch(batchId: string): AuditVerificationResult {
    const db = getDatabase();
    const batch = db.prepare(`
      SELECT 
        id, 
        sequence, 
        merkle_root as merkleRoot, 
        report_count as reportCount, 
        status, 
        contract_address as contractAddress, 
        network, 
        tx_hash as txHash, 
        block_number as blockNumber
      FROM audit_batches
      WHERE id = ?
    `).get(batchId) as unknown as AuditBatchRecord | undefined;

    if (!batch) {
      throw new Error("Audit batch not found.");
    }

    const records = this.getBatchRecords(batchId);
    if (records.length === 0) {
      throw new Error("No audit records found for this batch.");
    }

    // Recompute true Merkle root via pairwise balanced Merkle tree
    const leaves = records.map(r => r.commitmentHash);
    const tree = new MerkleTree(leaves);
    const calculatedRoot = tree.getRoot();

    const matches = calculatedRoot === batch.merkleRoot;

    return {
      batchId: batch.id,
      sequence: batch.sequence,
      calculatedMerkleRoot: calculatedRoot,
      publishedMerkleRoot: batch.merkleRoot,
      matches,
      status: matches ? "verified" : "mismatch",
      blockNumber: batch.blockNumber,
      txHash: batch.txHash,
      timestamp: new Date().toISOString(),
    };
  }

  getQueueStatus() {
    const db = getDatabase();
    const uncommitted = db.prepare("SELECT count(*) as c FROM reports WHERE audit_committed = 0").get() as { c: number };
    const latestBatch = db.prepare("SELECT sequence, merkle_root, created_at, status FROM audit_batches ORDER BY sequence DESC LIMIT 1").get() as any;

    return {
      pendingReportsInQueue: uncommitted.c,
      batchIntervalMinutes: 60,
      nextScheduledBatch: new Date(Date.now() + 25 * 60 * 1000).toISOString(),
      latestPublishedBatch: latestBatch ? {
        sequence: latestBatch.sequence,
        root: latestBatch.merkle_root,
        status: latestBatch.status,
        timestamp: latestBatch.created_at,
      } : null,
      blockchainStatus: "connected",
    };
  }
}

export const auditService = new AuditService();
