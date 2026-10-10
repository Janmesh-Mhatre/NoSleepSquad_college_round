export interface AuditBatchRecord {
  id: string;
  sequence: number;
  merkleRoot: string;
  reportCount: number;
  status: "pending" | "published" | "verified" | "delayed" | "blockchain_unavailable";
  contractAddress: string;
  network: string;
  txHash?: string;
  blockNumber?: number;
  createdAt: string;
  publishedAt?: string;
}

export interface AuditRecordItem {
  id: string;
  batchId: string;
  reportReference: string;
  commitmentHash: string;
  createdAt: string;
}

export interface AuditVerificationResult {
  batchId: string;
  sequence: number;
  calculatedMerkleRoot: string;
  publishedMerkleRoot: string;
  matches: boolean;
  status: "verified" | "mismatch";
  blockNumber?: number;
  txHash?: string;
  timestamp: string;
}
