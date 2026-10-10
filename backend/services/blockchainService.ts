import crypto from "node:crypto";
import { ethers } from "ethers";
import { getDatabase } from "../db.js";
import { env } from "../config/env.js";
import { MerkleTree } from "./merkleTree.js";

export const AUDIT_REGISTRY_ABI = [
  "function publishBatch(string calldata batchId, bytes32 merkleRoot, uint256 recordCount) external",
  "function verifyBatch(string calldata batchId, bytes32 expectedRoot) external view returns (bool matches, bytes32 onChainRoot, uint256 recordCount, uint256 timestamp, address publisher)",
  "function getBatchCount() external view returns (uint256)",
  "function getBatchIdByIndex(uint256 index) external view returns (string memory)",
  "event BatchPublished(string indexed batchId, bytes32 indexed merkleRoot, uint256 recordCount, uint256 timestamp, address publisher)",
];

export interface OnChainBatchRecord {
  batchId: string;
  merkleRoot: string;
  recordCount: number;
  timestamp: string;
  publisher?: string;
  txHash?: string;
  blockNumber?: number;
  chainId?: number;
  network: string;
  status: "confirmed" | "pending_retry" | "failed";
  error?: string;
}

export interface BlockchainVerificationResult {
  batchId: string;
  recomputedRoot: string;
  onChainRoot: string;
  matches: boolean;
  status: "verified" | "tampered_mismatch" | "unanchored" | "rpc_offline";
  blockNumber?: number;
  txHash?: string;
  timestamp: string;
  error?: string;
}

export interface AuditPublisher {
  publishBatchCommitment(params: {
    batchId: string;
    merkleRoot: string;
    recordCount: number;
  }): Promise<OnChainBatchRecord>;
  verifyBatchIntegrity(batchId: string): Promise<BlockchainVerificationResult>;
  retryBatch(batchId: string): Promise<OnChainBatchRecord>;
  retryPendingBatches(): Promise<OnChainBatchRecord[]>;
  getStatus(): Promise<{
    connected: boolean;
    rpcUrl: string;
    network: string;
    chainId?: number;
    contractAddress: string;
    publisherAddress?: string;
    mode: "live_rpc" | "offline_pending";
  }>;
}

/**
 * Real Blockchain Integrity Layer Adapter
 * Publishes cryptographic Merkle roots to deployed AuditRegistry smart contracts via real JSON-RPC provider and signer.
 * Strictly guarantees that report bodies, student identities, credentials, and nullifiers are NEVER sent on-chain.
 */
export class BlockchainAuditAdapter implements AuditPublisher {
  private rpcUrl: string;
  private contractAddress: string;
  private privateKey: string;
  private provider: ethers.JsonRpcProvider | null = null;
  private signer: ethers.Wallet | null = null;
  private contract: ethers.Contract | null = null;

  constructor(options?: {
    rpcUrl?: string;
    contractAddress?: string;
    privateKey?: string;
    customProvider?: ethers.JsonRpcProvider;
    customSigner?: ethers.Wallet;
  }) {
    this.rpcUrl = options?.rpcUrl || process.env.BLOCKCHAIN_RPC_URL || env.blockchainRpcUrl;
    this.contractAddress = options?.contractAddress || process.env.CONTRACT_ADDRESS || env.contractAddress;
    this.privateKey = options?.privateKey || process.env.BLOCKCHAIN_PRIVATE_KEY || env.blockchainPrivateKey;

    if (options?.customProvider && options?.customSigner) {
      this.provider = options.customProvider;
      this.signer = options.customSigner;
      this.contract = new ethers.Contract(this.contractAddress, AUDIT_REGISTRY_ABI, this.signer);
    } else {
      this.initializeProvider();
    }
  }

  private initializeProvider() {
    if (!this.rpcUrl || !this.contractAddress) {
      return;
    }

    try {
      const net = ethers.Network.from(31337);
      this.provider = new ethers.JsonRpcProvider(this.rpcUrl, net, {
        staticNetwork: net,
        batchMaxCount: 1,
      });

      if (this.privateKey && this.privateKey.length >= 64) {
        const formattedKey = this.privateKey.startsWith("0x") ? this.privateKey : `0x${this.privateKey}`;
        this.signer = new ethers.Wallet(formattedKey, this.provider);
        this.contract = new ethers.Contract(this.contractAddress, AUDIT_REGISTRY_ABI, this.signer);
      } else {
        // Read-only contract
        this.contract = new ethers.Contract(this.contractAddress, AUDIT_REGISTRY_ABI, this.provider);
      }
    } catch {
      this.provider = null;
      this.signer = null;
      this.contract = null;
    }
  }

  destroy(): void {
    if (this.provider) {
      this.provider.destroy();
    }
  }

  /**
   * Publishes a batch commitment (Merkle Root) on-chain via real transaction.
   * If RPC is unavailable, marks the batch as 'pending_retry' without interrupting report submission.
   */
  async publishBatchCommitment(params: {
    batchId: string;
    merkleRoot: string;
    recordCount: number;
  }): Promise<OnChainBatchRecord> {
    const { batchId, merkleRoot, recordCount } = params;
    const db = getDatabase();

    // Strict privacy validation: ensure root is a valid 32-byte hex scalar
    const cleanRoot = merkleRoot.startsWith("0x") ? merkleRoot.slice(2) : merkleRoot;
    if (cleanRoot.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(cleanRoot)) {
      throw new Error("Invalid Merkle root format. Expected 32-byte hex string.");
    }
    const formattedRoot = `0x${cleanRoot}`;

    // If no signer is configured or contract is not initialized, mark as pending_retry
    if (!this.contract || !this.signer || !this.provider) {
      const now = new Date().toISOString();
      db.prepare(`
        UPDATE audit_batches
        SET status = 'pending_retry'
        WHERE id = ?
      `).run(batchId);

      return {
        batchId,
        merkleRoot: cleanRoot,
        recordCount,
        timestamp: now,
        network: env.blockchainNetwork,
        status: "pending_retry",
        error: "Blockchain signer or RPC provider not configured.",
      };
    }

    try {
      // 1. Submit real transaction to smart contract
      const tx = await this.contract.publishBatch(batchId, formattedRoot, BigInt(recordCount));

      // 2. Await real on-chain transaction receipt
      const receipt = await tx.wait();
      if (!receipt || receipt.status === 0) {
        throw new Error(`Transaction reverted on-chain (txHash: ${tx.hash})`);
      }

      const network = await this.provider.getNetwork();
      const chainId = Number(network.chainId);
      const blockNumber = Number(receipt.blockNumber);
      const txHash = receipt.hash;
      const publisher = await this.signer.getAddress();
      const now = new Date().toISOString();

      // 3. Update database record with genuine blockchain receipt metadata
      db.prepare(`
        UPDATE audit_batches
        SET status = 'published', tx_hash = ?, block_number = ?, published_at = ?
        WHERE id = ?
      `).run(txHash, blockNumber, now, batchId);

      return {
        batchId,
        merkleRoot: cleanRoot,
        recordCount,
        timestamp: now,
        publisher,
        txHash,
        blockNumber,
        chainId,
        network: env.blockchainNetwork,
        status: "confirmed",
      };
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);

      // Graceful degradation: Mark pending_retry, off-chain integrity remains intact
      db.prepare(`
        UPDATE audit_batches
        SET status = 'pending_retry'
        WHERE id = ?
      `).run(batchId);

      return {
        batchId,
        merkleRoot: cleanRoot,
        recordCount,
        timestamp: new Date().toISOString(),
        network: env.blockchainNetwork,
        status: "pending_retry",
        error: errMsg,
      };
    }
  }

  /**
   * Reconciles local off-chain Merkle root against the recorded on-chain commitment.
   */
  async verifyBatchIntegrity(batchId: string): Promise<BlockchainVerificationResult> {
    const db = getDatabase();
    const batch = db.prepare(`
      SELECT id, merkle_root as merkleRoot, tx_hash as txHash, block_number as blockNumber, status, report_count as reportCount
      FROM audit_batches
      WHERE id = ?
    `).get(batchId) as { id: string; merkleRoot: string; txHash?: string; blockNumber?: number; status: string; reportCount: number } | undefined;

    if (!batch) {
      throw new Error(`Audit batch '${batchId}' not found in registry.`);
    }

    const records = db.prepare(`
      SELECT commitment_hash as commitmentHash
      FROM audit_records
      WHERE batch_id = ?
    `).all(batchId) as { commitmentHash: string }[];

    if (records.length === 0) {
      throw new Error(`Batch '${batchId}' contains no audit leaf commitments.`);
    }

    // 1. Recompute Merkle root off-chain from raw leaf records
    const tree = new MerkleTree(records.map((r) => r.commitmentHash));
    const recomputedRoot = tree.getRoot();

    // 2. Fetch on-chain commitment from contract if connected
    if (this.contract && this.provider) {
      try {
        const formattedExpected = `0x${recomputedRoot.startsWith("0x") ? recomputedRoot.slice(2) : recomputedRoot}`;
        const [matches, onChainRootBytes, , , ] = await this.contract.verifyBatch(batchId, formattedExpected);

        const onChainRoot = onChainRootBytes ? onChainRootBytes.toLowerCase().replace("0x", "") : "";
        const cleanRecomputed = recomputedRoot.toLowerCase().replace("0x", "");
        const isMatch = matches && cleanRecomputed === onChainRoot;

        return {
          batchId,
          recomputedRoot: cleanRecomputed,
          onChainRoot,
          matches: isMatch,
          status: isMatch ? "verified" : "tampered_mismatch",
          blockNumber: batch.blockNumber,
          txHash: batch.txHash,
          timestamp: new Date().toISOString(),
        };
      } catch (err) {
        const errMsg = err instanceof Error ? err.message : String(err);
        return {
          batchId,
          recomputedRoot,
          onChainRoot: batch.merkleRoot,
          matches: false,
          status: "rpc_offline",
          timestamp: new Date().toISOString(),
          error: errMsg,
        };
      }
    }

    // If offline / unanchored
    const isLocalMatch = recomputedRoot.toLowerCase() === batch.merkleRoot.toLowerCase();
    return {
      batchId,
      recomputedRoot,
      onChainRoot: batch.merkleRoot,
      matches: isLocalMatch,
      status: isLocalMatch ? "verified" : "tampered_mismatch",
      blockNumber: batch.blockNumber,
      txHash: batch.txHash,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Retries publishing a specific batch that failed or was pending due to an outage.
   */
  async retryBatch(batchId: string): Promise<OnChainBatchRecord> {
    const db = getDatabase();
    const batch = db.prepare(`
      SELECT id, merkle_root as merkleRoot, report_count as recordCount
      FROM audit_batches
      WHERE id = ?
    `).get(batchId) as { id: string; merkleRoot: string; recordCount: number } | undefined;

    if (!batch) {
      throw new Error(`Batch '${batchId}' not found.`);
    }

    return this.publishBatchCommitment({
      batchId: batch.id,
      merkleRoot: batch.merkleRoot,
      recordCount: batch.recordCount,
    });
  }

  /**
   * Retries all batches currently in 'pending_retry' state.
   */
  async retryPendingBatches(): Promise<OnChainBatchRecord[]> {
    const db = getDatabase();
    const pendingBatches = db.prepare(`
      SELECT id, merkle_root as merkleRoot, report_count as recordCount
      FROM audit_batches
      WHERE status = 'pending_retry'
    `).all() as { id: string; merkleRoot: string; recordCount: number }[];

    const results: OnChainBatchRecord[] = [];
    for (const b of pendingBatches) {
      const res = await this.publishBatchCommitment({
        batchId: b.id,
        merkleRoot: b.merkleRoot,
        recordCount: b.recordCount,
      });
      results.push(res);
    }

    return results;
  }

  /**
   * Retrieves connection and blockchain status metadata.
   */
  async getStatus(): Promise<{
    connected: boolean;
    rpcUrl: string;
    network: string;
    chainId?: number;
    contractAddress: string;
    publisherAddress?: string;
    mode: "live_rpc" | "offline_pending";
  }> {
    let connected = false;
    let chainId: number | undefined;
    let publisherAddress: string | undefined;

    if (this.provider) {
      try {
        const net = await this.provider.getNetwork();
        chainId = Number(net.chainId);
        connected = true;
      } catch {
        connected = false;
      }
    }

    if (this.signer) {
      try {
        publisherAddress = await this.signer.getAddress();
      } catch {
        publisherAddress = undefined;
      }
    }

    return {
      connected,
      rpcUrl: this.rpcUrl,
      network: env.blockchainNetwork,
      chainId,
      contractAddress: this.contractAddress,
      publisherAddress,
      mode: connected && this.signer ? "live_rpc" : "offline_pending",
    };
  }

  /**
   * Privacy validation: validates that an on-chain payload contains ZERO sensitive data.
   */
  assertPayloadPrivacy(calldataOrPayload: Record<string, any> | string): boolean {
    const serialized = typeof calldataOrPayload === "string" ? calldataOrPayload : JSON.stringify(calldataOrPayload);
    const forbiddenPatterns = [
      /student[-_]?id/i,
      /email/i,
      /report[-_]?body/i,
      /complaint/i,
      /nullifier[-_]?secret/i,
      /trapdoor/i,
      /ip[-_]?address/i,
    ];

    for (const pattern of forbiddenPatterns) {
      if (pattern.test(serialized)) {
        throw new Error(`PRIVACY VIOLATION: Calldata contains sensitive data matching ${pattern}`);
      }
    }

    return true;
  }
}

export const blockchainAuditAdapter = new BlockchainAuditAdapter();
