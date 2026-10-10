
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import hre from "hardhat";
import { ethers } from "ethers";
import { MerkleTree } from "../services/merkleTree.js";
import {
  BlockchainAuditAdapter,
  AUDIT_REGISTRY_ABI,
} from "../services/blockchainService.js";
import { getDatabase } from "../db.js";

test("PHASE D — Real Blockchain Audit & Smart Contract Integrity", async (t) => {
  // 1. Deploy real AuditRegistry contract using Hardhat
  const AuditRegistryFactory = await (hre as any).ethers.getContractFactory("AuditRegistry");
  const deployedContract = await AuditRegistryFactory.deploy();
  await deployedContract.waitForDeployment();
  const contractAddress = await deployedContract.getAddress();

  const [ownerSigner, unauthorizedSigner] = await (hre as any).ethers.getSigners();
  const ownerAddress = await ownerSigner.getAddress();

  // Connect BlockchainAuditAdapter directly to this real in-process contract
  const adapter = new BlockchainAuditAdapter({
    contractAddress,
    customProvider: (hre as any).ethers.provider,
    customSigner: ownerSigner,
  });

  const leaves = [
    crypto.createHash("sha256").update("audit-record-incident-01").digest("hex"),
    crypto.createHash("sha256").update("audit-record-incident-02").digest("hex"),
    crypto.createHash("sha256").update("audit-record-incident-03").digest("hex"),
  ];
  const tree = new MerkleTree(leaves);
  const trueRoot = tree.getRoot();

  await t.test("D1. Real Pairwise Balanced Merkle Tree generates deterministic root and proofs", () => {
    const tree2 = new MerkleTree(leaves);
    assert.equal(tree.getRoot(), tree2.getRoot());
    assert.equal(tree.getRoot().length, 64);

    for (let i = 0; i < leaves.length; i++) {
      const proof = tree.getProof(i);
      assert.equal(proof.leafIndex, i);
      assert.equal(MerkleTree.verifyProof(proof), true);
    }
  });

  await t.test("D2. Tamper detection: modifying leaf data alters Merkle root", () => {
    const tamperedLeaves = [...leaves];
    tamperedLeaves[0] = crypto.createHash("sha256").update("tampered-incident-data").digest("hex");
    const tamperedTree = new MerkleTree(tamperedLeaves);
    assert.notEqual(tamperedTree.getRoot(), trueRoot);
  });

  await t.test("D3. Smart contract authorization: unauthorized account cannot publish", async () => {
    const unauthorizedContract = deployedContract.connect(unauthorizedSigner);
    const fakeRoot = "0x" + "b".repeat(64);

    await assert.rejects(
      async () => {
        await (unauthorizedContract as any).publishBatch("batch-unauth-test", fakeRoot, 5);
      },
      /AuditRegistry: caller is not an authorized publisher/
    );
  });

  await t.test("D4. Real transaction submission: receipt yields genuine txHash and blockNumber", async () => {
    const batchId = "batch-real-tx-" + Date.now();
    const db = getDatabase();
    const now = new Date().toISOString();

    // Insert batch in local SQLite
    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 3, 'created', ?, 'Hardhat Local', ?)
    `).run(batchId, trueRoot, contractAddress, now);

    for (let i = 0; i < leaves.length; i++) {
      db.prepare(`
        INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(`rec-d4-${i}-${Date.now()}`, batchId, `INC-REF-${i}`, leaves[i], now);
    }

    // Submit via real blockchain adapter
    const result = await adapter.publishBatchCommitment({
      batchId,
      merkleRoot: trueRoot,
      recordCount: leaves.length,
    });

    assert.equal(result.status, "confirmed");
    assert.ok(result.txHash, "Transaction hash must be returned from real provider");
    assert.ok(typeof result.blockNumber === "number" && result.blockNumber > 0, "Receipt must contain real block number");
    assert.equal(result.publisher?.toLowerCase(), ownerAddress.toLowerCase());

    // Verify stored database metadata matches real receipt
    const row = db.prepare("SELECT status, tx_hash, block_number FROM audit_batches WHERE id = ?").get(batchId) as any;
    assert.equal(row.status, "published");
    assert.equal(row.tx_hash, result.txHash);
    assert.equal(row.block_number, result.blockNumber);
  });

  await t.test("D5. On-chain read and root reconciliation: contract verifies matching root", async () => {
    const batchId = "batch-reconcile-" + Date.now();
    const db = getDatabase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 3, 'created', ?, 'Hardhat Local', ?)
    `).run(batchId, trueRoot, contractAddress, now);

    for (let i = 0; i < leaves.length; i++) {
      db.prepare(`
        INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at)
        VALUES (?, ?, ?, ?, ?)
      `).run(`rec-d5-${i}-${Date.now()}`, batchId, `INC-REF-${i}`, leaves[i], now);
    }

    await adapter.publishBatchCommitment({
      batchId,
      merkleRoot: trueRoot,
      recordCount: leaves.length,
    });

    // Reconcile
    const reconciliation = await adapter.verifyBatchIntegrity(batchId);
    assert.equal(reconciliation.matches, true, "Contract on-chain root must match recomputed local Merkle tree");
    assert.equal(reconciliation.status, "verified");
    assert.equal(reconciliation.onChainRoot.toLowerCase(), trueRoot.toLowerCase());
  });

  await t.test("D6. Duplicate batch publication rejected on-chain", async () => {
    const batchId = "batch-duplicate-" + Date.now();
    const db = getDatabase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 3, 'created', ?, 'Hardhat Local', ?)
    `).run(batchId, trueRoot, contractAddress, now);

    // First publication succeeds
    const first = await adapter.publishBatchCommitment({
      batchId,
      merkleRoot: trueRoot,
      recordCount: 3,
    });
    assert.equal(first.status, "confirmed");

    // Second publication under same batch ID is rejected by contract
    const second = await adapter.publishBatchCommitment({
      batchId,
      merkleRoot: trueRoot,
      recordCount: 3,
    });
    assert.equal(second.status, "pending_retry");
    assert.ok(second.error?.includes("batch already published"));
  });

  await t.test("D7. Outage resilience: RPC failure marks batch pending_retry without crashing reporting", async () => {
    // Create adapter with offline / unreachable RPC URL
    const brokenAdapter = new BlockchainAuditAdapter({
      rpcUrl: "http://127.0.0.1:54321", // non-existent RPC endpoint
      contractAddress,
      privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
    });

    const batchId = "batch-outage-" + Date.now();
    const db = getDatabase();
    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 1, 'created', ?, 'Offline Network', ?)
    `).run(batchId, trueRoot, contractAddress, new Date().toISOString());

    try {
      const result = await brokenAdapter.publishBatchCommitment({
        batchId,
        merkleRoot: trueRoot,
        recordCount: 1,
      });

      // Does not throw fatal error, marks pending_retry
      assert.equal(result.status, "pending_retry");
      assert.ok(result.error);

      const dbRow = db.prepare("SELECT status FROM audit_batches WHERE id = ?").get(batchId) as any;
      assert.equal(dbRow.status, "pending_retry");
    } finally {
      brokenAdapter.destroy();
    }
  });

  await t.test("D8. Retry mechanism: successfully republishes pending batches", async () => {
    const batchId = "batch-retry-test-" + Date.now();
    const db = getDatabase();
    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 2, 'pending_retry', ?, 'Hardhat Local', ?)
    `).run(batchId, trueRoot, contractAddress, new Date().toISOString());

    // Retry through live adapter
    const retryResult = await adapter.retryBatch(batchId);
    assert.equal(retryResult.status, "confirmed");
    assert.ok(retryResult.txHash);

    const dbRow = db.prepare("SELECT status, tx_hash FROM audit_batches WHERE id = ?").get(batchId) as any;
    assert.equal(dbRow.status, "published");
    assert.equal(dbRow.tx_hash, retryResult.txHash);
  });

  await t.test("D9. Reconciliation detects tamper mismatch without overwriting local values", async () => {
    const batchId = "batch-tamper-recon-" + Date.now();
    const db = getDatabase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM audit_batches), ?, 2, 'created', ?, 'Hardhat Local', ?)
    `).run(batchId, trueRoot, contractAddress, now);

    // Published on-chain with trueRoot
    await adapter.publishBatchCommitment({
      batchId,
      merkleRoot: trueRoot,
      recordCount: 2,
    });

    // An attacker tampers with off-chain records table
    const forgedHash = crypto.createHash("sha256").update("forged-evidence").digest("hex");
    db.prepare(`
      INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at)
      VALUES (?, ?, 'INC-TAMPERED', ?, ?)
    `).run(`rec-tamper-${Date.now()}`, batchId, forgedHash, now);

    // Reconcile
    const recon = await adapter.verifyBatchIntegrity(batchId);
    assert.equal(recon.matches, false);
    assert.equal(recon.status, "tampered_mismatch");

    // Local recorded Merkle root must NOT be silently overwritten
    const localBatch = db.prepare("SELECT merkle_root FROM audit_batches WHERE id = ?").get(batchId) as any;
    assert.equal(localBatch.merkle_root, trueRoot);
  });

  await t.test("D10. Strict privacy on-chain: calldata payload contains zero report bodies or identities", () => {
    const validOnChainData = {
      batchId: "batch-101",
      merkleRoot: "0x" + "c".repeat(64),
      recordCount: 10,
    };
    assert.equal(adapter.assertPayloadPrivacy(validOnChainData), true);

    const leakyData = {
      ...validOnChainData,
      report_body: "Confidential misconduct complaint",
    };
    assert.throws(
      () => adapter.assertPayloadPrivacy(leakyData),
      /PRIVACY VIOLATION/
    );
  });

  // Clean up ephemeral test batches created in this test suite
  const db = getDatabase();
  db.prepare("DELETE FROM audit_batches WHERE id LIKE 'batch-%' AND id != 'batch-101'").run();
  db.prepare("DELETE FROM audit_records WHERE batch_id LIKE 'batch-%' AND batch_id != 'batch-101'").run();
});
