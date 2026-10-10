const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("AuditRegistry Smart Contract Privacy & Integrity Suite", function () {
  let auditRegistry;
  let owner;
  let authorizedPublisher;
  let unauthorizedAccount;

  const sampleBatchId = "batch-2026-001";
  const sampleMerkleRoot = ethers.keccak256(ethers.toUtf8Bytes("incognito-sample-root"));
  const sampleRecordCount = 15;

  beforeEach(async function () {
    [owner, authorizedPublisher, unauthorizedAccount] = await ethers.getSigners();

    const AuditRegistry = await ethers.getContractFactory("AuditRegistry");
    auditRegistry = await AuditRegistry.deploy();
    await auditRegistry.waitForDeployment();

    // Authorize institutional publisher
    await auditRegistry.connect(owner).setPublisher(authorizedPublisher.address, true);
  });

  it("1. Owner can authorize a publisher, unauthorized cannot publish", async function () {
    // Unauthorized attempt
    await expect(
      auditRegistry
        .connect(unauthorizedAccount)
        .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount)
    ).to.be.revertedWith("AuditRegistry: caller is not an authorized publisher");

    // Authorized attempt succeeds
    await expect(
      auditRegistry
        .connect(authorizedPublisher)
        .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount)
    )
      .to.emit(auditRegistry, "BatchPublished")
      .withArgs(
        sampleBatchId,
        sampleMerkleRoot,
        sampleRecordCount,
        await ethers.provider.getBlock("latest").then((b) => b.timestamp + 1),
        authorizedPublisher.address
      );
  });

  it("2. Duplicate batch publication is rejected", async function () {
    await auditRegistry
      .connect(authorizedPublisher)
      .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount);

    await expect(
      auditRegistry
        .connect(authorizedPublisher)
        .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount)
    ).to.be.revertedWith("AuditRegistry: batch already published");
  });

  it("3. Valid Merkle root returns matching verification on-chain", async function () {
    await auditRegistry
      .connect(authorizedPublisher)
      .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount);

    const [matches, onChainRoot, count, timestamp, publisher] = await auditRegistry.verifyBatch(
      sampleBatchId,
      sampleMerkleRoot
    );

    expect(matches).to.equal(true);
    expect(onChainRoot).to.equal(sampleMerkleRoot);
    expect(count).to.equal(sampleRecordCount);
    expect(publisher).to.equal(authorizedPublisher.address);
    expect(timestamp).to.be.gt(0);
  });

  it("4. Wrong Merkle root returns false match", async function () {
    await auditRegistry
      .connect(authorizedPublisher)
      .publishBatch(sampleBatchId, sampleMerkleRoot, sampleRecordCount);

    const wrongRoot = ethers.keccak256(ethers.toUtf8Bytes("different-wrong-root"));
    const [matches] = await auditRegistry.verifyBatch(sampleBatchId, wrongRoot);

    expect(matches).to.equal(false);
  });

  it("5. Zero address or zero root validation", async function () {
    await expect(
      auditRegistry
        .connect(authorizedPublisher)
        .publishBatch("batch-zero", ethers.ZeroHash, 5)
    ).to.be.revertedWith("AuditRegistry: zero Merkle root");

    await expect(
      auditRegistry
        .connect(owner)
        .setPublisher(ethers.ZeroAddress, true)
    ).to.be.revertedWith("AuditRegistry: zero address");
  });
});
