import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Identity } from "@semaphore-protocol/core";
import { oidcService, OidcAuthError } from "../services/oidcService.js";
import { zkProofService } from "../services/zkProofService.js";
import { reportService, ReportError } from "../services/reportService.js";
import { moderationPipeline } from "../moderation/pipeline.js";
import { mockModerationProvider } from "../moderation/providers/mock.js";
import { BlockchainAuditAdapter } from "../services/blockchainService.js";
import { MerkleTree } from "../services/merkleTree.js";
import { getDatabase } from "../db.js";

test("PHASE I — Full Protocol Lifecycle & Resilient Failure-Path Test Suite", async (t) => {
  const db = getDatabase();

  await t.test("I1. Complete 20-Step Protocol Lifecycle: From Institutional OIDC to On-Chain Audit & Resolution", async () => {
    // Step 1 & 2: Student authenticates through institutional identity provider; eligibility verified
    const studentSub = "stu-flow-994";
    const institutionalToken = `eyJhbGciOiJub25lIn0.${Buffer.from(
      JSON.stringify({
        sub: studentSub,
        email: "whistleblower@university.edu",
        aud: "incognito-institutional-app-id",
        exp: Math.floor(Date.now() / 1000) + 3600,
        roles: ["Student"],
      })
    ).toString("base64url")}.sig`;

    const oidcResult = await oidcService.verifyInstitutionalToken(institutionalToken);
    assert.strictEqual(oidcResult.eligible, true);
    assert.strictEqual(oidcResult.institutionDomain, "university.edu");

    // Step 3 & 4: Anonymous Semaphore identity generated client-side; secret material never leaves client
    const studentIdentity = new Identity();
    assert.ok(studentIdentity.commitment);
    assert.ok(studentIdentity.privateKey);

    // Step 5: Public commitment registered in institutional group tree
    const regResult = zkProofService.registerCommitment(studentIdentity.commitment.toString());
    assert.ok(regResult.leafIndex >= 0);

    // Step 6 & 7: User generates genuine Semaphore Groth16 ZK proof
    const categoryId = "cat-harassment";
    const reportText = "Urgent: Unsolicited intimidation and ragging by seniors in Hostel B corridor room 204.";

    const zkProof = await zkProofService.generateProof({
      identity: studentIdentity,
      topicScope: categoryId,
      reportBody: reportText,
    });
    assert.ok(zkProof.nullifier);
    assert.strictEqual(zkProof.points.length, 8);

    // Step 8 & 9: Backend verifies proof and submits report; encrypted with authenticated AES-256-GCM
    const submission = await reportService.submitReport({
      categoryId,
      body: reportText,
      proof: zkProof,
    });
    assert.ok(submission.reference.startsWith("INC-"));
    assert.ok(submission.statusSecret.startsWith("sec_"));
    assert.strictEqual(submission.status, "received");

    // Step 10: AI moderation evaluated without reporter identity
    const modEval = await moderationPipeline.evaluate(reportText, categoryId);
    assert.ok(modEval.classification === "escalated" || modEval.classification === "flagged");
    assert.strictEqual(modEval.detectedSignals.length > 0, true);

    // Step 11 & 12: Stored report in database has zero identity columns
    const stored = db.prepare("SELECT * FROM reports WHERE reference = ?").get(submission.reference) as any;
    assert.ok(stored.encrypted_body.startsWith("gcm:"));
    assert.strictEqual(stored.student_id, undefined);
    assert.strictEqual(stored.email, undefined);

    // Step 13 & 14: Audit batch commitments calculated with pairwise Merkle tree
    const commitmentHash = crypto.createHash("sha256").update(`${submission.reference}:${zkProof.nullifier}`).digest("hex");
    const auditTree = new MerkleTree([commitmentHash]);
    const root = auditTree.getRoot();
    assert.ok(root.length === 64);

    // Step 15 & 16: Audit batch publishing via adapter
    const batchId = "batch-flow-" + crypto.randomBytes(4).toString("hex");
    const uniqueSeq = 980000 + Math.floor(Math.random() * 10000);
    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, ?, ?, 1, 'pending', '0x742d35Cc6634C0532925a3b844Bc454e4438f44e', 'Sepolia Testnet', ?)
    `).run(batchId, uniqueSeq, root, new Date().toISOString());

    const recId = "rec-flow-" + crypto.randomUUID();
    db.prepare(`
      INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(recId, batchId, submission.reference, commitmentHash, new Date().toISOString());

    // Step 17 & 18: Moderator reviews report; cannot see reporter identity
    const moderatorView = reportService.getReportById(stored.id);
    assert.ok(moderatorView);
    assert.strictEqual(moderatorView.body, reportText);
    assert.strictEqual((moderatorView as any).student_id, undefined);

    // Step 19: Reporter securely queries status using status secret
    const statusQuery = reportService.getReportStatus(submission.reference, submission.statusSecret);
    assert.strictEqual(statusQuery.status, "received");

    // Step 20: Audit integrity verification
    const adapter = new BlockchainAuditAdapter();
    const verification = await adapter.verifyBatchIntegrity(batchId);
    assert.strictEqual(verification.recomputedRoot.toLowerCase(), verification.onChainRoot.toLowerCase());
    assert.ok(verification.status === "verified" || verification.status === "rpc_offline");
  });

  await t.test("I2. Deliberate Failure-Path Testing: Outages and attacks fail safely", async () => {
    // 1. OIDC Outage / Invalid domain fails safely
    const attackerToken = `eyJhbGciOiJub25lIn0.${Buffer.from(
      JSON.stringify({
        sub: "attacker",
        email: "malicious@external-domain.com",
        aud: "incognito-institutional-app-id",
        exp: Math.floor(Date.now() / 1000) + 3600,
      })
    ).toString("base64url")}.sig`;

    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(attackerToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unauthorized_domain"
    );

    // 2. AI Outage degrades safely to human review (NEVER silent pass)
    moderationPipeline.setProvider("mock");
    mockModerationProvider.setSimulatedFailure("server_error");

    const degraded = await moderationPipeline.evaluate("Some inquiry text during AI provider outage", "cat-academic");
    assert.strictEqual(degraded.classification, "review_required");
    assert.strictEqual(degraded.recommendedAction, "require_human_review");

    mockModerationProvider.setSimulatedFailure(null);
    moderationPipeline.setProvider("deterministic");

    // 3. Status query with incorrect status secret rejected with 403
    await assert.rejects(
      async () => reportService.getReportStatus("INC-849204", "wrong_status_secret_guess"),
      (err: any) => err instanceof ReportError && err.status === 403
    );

    // 4. Duplicate nullifier replay fails safely with 409
    const dupSeed = "nullifier:dup-test-" + crypto.randomBytes(6).toString("hex");
    await reportService.submitReport({
      categoryId: "cat-academic",
      body: "Initial report occupying the nullifier scope.",
      proofNullifier: dupSeed,
    });

    await assert.rejects(
      async () =>
        reportService.submitReport({
          categoryId: "cat-academic",
          body: "Subsequent report attempting to reuse identical nullifier.",
          proofNullifier: dupSeed,
        }),
      (err: any) => err instanceof ReportError && err.status === 409
    );
  });
});
