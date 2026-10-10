import test from "node:test";
import assert from "node:assert/strict";
import { Identity, Group } from "@semaphore-protocol/core";
import { zkProofService, type ZkMembershipProof } from "../services/zkProofService.js";
import { ReportService, ReportError } from "../services/reportService.js";
import { SqliteMembershipService } from "../services/membershipService.js";

test("PHASE B — Real Semaphore Zero-Knowledge Anonymous Membership Proofs", async (t) => {
  const reportService = new ReportService();
  const membershipService = new SqliteMembershipService();

  // 1. Generate real Semaphore identities
  const alice = new Identity();
  const bob = new Identity();

  // 2. Register Alice in institutional membership group
  const regResult = zkProofService.registerCommitment(alice.commitment.toString());
  assert.ok(regResult.leafIndex >= 0, "Alice must be assigned a leaf index");
  assert.ok(regResult.root.length > 0, "Group root must be present");

  const testCategory = "cat-safety";
  const testReportBody = "Valid safety hazard report regarding ungrounded high-voltage power transformer in engineering bay " + Date.now();

  await t.test("B1. Valid genuine Semaphore Groth16 ZK proof generated and verified", async () => {
    const proof = await zkProofService.generateProof({
      identity: alice,
      topicScope: testCategory,
      reportBody: testReportBody,
    });

    assert.ok(proof.nullifier, "Proof must contain a derived nullifier");
    assert.ok(proof.points.length === 8, "Packed Groth16 proof must contain 8 scalar points");
    assert.equal(proof.merkleTreeRoot, zkProofService.getActiveRoot());

    const verification = await zkProofService.verifyProof(proof, testCategory, testReportBody);
    assert.equal(verification.valid, true, "Valid Semaphore Groth16 proof must pass verification");
  });

  await t.test("B2. Forged / tampered Groth16 proof points are rejected", async () => {
    const proof = await zkProofService.generateProof({
      identity: alice,
      topicScope: testCategory,
      reportBody: testReportBody,
    });

    // Tamper with Groth16 proof point
    const forgedProof: ZkMembershipProof = {
      ...proof,
      points: [
        "1234567890123456789012345678901234567890",
        proof.points[1],
        proof.points[2],
        proof.points[3],
        proof.points[4],
        proof.points[5],
        proof.points[6],
        proof.points[7],
      ],
    };

    const verification = await zkProofService.verifyProof(forgedProof, testCategory, testReportBody);
    assert.equal(verification.valid, false);
    assert.ok(verification.reason?.includes("verification failed") || verification.reason?.includes("error"));
  });

  await t.test("B3. Non-member identity proof rejected against active institutional root", async () => {
    // Bob is NOT registered in institutional tree
    // If Bob generates a proof using his own single-member group, its root won't match institutional registry
    const bobGroup = new Group([bob.commitment]);
    const bobProof = await zkProofService.generateProof({
      identity: bob,
      group: bobGroup,
      topicScope: testCategory,
      reportBody: testReportBody,
    });

    const verification = await zkProofService.verifyProof(bobProof, testCategory, testReportBody);
    assert.equal(verification.valid, false);
    assert.ok(verification.reason?.includes("Merkle root is not active"));
  });

  await t.test("B4. Signal mismatch: front-running or report alteration rejected", async () => {
    const proof = await zkProofService.generateProof({
      identity: alice,
      topicScope: testCategory,
      reportBody: testReportBody,
    });

    const alteredReport = "Tampered report text trying to reuse Alice's anonymous zero-knowledge proof " + Date.now();
    const verification = await zkProofService.verifyProof(proof, testCategory, alteredReport);
    assert.equal(verification.valid, false);
    assert.ok(verification.reason?.includes("does not bind"));
  });

  await t.test("B5. Wrong topic scope rejected", async () => {
    const proof = await zkProofService.generateProof({
      identity: alice,
      topicScope: "cat-harassment",
      reportBody: testReportBody,
    });

    const verification = await zkProofService.verifyProof(proof, "cat-facilities", testReportBody);
    assert.equal(verification.valid, false);
    assert.ok(verification.reason?.includes("topic scope"));
  });

  await t.test("B6. Topic-scoped nullifiers guarantee cross-topic unlinkability", async () => {
    const proofSafety = await zkProofService.generateProof({
      identity: alice,
      topicScope: "cat-safety",
      reportBody: testReportBody,
    });

    const proofHarassment = await zkProofService.generateProof({
      identity: alice,
      topicScope: "cat-harassment",
      reportBody: testReportBody,
    });

    assert.notEqual(
      proofSafety.nullifier,
      proofHarassment.nullifier,
      "Nullifiers across different topics must be cryptographically distinct"
    );
  });

  await t.test("B7. Same-topic duplicate prevention produces deterministic identical nullifier", async () => {
    const report1 = "First report under safety category " + Date.now();
    const report2 = "Second different report under safety category " + Date.now();

    const proof1 = await zkProofService.generateProof({
      identity: alice,
      topicScope: "cat-safety",
      reportBody: report1,
    });

    const proof2 = await zkProofService.generateProof({
      identity: alice,
      topicScope: "cat-safety",
      reportBody: report2,
    });

    assert.equal(
      proof1.nullifier,
      proof2.nullifier,
      "Same member in same topic scope must always yield identical nullifier for double-submission prevention"
    );
  });

  await t.test("B8. Identity secrecy: public proof leaks zero identity secrets or commitments", async () => {
    const proof = await zkProofService.generateProof({
      identity: alice,
      topicScope: testCategory,
      reportBody: testReportBody,
    });

    const proofString = JSON.stringify(proof);
    // Ensure Alice's private key / secret scalar is not anywhere in the proof
    assert.equal(proofString.includes(alice.privateKey.toString()), false);
    assert.equal(proofString.includes(alice.secretScalar.toString()), false);
    // Crucially, in genuine Semaphore, Alice's commitment is also NOT in the public proof
    assert.equal(proofString.includes(alice.commitment.toString()), false);
  });

  await t.test("B9. Revoked member cannot generate valid proofs against updated tree", async () => {
    const charlie = new Identity();
    zkProofService.registerCommitment(charlie.commitment.toString());

    // Revoke Charlie
    zkProofService.revokeCommitment(charlie.commitment.toString());

    // Charlie's commitment is no longer in the active group
    assert.equal(zkProofService.getGroup().indexOf(charlie.commitment), -1);

    // Attempting proof generation against active group fails because Charlie is not in tree
    await assert.rejects(
      async () => {
        await zkProofService.generateProof({
          identity: charlie,
          topicScope: testCategory,
          reportBody: testReportBody,
        });
      },
      (err: any) => err.message.includes("does not exist in this tree")
    );
  });

  await t.test("B10. Client claiming fake { valid: true } proof rejected by backend", async () => {
    const fakeProof: any = {
      valid: true,
      proof: "simulated-bypass",
    };

    await assert.rejects(
      async () => {
        await reportService.submitReport({
          categoryId: testCategory,
          body: "Attempting bypass with client-side claimed proof " + Date.now(),
          proof: fakeProof,
        });
      },
      (err: any) => err instanceof ReportError && err.code === "invalid_proof"
    );
  });

  await t.test("B11. End-to-end report submission with valid Semaphore proof succeeds and blocks duplicate replay", async () => {
    const eve = new Identity();
    zkProofService.registerCommitment(eve.commitment.toString());

    const reportText = "Critical emergency protocol failure observed during chemistry lab session " + Date.now();
    const proof = await zkProofService.generateProof({
      identity: eve,
      topicScope: testCategory,
      reportBody: reportText,
    });

    // 1. First submission succeeds
    const result = await reportService.submitReport({
      categoryId: testCategory,
      body: reportText,
      proof,
    });

    assert.ok(result.reference.startsWith("INC-"));
    assert.equal(result.status, "received");

    // 2. Second submission with same nullifier within same topic is rejected
    await assert.rejects(
      async () => {
        await reportService.submitReport({
          categoryId: testCategory,
          body: reportText,
          proof,
        });
      },
      (err: any) => err instanceof ReportError && (err.code === "duplicate" || err.code === "invalid_proof")
    );
  });
});
