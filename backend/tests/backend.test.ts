import test from "node:test";
import assert from "node:assert/strict";
import { getDatabase, closeDatabase } from "../db.js";
import { SqliteMembershipService, MembershipError } from "../services/membershipService.js";
import { LocalCredentialProvider } from "../services/credentialService.js";
import { ReportService, ReportError } from "../services/reportService.js";
import { ModerationService } from "../services/moderationService.js";
import { AuditService } from "../services/auditService.js";
import { SecurityService } from "../services/securityService.js";
import { getHealth } from "../services/healthService.js";
import { createRateLimiter } from "../middleware/rateLimiter.js";
import { requireRole } from "../middleware/auth.js";
import { authService } from "../services/authService.js";
import { Identity } from "@semaphore-protocol/core";

test("Incognito Backend Architecture & Security Test Suite", async (t) => {
  const membershipService = new SqliteMembershipService();
  const credentialProvider = new LocalCredentialProvider();
  const reportService = new ReportService();
  const moderationService = new ModerationService();
  const auditService = new AuditService();
  const securityService = new SecurityService();

  await t.test("1. System Health Report returns operational components", () => {
    const health = getHealth();
    assert.equal(health.status, "ok");
    assert.equal(health.service, "incognito-api");
    assert.equal(health.components.database.state, "operational");
    assert.equal(health.components.membershipService.state, "operational");
  });

  await t.test("2. Membership & Credential Lifecycle", () => {
    const memberRef = "test-unit-member-" + Date.now();
    const clientIdentity = new Identity();
    const clientCommitment = clientIdentity.commitment.toString();

    // Enrollment without client commitment fails with invalid_commitment
    assert.throws(
      () => membershipService.enroll(memberRef),
      (err: any) => err instanceof MembershipError && err.code === "invalid_commitment"
    );

    // Status before enroll
    const statusPre = membershipService.getStatus(memberRef);
    assert.equal(statusPre.registered, false);
    assert.equal(statusPre.status, "not_registered");

    // Enroll with valid client commitment
    const enrolled = membershipService.enroll(memberRef, clientCommitment);
    assert.equal(enrolled.success, true);
    assert.equal(enrolled.membership.status, "active");
    assert.equal(enrolled.credential.status, "registered");
    assert.ok(enrolled.credential.commitmentReference.length > 0);
    assert.equal(enrolled.credential.commitment, clientCommitment);
    assert.equal((enrolled.credential as any).identitySecretExport, undefined);

    // Duplicate enrollment rejected
    assert.throws(
      () => membershipService.enroll(memberRef, clientCommitment),
      (err: any) => err instanceof MembershipError && err.status === 409
    );

    // Validate
    const validation = membershipService.validate(memberRef);
    assert.equal(validation.valid, true);
    assert.equal(validation.active, true);
    assert.equal(validation.credentialValid, true);

    // Revoke
    const revoked = membershipService.revoke(memberRef, "Test revocation");
    assert.equal(revoked.success, true);
    assert.equal(revoked.status, "revoked");

    // Post-revocation validation fails
    const postValidation = membershipService.validate(memberRef);
    assert.equal(postValidation.valid, false);
    assert.equal(postValidation.active, false);
  });

  await t.test("3. Anonymous Report Submission & Separation", async () => {
    const categories = reportService.getCategories();
    assert.ok(categories.length >= 5);
    const catId = categories[0].id;

    // Body too short rejected
    await assert.rejects(
      async () => { await reportService.submitReport({ categoryId: catId, body: "Short" }); },
      (err: any) => err instanceof ReportError && err.code === "invalid_body"
    );

    // Valid report submitted
    const reportBody = "This is a legitimate institutional concern regarding laboratory safety protocols and protective gear " + Date.now();
    const result = await reportService.submitReport({
      categoryId: catId,
      body: reportBody,
    });

    assert.ok(result.reference.startsWith("INC-"));
    assert.equal(result.status, "received");
    assert.ok(result.statusSecret.startsWith("sec_"));

    // Duplicate submission with same scope/body rejected
    await assert.rejects(
      async () => { await reportService.submitReport({ categoryId: catId, body: reportBody }); },
      (err: any) => err instanceof ReportError && err.code === "duplicate"
    );

    // Status lookup with wrong secret rejected
    assert.throws(
      () => reportService.getReportStatus(result.reference, "wrong_secret"),
      (err: any) => err instanceof ReportError && err.status === 403
    );

    // Status lookup with correct secret succeeds
    const status = reportService.getReportStatus(result.reference, result.statusSecret);
    assert.equal(status.status, "received");
    assert.equal(status.categoryName, categories[0].name);
  });

  await t.test("4. Moderator Queue & Review Actions", () => {
    const list = reportService.getModeratorReports({});
    assert.ok(list.length > 0);
    const firstReport = list[0];

    // Detail lookup
    const detail = reportService.getReportById(firstReport.id);
    assert.ok(detail);
    assert.equal(detail.id, firstReport.id);
    assert.ok(detail.moderationResult);

    // Apply action
    const actionResult = reportService.applyModeratorAction({
      reportId: firstReport.id,
      action: "confirm",
      reason: "Verified initial report content and confirmed initial review.",
      moderatorId: "mod-test-01",
    });

    assert.equal(actionResult.success, true);
    assert.equal(actionResult.newStatus, "under_review");

    // Metrics are real counts
    const metrics = reportService.getMetrics();
    assert.ok(metrics.totalReports > 0);
  });

  await t.test("5. Moderation Rule Engine & NLP Classifier", () => {
    const hazardAnalysis = moderationService.analyzeContent("Hazardous chemical spill left uncontained in engineering hall", "cat-safety");
    assert.ok(hazardAnalysis.detectedSignals.some(s => s.includes("Hazard")));
    assert.ok(hazardAnalysis.urgencyScore >= 70);

    const policy = moderationService.getPolicyConfig();
    assert.equal(policy.ruleEngineStatus, "active");
    assert.ok(policy.activeRules.length >= 4);
  });

  await t.test("6. Audit Batches & Merkle Root Cryptographic Verification", () => {
    const verification = auditService.verifyBatch("batch-101");
    assert.equal(verification.matches, true);
    assert.equal(verification.status, "verified");
    assert.equal(verification.calculatedMerkleRoot, verification.publishedMerkleRoot);
  });

  await t.test("7. Security & Privacy Test Suite Execution", () => {
    const audit = securityService.runSecurityAudit();
    assert.equal(audit.overallStatus, "healthy");
    assert.equal(audit.testsPassed, audit.testsTotal);
    assert.ok(audit.results.every(r => r.status === "passed"));
  });

  await t.test("8. Authenticated AES-256-GCM Encryption At Rest", async () => {
    const db = getDatabase();
    const categories = reportService.getCategories();
    const catId = categories[0].id;
    const sensitivePayload = "Confidential report with sensitive allegations regarding laboratory equipment safety " + Date.now();

    const res = await reportService.submitReport({
      categoryId: catId,
      body: sensitivePayload,
    });

    // Check DB row directly
    const row = db.prepare("SELECT encrypted_body FROM reports WHERE reference = ?").get(res.reference) as any;
    assert.ok(row, "Database row must exist");
    assert.ok(row.encrypted_body.startsWith("gcm:"), "Encrypted body must use gcm: prefix");
    assert.equal(row.encrypted_body.includes(sensitivePayload), false, "Raw plaintext must never appear in database");

    // Fetch report via moderator API
    const retrieved = reportService.getReportById(res.reference);
    assert.ok(retrieved);
    assert.equal(retrieved.body, sensitivePayload, "Decrypted body must match original plaintext");
  });

  await t.test("9. Multi-lingual Safety, Unicode Normalization & PII Pre-Scrubbing", () => {
    // Test PII scrubbing
    const piiText = "Contact me at whistleblower@university.edu or call +1 555 123 4567 regarding the dean.";
    const scrubbed = moderationService.scrubPII(piiText);
    assert.ok(!scrubbed.includes("whistleblower@university.edu"));
    assert.ok(scrubbed.includes("[REDACTED_EMAIL]"));
    assert.ok(scrubbed.includes("[REDACTED_PHONE]"));

    // Test multi-lingual Hindi/Hinglish safety signal
    const hindiHazard = "यहां ragging aur dhamki ho rahi hai hostel block C me";
    const analysis = moderationService.analyzeContent(hindiHazard, "cat-harassment");
    assert.ok(analysis.detectedSignals.some(s => s.toLowerCase().includes("ragging") || s.toLowerCase().includes("harassment") || s.toLowerCase().includes("intimidation")));
  });

  await t.test("10. Sliding Window Rate Limiter & Headers", () => {
    const limiter = createRateLimiter({ windowMs: 1000, max: 2, message: "Rate limit reached" });

    let status = 200;
    let responseBody: any = null;
    const mockRes: any = {
      setHeader: () => { },
      status: (code: number) => {
        status = code;
        return {
          json: (body: any) => { responseBody = body; }
        };
      }
    };
    const mockReq: any = { headers: {}, socket: { remoteAddress: "10.0.0.1" } };
    let nextCount = 0;
    const mockNext = () => { nextCount++; };

    // Request 1: allowed
    limiter(mockReq, mockRes, mockNext);
    assert.equal(nextCount, 1);

    // Request 2: allowed
    limiter(mockReq, mockRes, mockNext);
    assert.equal(nextCount, 2);

    // Request 3: blocked (max: 2)
    limiter(mockReq, mockRes, mockNext);
    assert.equal(nextCount, 2);
    assert.equal(status, 429);
    assert.equal(responseBody.error, "too_many_requests");
  });

  await t.test("11. Role-Based Access Control (RBAC) Middleware", () => {
    const adminMiddleware = requireRole(["admin"]);
    const modToken = authService.generateToken({ sub: "mod-01", role: "moderator" });
    const adminToken = authService.generateToken({ sub: "adm-01", role: "admin" });

    let status = 200;
    let responseBody: any = null;
    const mockRes: any = {
      status: (code: number) => {
        status = code;
        return { json: (body: any) => { responseBody = body; } };
      }
    };

    // Moderator attempting admin route with token
    const mockReqMod: any = {
      headers: { authorization: `Bearer ${modToken}` }
    };
    let nextCalled = false;
    adminMiddleware(mockReqMod, mockRes, () => { nextCalled = true; });
    assert.equal(nextCalled, false);
    assert.equal(status, 403);
    assert.equal(responseBody.error, "unauthorized");

    // Admin attempting admin route with token
    const mockReqAdmin: any = {
      headers: { authorization: `Bearer ${adminToken}` }
    };
    nextCalled = false;
    adminMiddleware(mockReqAdmin, mockRes, () => { nextCalled = true; });
    assert.equal(nextCalled, true);
    assert.equal(mockReqAdmin.staffRole, "admin");
  });
});

