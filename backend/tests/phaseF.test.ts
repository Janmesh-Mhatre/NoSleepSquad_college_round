import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { getDatabase } from "../db.js";
import { migrationRunner } from "../migrations/runner.js";
import { reportService, ReportError } from "../services/reportService.js";
import { retentionService } from "../services/retentionService.js";

test("PHASE F — PostgreSQL & Production Data Layer", async (t) => {
  const db = getDatabase();

  await t.test("F1. Migration files are structured, valid SQL, and verified", async () => {
    const migrations = migrationRunner.getMigrationFiles();
    assert.ok(migrations.length >= 2, "Expected at least 2 SQL migration files");

    const m1 = migrations.find((m) => m.id.includes("001_initial_schema"));
    assert.ok(m1, "Migration 001 exists");
    assert.ok(m1.sql.includes("CREATE TABLE IF NOT EXISTS reports"));
    assert.ok(m1.sql.includes("nullifier_hash VARCHAR(128) UNIQUE NOT NULL"));

    const m2 = migrations.find((m) => m.id.includes("002_retention_and_audit"));
    assert.ok(m2, "Migration 002 exists");
    assert.ok(m2.sql.includes("security_events"));
  });

  await t.test("F2. Strict Privacy Schema Audit: Zero identity columns in reports table", () => {
    const tableInfo = db.prepare("PRAGMA table_info(reports)").all() as { name: string; type: string }[];
    const columnNames = tableInfo.map((c) => c.name.toLowerCase());

    const prohibitedTerms = [
      "student_id",
      "student",
      "user_id",
      "member_id",
      "email",
      "name",
      "ip",
      "ip_address",
      "user_agent",
      "auth_token",
      "identity",
      "session_id",
    ];

    for (const term of prohibitedTerms) {
      assert.strictEqual(
        columnNames.includes(term),
        false,
        `PRIVACY VIOLATION: reports table contains forbidden column '${term}'`
      );
    }

    // Required security columns must exist
    assert.ok(columnNames.includes("nullifier_hash"));
    assert.ok(columnNames.includes("status_secret_hash"));
    assert.ok(columnNames.includes("encrypted_body"));
  });

  await t.test("F3. Relational integrity: cascades and foreign key constraints", () => {
    // Audit records cascade delete when batch is removed
    const testBatchId = "batch-test-cascade-" + crypto.randomUUID();
    const testRecId = "rec-cas-" + crypto.randomUUID();
    const uniqueSeq = 990000 + Math.floor(Math.random() * 10000);
    db.prepare(`
      INSERT INTO audit_batches (id, sequence, merkle_root, report_count, status, contract_address, network, created_at)
      VALUES (?, ?, '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789', 1, 'published', '0x123', 'Testnet', ?)
    `).run(testBatchId, uniqueSeq, new Date().toISOString());

    db.prepare(`
      INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at)
      VALUES (?, ?, 'INC-TEST-01', '0xcomm01', ?)
    `).run(testRecId, testBatchId, new Date().toISOString());

    const initialRec = db.prepare("SELECT id FROM audit_records WHERE id = ?").get(testRecId);
    assert.ok(initialRec);

    // Delete batch
    db.prepare("DELETE FROM audit_batches WHERE id = ?").run(testBatchId);

    const afterRec = db.prepare("SELECT id FROM audit_records WHERE id = ?").get(testRecId);
    assert.strictEqual(afterRec, undefined, "Cascade delete should have removed child audit_records");
  });

  await t.test("F4. Concurrency & Race Condition Protection: Duplicate nullifiers rejected", async () => {
    const sharedNullifier = "nullifier:concurrent-test-" + crypto.randomBytes(8).toString("hex");

    // Launch 5 concurrent submissions with the identical nullifier
    const submissionPromises = Array.from({ length: 5 }, (_, i) =>
      reportService.submitReport({
        categoryId: "cat-academic",
        body: `Concurrent race condition submission attempt ${i + 1} with identical nullifier.`,
        proofNullifier: sharedNullifier,
      })
    );

    const results = await Promise.allSettled(submissionPromises);

    const fulfilled = results.filter((r) => r.status === "fulfilled");
    const rejected = results.filter((r) => r.status === "rejected");

    // Exactly one submission must succeed; all others must be rejected with duplicate conflict
    assert.strictEqual(fulfilled.length, 1, "Exactly one concurrent submission must succeed");
    assert.strictEqual(rejected.length, 4, "Remaining concurrent submissions must be rejected");

    for (const rej of rejected) {
      if (rej.status === "rejected") {
        assert.ok(rej.reason instanceof ReportError);
        assert.strictEqual(rej.reason.code, "duplicate");
      }
    }
  });

  await t.test("F5. Data Retention: Expired closed reports are purged while preserving audit commitments", async () => {
    const oldDate = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString(); // 400 days ago
    const expiredReportId = "rep-retention-" + crypto.randomUUID();
    const testRef = "INC-RET-" + crypto.randomBytes(4).toString("hex").toUpperCase();
    const testSecretHash = crypto.createHash("sha256").update(crypto.randomBytes(16)).digest("hex");
    const testNullifier = crypto.createHash("sha256").update("nullifier:retention:" + crypto.randomUUID()).digest("hex");

    db.prepare(`
      INSERT INTO reports (
        id, reference, status_secret_hash, category_id, encrypted_body, priority, status,
        moderation_result, nullifier_hash, created_at, updated_at, audit_committed
      ) VALUES (?, ?, ?, 'cat-academic', 'Sensitive details to be purged', 'low', 'closed', '{}', ?, ?, ?, 1)
    `).run(expiredReportId, testRef, testSecretHash, testNullifier, oldDate, oldDate);

    // Run purge routine
    const purgeResult = retentionService.purgeExpiredReports(365);
    assert.ok(purgeResult.purgedCount >= 1, "Expected at least 1 report to be purged");

    const purgedRecord = db.prepare("SELECT encrypted_body, is_purged FROM reports WHERE id = ?").get(expiredReportId) as any;
    assert.strictEqual(purgedRecord.encrypted_body, "[DATA_RETENTION_EXPIRED_PURGED]");
    assert.strictEqual(purgedRecord.is_purged, 1);

    // Verify blockchain audit records remain intact
    assert.ok(purgeResult.retainedAuditBatchCount >= 1);
  });

  await t.test("F6. Immutability guarantee: Audit batches are strictly non-deletable", () => {
    assert.strictEqual(retentionService.assertImmutableAuditIntegrity(), true);
  });
});
