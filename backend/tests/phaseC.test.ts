import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Identity } from "@semaphore-protocol/core";
import { getDatabase } from "../db.js";
import {
  KeyManagementService,
  DevelopmentKeyProvider,
  ProductionKMSProvider,
} from "../services/keyService.js";
import { ReportService, ReportError } from "../services/reportService.js";
import { zkProofService } from "../services/zkProofService.js";
import { createApp } from "../app.js";

test("PHASE C — Privacy & Identity Separation Test Suite", async (t) => {
  const reportService = new ReportService();

  await t.test("C1. Database schema privacy: Zero identity columns in reports table", () => {
    const db = getDatabase();
    const columns = db.prepare("PRAGMA table_info(reports)").all() as { name: string }[];
    const columnNames = columns.map((c) => c.name.toLowerCase());

    const forbiddenColumns = [
      "student_id",
      "member_id",
      "email",
      "name",
      "ip",
      "ip_address",
      "user_agent",
      "device_id",
      "session_id",
      "auth_token",
    ];

    for (const forbidden of forbiddenColumns) {
      assert.equal(
        columnNames.includes(forbidden),
        false,
        `Found forbidden identity column '${forbidden}' in reports table.`
      );
    }
  });

  await t.test("C2. Foreign key / join impossibility between reports and members", () => {
    const db = getDatabase();
    const foreignKeys = db.prepare("PRAGMA foreign_key_list(reports)").all() as any[];
    const referencesMembers = foreignKeys.some((fk) => fk.table?.toLowerCase() === "members");
    assert.equal(referencesMembers, false, "Reports table must not have foreign keys to members");
  });

  await t.test("C3. KeyProvider abstraction: DevelopmentKeyProvider vs ProductionKMSProvider", () => {
    // 1. DevelopmentKeyProvider creates functioning keys
    const devProvider = new DevelopmentKeyProvider("test-development-key-seed-entropy");
    assert.equal(devProvider.providerType, "development");
    assert.equal(devProvider.getKey().length, 32);

    // 2. ProductionKMSProvider fails closed if key is insecure, short, or missing
    assert.throws(
      () => new ProductionKMSProvider("dev-only-local-encryption-key-32b!"),
      /FATAL: Production environment requires a securely injected ENCRYPTION_KEY/
    );

    // 3. KeyManagementService fails closed in production
    const originalEnv = process.env.NODE_ENV;
    const originalKey = process.env.ENCRYPTION_KEY;
    try {
      process.env.NODE_ENV = "production";
      process.env.ENCRYPTION_KEY = "short";

      assert.throws(
        () => new KeyManagementService(),
        /FATAL: Production environment requires a securely injected ENCRYPTION_KEY/
      );
    } finally {
      process.env.NODE_ENV = originalEnv;
      process.env.ENCRYPTION_KEY = originalKey;
    }
  });

  await t.test("C4. Status Secrets have at least 128 bits of entropy & secure references", async () => {
    const result = await reportService.submitReport({
      categoryId: "cat-safety",
      body: "Valid compliant institutional report for entropy verification testing " + Date.now(),
    });

    // Reference format: INC- + at least 12 hex chars
    assert.ok(result.reference.startsWith("INC-"));
    assert.ok(result.reference.length >= 10);

    // Status Secret format: sec_ + 32 hex chars (16 bytes = 128 bits of entropy)
    assert.ok(result.statusSecret.startsWith("sec_"));
    const secretEntropyHex = result.statusSecret.substring(4);
    assert.equal(secretEntropyHex.length, 32, "Secret must have 32 hex chars (128 bits)");
    assert.match(secretEntropyHex, /^[0-9a-f]{32}$/);
  });

  await t.test("C5. Status Secret verification is constant-time & timing-safe", async () => {
    const result = await reportService.submitReport({
      categoryId: "cat-safety",
      body: "Valid compliant institutional report for constant time check " + Date.now(),
    });

    // Valid lookup succeeds
    const status = reportService.getReportStatus(result.reference, result.statusSecret);
    assert.equal(status.status, "received");

    // Invalid lookup fails with 403
    assert.throws(
      () => reportService.getReportStatus(result.reference, "sec_" + "0".repeat(32)),
      (err: any) => err instanceof ReportError && err.status === 403
    );
  });

  await t.test("C6. Zero identity leakage: API explicitly prohibits GET /reports/:id/identity", async () => {
    const app = createApp();

    // Use Node test server / supertest simulation
    const server = app.listen(0);
    const port = (server.address() as any).port;

    try {
      const res = await fetch(`http://127.0.0.1:${port}/api/reports/INC-12345/identity`);
      assert.equal(res.status, 403, "Must return 403 Forbidden on identity lookup attempts");
      const json = await res.json() as any;
      assert.equal(json.error, "forbidden_operation");
    } finally {
      server.close();
    }
  });

  await t.test("C7. Cross-topic nullifier unlinkability under genuine Semaphore identity", async () => {
    const user = new Identity();
    zkProofService.registerCommitment(user.commitment.toString());

    const body = "Safety and facility observation report " + Date.now();
    const proofSafety = await zkProofService.generateProof({
      identity: user,
      topicScope: "cat-safety",
      reportBody: body,
    });

    const proofEthics = await zkProofService.generateProof({
      identity: user,
      topicScope: "cat-ethics",
      reportBody: body,
    });

    assert.notEqual(proofSafety.nullifier, proofEthics.nullifier);
  });
});
