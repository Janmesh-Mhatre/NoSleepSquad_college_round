import crypto from "node:crypto";
import { getDatabase } from "../db.js";
import { env } from "../config/env.js";
import type {
  ReportCategory,
  ReportRecord,
  ReportStatus,
  ReportPriority,
  ModeratorReportSummary,
  ModerationActionRecord,
} from "../models/report.js";
import { moderationService } from "./moderationService.js";
import { zkProofService, type ZkMembershipProof } from "./zkProofService.js";
import { keyService } from "./keyService.js";

export class ReportError extends Error {
  constructor(public code: string, message: string, public status: number = 400) {
    super(message);
    this.name = "ReportError";
  }
}

// Derive a 32-byte cryptographic key for AES-256-GCM via KMS abstraction
function getMasterKey(): Buffer {
  return keyService.getMasterKey();
}

/**
 * Encrypts report payload with authenticated AES-256-GCM.
 * Output format: gcm:<12-byte IV hex>:<16-byte AuthTag hex>:<Ciphertext hex>
 */
export function encryptPayload(plaintext: string): string {
  const key = getMasterKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `gcm:${iv.toString("hex")}:${tag.toString("hex")}:${encrypted.toString("hex")}`;
}

/**
 * Decrypts authenticated AES-256-GCM ciphertext and validates authentication tag.
 */
export function decryptPayload(ciphertext: string): string {
  if (!ciphertext.startsWith("gcm:")) {
    // Backward compatibility for legacy test seeds
    return ciphertext.replace(/^\[AES-256-GCM Encrypted\]\s*/, "");
  }
  const parts = ciphertext.split(":");
  if (parts.length !== 4) return ciphertext;
  const [, ivHex, tagHex, dataHex] = parts;
  try {
    const key = getMasterKey();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
    decipher.setAuthTag(Buffer.from(tagHex, "hex"));
    const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, "hex")), decipher.final()]);
    return decrypted.toString("utf8");
  } catch {
    return "[Decryption failed: Authentication tag verification mismatch]";
  }
}

export class ReportService {
  getCategories(): ReportCategory[] {
    const db = getDatabase();
    const rows = db.prepare("SELECT id, name, description, risk_tier as riskTier FROM categories ORDER BY name ASC").all() as unknown as ReportCategory[];
    return rows;
  }

  async submitReport(params: {
    categoryId: string;
    body: string;
    idempotencyKey?: string;
    proofNullifier?: string;
    proof?: ZkMembershipProof;
  }): Promise<{ reference: string; status: ReportStatus; statusSecret: string; priority: ReportPriority }> {
    const { categoryId, body, proofNullifier, proof } = params;

    if (!categoryId || typeof categoryId !== "string") {
      throw new ReportError("invalid_category", "A valid report category is required.", 400);
    }

    if (!body || typeof body !== "string" || body.trim().length < 20 || body.length > 5000) {
      throw new ReportError("invalid_body", "Report body must be between 20 and 5000 characters.", 400);
    }

    const db = getDatabase();

    // Verify category exists
    const category = db.prepare("SELECT id, name, risk_tier FROM categories WHERE id = ?").get(categoryId) as { id: string; name: string; risk_tier: string } | undefined;
    if (!category) {
      throw new ReportError("category_not_found", "Specified category was not found.", 404);
    }

    // Determine nullifier hash with cryptographic domain separation and ZK proof verification
    let nullifierHash: string;
    if (proof) {
      const verification = await zkProofService.verifyProof(proof, categoryId, body);
      if (!verification.valid) {
        throw new ReportError("invalid_proof", verification.reason || "Cryptographic proof verification failed.", 400);
      }
      nullifierHash = proof.nullifier;
    } else {
      const contentDigest = crypto.createHash("sha256").update(body.trim().toLowerCase()).digest("hex");
      const nullifierSeed = proofNullifier || `incognito:scope:${categoryId}:${contentDigest}`;
      nullifierHash = crypto.createHash("sha256").update(nullifierSeed).digest("hex");
    }

    // Check duplicate submission for this topic/scope
    const existing = db.prepare("SELECT id, reference FROM reports WHERE nullifier_hash = ?").get(nullifierHash);
    if (existing) {
      throw new ReportError("duplicate", "A submission already exists for this reporting scope.", 409);
    }

    // Generate cryptographically secure random reference and 128-bit status secret
    const reference = "INC-" + crypto.randomBytes(6).toString("hex").toUpperCase();
    const statusSecret = "sec_" + crypto.randomBytes(16).toString("hex");
    const statusSecretHash = crypto.createHash("sha256").update(statusSecret).digest("hex");

    // Real authenticated AES-256-GCM encryption before persistence
    const encryptedBody = encryptPayload(body.trim());

    // Execute automated moderation
    const moderation = moderationService.analyzeContent(body, categoryId);

    // Initial priority
    let priority: ReportPriority = "medium";
    if (moderation.urgencyScore >= 75 || category.risk_tier === "urgent") {
      priority = "high";
    } else if (moderation.urgencyScore <= 30) {
      priority = "low";
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const insertStmt = db.prepare(`
      INSERT INTO reports (
        id, reference, status_secret_hash, category_id, encrypted_body, priority, status,
        moderation_result, nullifier_hash, created_at, updated_at, audit_committed
      ) VALUES (?, ?, ?, ?, ?, ?, 'received', ?, ?, ?, ?, 0)
    `);

    insertStmt.run(
      id,
      reference,
      statusSecretHash,
      categoryId,
      encryptedBody,
      priority,
      JSON.stringify(moderation),
      nullifierHash,
      now,
      now
    );

    return {
      reference,
      status: "received",
      statusSecret,
      priority,
    };
  }

  getReportStatus(reference: string, statusSecret: string): { status: ReportStatus; categoryName: string; createdAt: string; priority: ReportPriority } {
    if (!reference || !statusSecret) {
      throw new ReportError("invalid_request", "Both reference and status secret are required.", 400);
    }

    const db = getDatabase();
    const row = db.prepare(`
      SELECT r.status, r.status_secret_hash, r.created_at, r.priority, c.name as categoryName
      FROM reports r
      JOIN categories c ON r.category_id = c.id
      WHERE r.reference = ?
    `).get(reference) as { status: ReportStatus; status_secret_hash: string; created_at: string; priority: ReportPriority; categoryName: string } | undefined;

    if (!row) {
      throw new ReportError("not_found", "No report found with the provided reference.", 404);
    }

    const computedHash = crypto.createHash("sha256").update(statusSecret).digest("hex");
    const computedBuf = Buffer.from(computedHash);
    const expectedBuf = Buffer.from(row.status_secret_hash);

    if (computedBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(computedBuf, expectedBuf)) {
      throw new ReportError("invalid_credentials", "Invalid status access secret.", 403);
    }

    return {
      status: row.status,
      categoryName: row.categoryName,
      createdAt: row.created_at,
      priority: row.priority,
    };
  }

  getModeratorReports(params: {
    status?: string;
    categoryId?: string;
    priority?: string;
    search?: string;
  }): ModeratorReportSummary[] {
    const db = getDatabase();
    let query = `
      SELECT 
        r.id,
        r.reference,
        r.category_id as categoryId,
        c.name as categoryName,
        r.status,
        r.priority,
        r.moderation_result as moderationResult,
        r.created_at as createdAt,
        r.assigned_moderator as assignedModerator,
        (SELECT count(*) FROM moderation_actions WHERE report_id = r.id) as actionCount
      FROM reports r
      JOIN categories c ON r.category_id = c.id
      WHERE 1=1
    `;

    const args: any[] = [];

    if (params.status && params.status !== "all") {
      query += " AND r.status = ?";
      args.push(params.status);
    }

    if (params.categoryId && params.categoryId !== "all") {
      query += " AND r.category_id = ?";
      args.push(params.categoryId);
    }

    if (params.priority && params.priority !== "all") {
      query += " AND r.priority = ?";
      args.push(params.priority);
    }

    if (params.search) {
      query += " AND (r.reference LIKE ? OR c.name LIKE ?)";
      args.push(`%${params.search}%`, `%${params.search}%`);
    }

    query += " ORDER BY r.created_at DESC";

    const rows = db.prepare(query).all(...args) as any[];

    return rows.map(r => ({
      id: r.id,
      reference: r.reference,
      categoryId: r.categoryId,
      categoryName: r.categoryName,
      status: r.status,
      priority: r.priority,
      moderationResult: JSON.parse(r.moderationResult),
      createdAt: r.createdAt,
      assignedModerator: r.assignedModerator || undefined,
      actionCount: r.actionCount || 0,
    }));
  }

  getReportById(id: string) {
    const db = getDatabase();
    const row = db.prepare(`
      SELECT 
        r.id,
        r.reference,
        r.category_id as categoryId,
        c.name as categoryName,
        r.encrypted_body as encryptedBody,
        r.status,
        r.priority,
        r.moderation_result as moderationResult,
        r.created_at as createdAt,
        r.updated_at as updatedAt,
        r.assigned_moderator as assignedModerator,
        r.audit_committed as auditCommitted,
        r.audit_batch_id as auditBatchId
      FROM reports r
      JOIN categories c ON r.category_id = c.id
      WHERE r.id = ? OR r.reference = ?
    `).get(id, id) as any;

    if (!row) return null;

    const actions = db.prepare(`
      SELECT id, action, previous_status as previousStatus, new_status as newStatus, reason, moderator_id as moderatorId, created_at as createdAt
      FROM moderation_actions
      WHERE report_id = ?
      ORDER BY created_at ASC
    `).all(row.id) as unknown as ModerationActionRecord[];

    const decrypted = decryptPayload(row.encryptedBody);

    return {
      ...row,
      body: decrypted,
      encryptedBody: decrypted,
      moderationResult: JSON.parse(row.moderationResult),
      actions,
    };
  }

  applyModeratorAction(params: {
    reportId: string;
    action: "confirm" | "reclassify" | "escalate" | "request_review" | "close";
    reason: string;
    moderatorId?: string;
    newStatus?: ReportStatus;
  }) {
    const { reportId, action, reason, moderatorId = "moderator-primary" } = params;

    if (!reason || reason.trim().length < 5) {
      throw new ReportError("invalid_reason", "Action reason must be at least 5 characters.", 400);
    }

    const db = getDatabase();
    const report = db.prepare("SELECT id, status FROM reports WHERE id = ?").get(reportId) as { id: string; status: ReportStatus } | undefined;

    if (!report) {
      throw new ReportError("not_found", "Report not found.", 404);
    }

    let nextStatus: ReportStatus = report.status;
    if (action === "confirm") nextStatus = "under_review";
    else if (action === "escalate") nextStatus = "moderation_review";
    else if (action === "request_review") nextStatus = "assigned";
    else if (action === "close") nextStatus = "closed";
    else if (params.newStatus) nextStatus = params.newStatus;

    const now = new Date().toISOString();
    const actionId = crypto.randomUUID();

    db.prepare(`
      INSERT INTO moderation_actions (id, report_id, action, previous_status, new_status, reason, moderator_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(actionId, report.id, action, report.status, nextStatus, reason.trim(), moderatorId, now);

    db.prepare(`
      UPDATE reports
      SET status = ?, updated_at = ?, assigned_moderator = ?
      WHERE id = ?
    `).run(nextStatus, now, moderatorId, report.id);

    return {
      success: true,
      previousStatus: report.status,
      newStatus: nextStatus,
      actionId,
      updatedAt: now,
    };
  }

  getMetrics() {
    const db = getDatabase();
    const total = (db.prepare("SELECT count(*) as c FROM reports").get() as any).c;
    const received = (db.prepare("SELECT count(*) as c FROM reports WHERE status = 'received'").get() as any).c;
    const underReview = (db.prepare("SELECT count(*) as c FROM reports WHERE status = 'under_review' OR status = 'moderation_review'").get() as any).c;
    const actionTaken = (db.prepare("SELECT count(*) as c FROM reports WHERE status = 'action_taken' OR status = 'closed'").get() as any).c;
    const flagged = (db.prepare("SELECT count(*) as c FROM reports WHERE moderation_result LIKE '%\"classification\":\"flagged\"%' OR moderation_result LIKE '%\"classification\":\"escalated\"%'").get() as any).c;
    const auditCommitted = (db.prepare("SELECT count(*) as c FROM reports WHERE audit_committed = 1").get() as any).c;

    return {
      totalReports: total,
      awaitingReview: received,
      inInvestigation: underReview,
      resolved: actionTaken,
      flaggedByModeration: flagged,
      auditCommitted,
    };
  }
}

export const reportService = new ReportService();
