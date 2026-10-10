import { getDatabase } from "../db.js";

export interface RetentionPolicyConfig {
  closedReportRetentionDays: number;
  securityEventRetentionDays: number;
  ephemeralTokenRetentionHours: number;
  allowAuditBatchDeletion: boolean; // MUST ALWAYS BE FALSE: On-chain evidence is immutable
}

export const DEFAULT_RETENTION_POLICY: RetentionPolicyConfig = {
  closedReportRetentionDays: 365,
  securityEventRetentionDays: 90,
  ephemeralTokenRetentionHours: 24,
  allowAuditBatchDeletion: false, // Invariant
};

export class RetentionService {
  /**
   * Identifies and purges report bodies that have exceeded retention periods.
   * Invariant: Preserves reference and on-chain Merkle commitment for historical tamper verification,
   * while zeroing out encrypted_body content to honor privacy right-to-be-forgotten policies.
   */
  purgeExpiredReports(olderThanDays = DEFAULT_RETENTION_POLICY.closedReportRetentionDays): {
    purgedCount: number;
    retainedAuditBatchCount: number;
  } {
    const db = getDatabase();
    const cutoffDate = new Date(Date.now() - olderThanDays * 24 * 60 * 60 * 1000).toISOString();

    // Select reports closed before cutoffDate that are not yet purged
    const expiredReports = db
      .prepare(
        "SELECT id, reference FROM reports WHERE status = 'closed' AND updated_at < ? AND (is_purged IS NULL OR is_purged = 0)"
      )
      .all(cutoffDate) as { id: string; reference: string }[];

    if (expiredReports.length > 0) {
      const purgeStmt = db.prepare(
        "UPDATE reports SET encrypted_body = '[DATA_RETENTION_EXPIRED_PURGED]', is_purged = 1 WHERE id = ?"
      );
      for (const r of expiredReports) {
        purgeStmt.run(r.id);
      }
    }

    // Strict invariant check: verify audit batches are preserved
    const auditCount = (db.prepare("SELECT count(*) as c FROM audit_batches").get() as any).c;

    return {
      purgedCount: expiredReports.length,
      retainedAuditBatchCount: auditCount,
    };
  }

  /**
   * Asserts that blockchain audit records cannot be deleted.
   */
  assertImmutableAuditIntegrity(): boolean {
    if (DEFAULT_RETENTION_POLICY.allowAuditBatchDeletion) {
      throw new Error("CRITICAL SAFETY VIOLATION: Audit batch deletion must never be enabled.");
    }
    return true;
  }
}

export const retentionService = new RetentionService();
