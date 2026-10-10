export type ReportStatus =
  | "received"
  | "under_review"
  | "moderation_review"
  | "assigned"
  | "action_taken"
  | "closed";

export type ReportPriority = "low" | "medium" | "high" | "critical";

export interface ReportCategory {
  id: string;
  name: string;
  description: string;
  riskTier: "standard" | "elevated" | "urgent";
}

export interface ModerationResult {
  classification: "cleared" | "flagged" | "escalated";
  confidence: number;
  policyVersion: string;
  detectedSignals: string[];
  urgencyScore: number;
  reviewStatus: "automated" | "human_reviewed" | "overridden";
}

export interface ReportRecord {
  id: string;
  reference: string;
  statusSecretHash: string;
  categoryId: string;
  encryptedBody: string;
  priority: ReportPriority;
  status: ReportStatus;
  moderationResult: string; // JSON string of ModerationResult
  nullifierHash: string;
  createdAt: string;
  updatedAt: string;
  assignedModerator?: string;
  auditCommitted: boolean;
  auditBatchId?: string;
}

export interface ModerationActionRecord {
  id: string;
  reportId: string;
  action: "confirm" | "reclassify" | "escalate" | "request_review" | "close";
  previousStatus: ReportStatus;
  newStatus: ReportStatus;
  reason: string;
  moderatorId: string;
  createdAt: string;
}

export interface ModeratorReportSummary {
  id: string;
  reference: string;
  categoryId: string;
  categoryName: string;
  status: ReportStatus;
  priority: ReportPriority;
  moderationResult: ModerationResult;
  createdAt: string;
  assignedModerator?: string;
  actionCount: number;
}
