import { request } from "./client";
import type {
  ReportCategory,
  SubmitResult,
  StatusResult,
  ModeratorReportSummary,
  ReportDetail,
  ModeratorMetrics,
  ModerationPolicyConfig,
  AuditBatch,
  AuditVerificationResult,
  AuditQueueStatus,
  SecurityPostureSummary,
  SystemHealth,
  CredentialStatusResponse,
  MembershipStatusResponse,
  ReportStatus,
} from "./types";

export const reportService = {
  getCategories: () =>
    request<ReportCategory[]>("/api/reports/categories"),

  submit: (p: { categoryId: string; body: string; proofNullifier?: string }, idempotencyKey?: string) =>
    request<SubmitResult>("/api/reports", { method: "POST", body: p, idempotencyKey }),

  status: (reference: string, statusSecret: string) =>
    request<StatusResult>("/api/reports/status", { method: "POST", body: { reference, statusSecret } }),

  getModeratorReports: (params: { status?: string; categoryId?: string; priority?: string; search?: string } = {}) => {
    const query = new URLSearchParams();
    if (params.status) query.set("status", params.status);
    if (params.categoryId) query.set("categoryId", params.categoryId);
    if (params.priority) query.set("priority", params.priority);
    if (params.search) query.set("search", params.search);
    const qs = query.toString();
    return request<ModeratorReportSummary[]>(`/api/moderator/reports${qs ? `?${qs}` : ""}`);
  },

  getReportById: (id: string) =>
    request<ReportDetail>(`/api/moderator/reports/${id}`),

  applyAction: (
    id: string,
    params: { action: "confirm" | "reclassify" | "escalate" | "request_review" | "close"; reason: string; moderatorId?: string; newStatus?: ReportStatus }
  ) =>
    request<{ success: boolean; previousStatus: ReportStatus; newStatus: ReportStatus; actionId: string; updatedAt: string }>(
      `/api/moderator/reports/${id}/action`,
      { method: "POST", body: params }
    ),

  getMetrics: () =>
    request<ModeratorMetrics>("/api/moderator/metrics"),
};

export const credentialService = {
  status: (memberRef = "demo-member-01") =>
    request<CredentialStatusResponse>(`/api/credential/status?ref=${encodeURIComponent(memberRef)}`),

  getMembershipStatus: (memberRef = "demo-member-01") =>
    request<MembershipStatusResponse>(`/api/membership/status?ref=${encodeURIComponent(memberRef)}`),

  enroll: (memberRef = "demo-member-01") =>
    request<{ success: boolean; membership: { status: string }; credential: { status: string; commitmentReference: string; expiresAt: string } }>(
      "/api/membership/enroll",
      { method: "POST", body: { memberRef } }
    ),

  validate: (memberRef = "demo-member-01") =>
    request<{ valid: boolean; status: string; active: boolean; credentialValid: boolean }>(
      "/api/membership/validate",
      { method: "POST", body: { memberRef } }
    ),
};

export const moderationService = {
  getPolicies: () =>
    request<ModerationPolicyConfig>("/api/moderation/policies"),
};

export const auditService = {
  getBatches: () =>
    request<AuditBatch[]>("/api/audit/batches"),

  verifyBatch: (batchId: string) =>
    request<AuditVerificationResult>(`/api/audit/verify/${batchId}`, { method: "POST" }),

  getQueueStatus: () =>
    request<AuditQueueStatus>("/api/audit/status"),
};

export const securityService = {
  getTests: () =>
    request<SecurityPostureSummary>("/api/security/tests"),

  runTests: () =>
    request<SecurityPostureSummary>("/api/security/tests/run", { method: "POST" }),
};

export const systemService = {
  getHealth: () =>
    request<SystemHealth>("/api/health"),
};
