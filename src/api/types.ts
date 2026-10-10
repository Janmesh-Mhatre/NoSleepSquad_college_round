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

export interface SubmitResult {
  reference: string;
  status: ReportStatus;
  statusSecret: string;
  priority: ReportPriority;
}

export interface StatusResult {
  status: ReportStatus;
  categoryName: string;
  createdAt: string;
  priority: ReportPriority;
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

export interface ModerationAction {
  id: string;
  reportId: string;
  action: "confirm" | "reclassify" | "escalate" | "request_review" | "close";
  previousStatus: ReportStatus;
  newStatus: ReportStatus;
  reason: string;
  moderatorId: string;
  createdAt: string;
}

export interface ReportDetail {
  id: string;
  reference: string;
  categoryId: string;
  categoryName: string;
  encryptedBody: string;
  status: ReportStatus;
  priority: ReportPriority;
  moderationResult: ModerationResult;
  createdAt: string;
  updatedAt: string;
  assignedModerator?: string;
  auditCommitted: boolean;
  auditBatchId?: string;
  actions: ModerationAction[];
}

export interface ModeratorMetrics {
  totalReports: number;
  awaitingReview: number;
  inInvestigation: number;
  resolved: number;
  flaggedByModeration: number;
  auditCommitted: number;
}

export interface ModerationPolicyConfig {
  policyVersion: string;
  ruleEngineStatus: "active" | "degraded" | "inactive";
  nlpClassifier: {
    model: string;
    version: string;
    threshold: number;
    status: "active" | "updating" | "offline";
  };
  optionalLlmReview: {
    provider: string;
    status: "active" | "fallback_local" | "disabled";
    policy: string;
    timeoutMs: number;
  };
  activeRules: Array<{
    id: string;
    name: string;
    category: string;
    action: "flag" | "escalate" | "route_priority";
    description: string;
  }>;
  metrics: {
    falsePositiveRate: string;
    falseNegativeRate: string;
    humanOverridesCount: number;
    totalEvaluated: number;
  };
}

export interface AuditBatch {
  id: string;
  sequence: number;
  merkleRoot: string;
  reportCount: number;
  status: "pending" | "published" | "verified" | "delayed" | "blockchain_unavailable" | "pending_retry" | "confirmed" | "failed";
  contractAddress: string;
  network: string;
  txHash?: string;
  blockNumber?: number;
  createdAt: string;
  publishedAt?: string;
}

export interface AuditVerificationResult {
  batchId: string;
  sequence: number;
  calculatedMerkleRoot: string;
  publishedMerkleRoot: string;
  matches: boolean;
  status: "verified" | "mismatch";
  blockNumber?: number;
  txHash?: string;
  timestamp: string;
}

export interface AuditQueueStatus {
  pendingReportsInQueue: number;
  batchIntervalMinutes: number;
  nextScheduledBatch: string;
  latestPublishedBatch: {
    sequence: number;
    root: string;
    status: string;
    timestamp: string;
  } | null;
  blockchainStatus: string;
}

export interface SecurityTestResult {
  id: string;
  name: string;
  category: "identity_separation" | "cryptographic_privacy" | "transport_security" | "access_control";
  status: "passed" | "warning" | "failed";
  details: string;
  durationMs: number;
  testedAt: string;
}

export interface SecurityPostureSummary {
  overallStatus: "healthy" | "advisory" | "critical";
  lastScanTimestamp: string;
  testsPassed: number;
  testsTotal: number;
  results: SecurityTestResult[];
  securityAdvisories: string[];
}

export interface SystemHealth {
  status: "ok" | "degraded" | "unavailable";
  service: string;
  version: string;
  timestamp: string;
  components: {
    api: { state: string; detail?: string };
    database: { state: string; detail?: string };
    membershipService: { state: string; detail?: string };
    moderationEngine: { state: string; detail?: string };
    auditBatcher: { state: string; detail?: string };
    blockchain: { state: string; detail?: string };
  };
}

export interface CredentialStatusResponse {
  state: "none" | "active" | "expired" | "revoked";
  expiresAt?: string;
  registered: boolean;
  anonymousVerificationReady: boolean;
}

export interface MembershipStatusResponse {
  registered: boolean;
  active: boolean;
  status: "active" | "revoked" | "pending" | "not_registered";
  credentialRegistered: boolean;
  credentialStatus: "registered" | "revoked" | "none";
  anonymousVerificationReady: boolean;
  expiresAt?: string;
}
