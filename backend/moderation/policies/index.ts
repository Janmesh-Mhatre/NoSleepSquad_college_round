export interface ModerationPolicy {
  policyVersion: string;
  escalationThreshold: number;
  flagThreshold: number;
  maxReportLength: number;
  minReportLength: number;
  allowedOverrideActions: string[];
  categoryRiskTiers: Record<string, "standard" | "elevated" | "urgent">;
}

export const CURRENT_MODERATION_POLICY: ModerationPolicy = {
  policyVersion: "2026.5-institutional-independent",
  escalationThreshold: 75,
  flagThreshold: 45,
  maxReportLength: 5000,
  minReportLength: 20,
  allowedOverrideActions: [
    "APPROVE",
    "FLAG",
    "ESCALATE",
    "REJECT_MODERATION_RESULT",
    "REQUIRE_HUMAN_REVIEW",
  ],
  categoryRiskTiers: {
    "cat-harassment": "urgent",
    "cat-safety": "urgent",
    "cat-misconduct": "elevated",
    "cat-academic": "standard",
    "cat-institutional": "standard",
    "cat-other": "standard",
  },
};
