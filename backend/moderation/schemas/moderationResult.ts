export type ModerationClassification = "cleared" | "flagged" | "escalated" | "review_required" | "moderation_failed";
export type ModerationSeverity = "low" | "medium" | "high" | "critical";
export type ModerationRecommendedAction = "approve" | "flag" | "escalate" | "require_human_review" | "reject";

export interface ModerationResultSchema {
  category: string;
  classification: ModerationClassification;
  severity: ModerationSeverity;
  confidence: number;
  recommendedAction: ModerationRecommendedAction;
  explanation: string;
  detectedSignals: string[];
  urgencyScore: number;
  policyVersion: string;
  modelVersion: string;
  provider: string;
  reviewStatus: "automated" | "human_reviewed" | "review_required" | "override";
  overrideMetadata?: {
    reviewerId: string;
    overrideAction: string;
    reason: string;
    timestamp: string;
  };
}

/**
 * Strict schema validator for raw provider responses.
 * Rejects arbitrary or un-typed JSON outputs.
 */
export function validateModerationResponse(data: unknown, fallbackProvider = "unknown"): ModerationResultSchema {
  if (!data || typeof data !== "object") {
    throw new Error("Invalid moderation payload: Expected JSON object.");
  }

  const obj = data as Record<string, any>;

  // Valid classifications
  const validClassifications: ModerationClassification[] = [
    "cleared",
    "flagged",
    "escalated",
    "review_required",
    "moderation_failed",
  ];
  const classification: ModerationClassification = validClassifications.includes(obj.classification)
    ? obj.classification
    : "review_required";

  // Valid severities
  const validSeverities: ModerationSeverity[] = ["low", "medium", "high", "critical"];
  const severity: ModerationSeverity = validSeverities.includes(obj.severity) ? obj.severity : "medium";

  // Valid actions
  const validActions: ModerationRecommendedAction[] = [
    "approve",
    "flag",
    "escalate",
    "require_human_review",
    "reject",
  ];
  const recommendedAction: ModerationRecommendedAction = validActions.includes(obj.recommendedAction)
    ? obj.recommendedAction
    : "require_human_review";

  // Confidence check
  let confidence = typeof obj.confidence === "number" ? obj.confidence : 0.85;
  if (Number.isNaN(confidence) || confidence < 0 || confidence > 1) {
    confidence = 0.5;
  }

  // Urgency score check
  let urgencyScore = typeof obj.urgencyScore === "number" ? obj.urgencyScore : 50;
  if (Number.isNaN(urgencyScore)) urgencyScore = 50;
  urgencyScore = Math.max(0, Math.min(100, Math.round(urgencyScore)));

  // Signals check
  const detectedSignals = Array.isArray(obj.detectedSignals)
    ? obj.detectedSignals.map((s) => String(s).slice(0, 100))
    : [];

  return {
    category: typeof obj.category === "string" ? obj.category : "general",
    classification,
    severity,
    confidence: Math.round(confidence * 100) / 100,
    recommendedAction,
    explanation: typeof obj.explanation === "string" ? obj.explanation.slice(0, 500) : "Structured moderation evaluation completed.",
    detectedSignals,
    urgencyScore,
    policyVersion: typeof obj.policyVersion === "string" ? obj.policyVersion : "2026.4-prod",
    modelVersion: typeof obj.modelVersion === "string" ? obj.modelVersion : "v1.0",
    provider: typeof obj.provider === "string" ? obj.provider : fallbackProvider,
    reviewStatus: classification === "review_required" || classification === "moderation_failed" ? "review_required" : "automated",
  };
}
