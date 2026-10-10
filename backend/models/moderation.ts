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
