import { BaseModerationProvider } from "./providers/base.js";
import { deterministicProvider, DeterministicModerationProvider } from "./providers/deterministic.js";
import { GeminiModerationProvider } from "./providers/gemini.js";
import { OpenAIModerationProvider } from "./providers/openai.js";
import { mockModerationProvider, MockModerationProvider } from "./providers/mock.js";
import { textNormalizer } from "./normalizer.js";
import type { ModerationResultSchema } from "./schemas/moderationResult.js";
import { CURRENT_MODERATION_POLICY } from "./policies/index.js";

export type ModerationProviderType = "deterministic" | "gemini" | "openai" | "mock";

export class ModerationPipeline {
  private activeProviderType: ModerationProviderType = "deterministic";
  private contextualProvider: BaseModerationProvider | null = null;
  private deterministic: DeterministicModerationProvider = deterministicProvider;

  constructor() {
    this.configureFromEnvironment();
  }

  configureFromEnvironment() {
    const defaultProvider = process.env.GROQ_API_KEY ? "openai" : "deterministic";
    const providerName = (process.env.LLM_PROVIDER || defaultProvider).toLowerCase() as ModerationProviderType;
    this.activeProviderType = providerName;

    switch (providerName) {
      case "gemini":
        this.contextualProvider = new GeminiModerationProvider();
        break;
      case "openai":
        this.contextualProvider = new OpenAIModerationProvider();
        break;
      case "mock":
        this.contextualProvider = mockModerationProvider;
        break;
      default:
        this.contextualProvider = null;
        this.activeProviderType = "deterministic";
    }
  }

  setProvider(providerType: ModerationProviderType, customProvider?: BaseModerationProvider) {
    this.activeProviderType = providerType;
    if (customProvider) {
      this.contextualProvider = customProvider;
    } else if (providerType === "mock") {
      this.contextualProvider = mockModerationProvider;
    } else if (providerType === "gemini") {
      this.contextualProvider = new GeminiModerationProvider();
    } else if (providerType === "openai") {
      this.contextualProvider = new OpenAIModerationProvider();
    } else {
      this.contextualProvider = null;
    }
  }

  getActiveProviderName(): string {
    return this.contextualProvider ? this.contextualProvider.name : this.deterministic.name;
  }

  /**
   * Executes complete end-to-end moderation pipeline:
   * 1. Normalization & homoglyph de-obfuscation
   * 2. PII pre-scrubbing
   * 3. Deterministic safety analysis
   * 4. Contextual LLM evaluation (if configured)
   * 5. Safe fault-tolerant synthesis (Never fails open on provider outage!)
   */
  async evaluate(rawText: string, categoryId: string): Promise<ModerationResultSchema> {
    const scrubbed = textNormalizer.scrubPII(rawText);
    const normalized = textNormalizer.normalize(scrubbed);

    // 1. Primary deterministic safety checks
    const deterministicResult = await this.deterministic.moderate(normalized, categoryId);

    // 2. If no contextual provider configured, return deterministic result
    if (!this.contextualProvider || this.activeProviderType === "deterministic") {
      return deterministicResult;
    }

    // 3. Attempt contextual LLM moderation with safe fault tolerance
    try {
      const contextualResult = await this.contextualProvider.moderate(normalized, categoryId);

      // Synthesize: Take the higher urgency / stricter safety assessment to prevent prompt injection evasion
      const higherUrgency = Math.max(deterministicResult.urgencyScore, contextualResult.urgencyScore);
      const isEscalated = deterministicResult.classification === "escalated" || contextualResult.classification === "escalated";
      const isFlagged = deterministicResult.classification === "flagged" || contextualResult.classification === "flagged";

      const finalClassification = isEscalated ? "escalated" : isFlagged ? "flagged" : "cleared";
      const combinedSignals = Array.from(new Set([...deterministicResult.detectedSignals, ...contextualResult.detectedSignals]));

      return {
        ...contextualResult,
        classification: finalClassification,
        urgencyScore: higherUrgency,
        detectedSignals: combinedSignals,
        provider: `${this.contextualProvider.name}+deterministic`,
      };
    } catch (err) {
      // SAFE DEGRADATION: External provider failure MUST NEVER silently clear content!
      const errorMsg = err instanceof Error ? err.message : String(err);

      // If deterministic layer found danger, escalate/flag it; otherwise route to human review
      const isDangerous = deterministicResult.classification !== "cleared";

      return {
        category: categoryId,
        classification: isDangerous ? deterministicResult.classification : "review_required",
        severity: isDangerous ? deterministicResult.severity : "medium",
        confidence: 0.5,
        recommendedAction: "require_human_review",
        explanation: `Contextual moderation provider unavailable (${errorMsg.slice(0, 100)}). Flagged for human review.`,
        detectedSignals: [
          ...deterministicResult.detectedSignals,
          "Provider Degraded: Human Review Required",
        ],
        urgencyScore: Math.max(50, deterministicResult.urgencyScore),
        policyVersion: CURRENT_MODERATION_POLICY.policyVersion,
        modelVersion: "fallback-safe",
        provider: "fail-safe-human-review",
        reviewStatus: "review_required",
      };
    }
  }

  /**
   * Applies authenticated human moderator review override.
   */
  applyHumanOverride(
    originalResult: ModerationResultSchema,
    override: {
      reviewerId: string;
      overrideAction: "APPROVE" | "FLAG" | "ESCALATE" | "REJECT_MODERATION_RESULT" | "REQUIRE_HUMAN_REVIEW";
      reason: string;
    }
  ): ModerationResultSchema {
    if (!CURRENT_MODERATION_POLICY.allowedOverrideActions.includes(override.overrideAction)) {
      throw new Error(`Invalid override action: ${override.overrideAction}`);
    }

    if (!override.reason || override.reason.trim().length < 5) {
      throw new Error("Human override requires a documented reason of at least 5 characters.");
    }

    let newClassification: ModerationResultSchema["classification"] = originalResult.classification;
    let newAction: ModerationResultSchema["recommendedAction"] = originalResult.recommendedAction;

    switch (override.overrideAction) {
      case "APPROVE":
        newClassification = "cleared";
        newAction = "approve";
        break;
      case "FLAG":
        newClassification = "flagged";
        newAction = "flag";
        break;
      case "ESCALATE":
        newClassification = "escalated";
        newAction = "escalate";
        break;
      case "REJECT_MODERATION_RESULT":
      case "REQUIRE_HUMAN_REVIEW":
        newClassification = "review_required";
        newAction = "require_human_review";
        break;
    }

    return {
      ...originalResult,
      classification: newClassification,
      recommendedAction: newAction,
      reviewStatus: "override",
      overrideMetadata: {
        reviewerId: override.reviewerId,
        overrideAction: override.overrideAction,
        reason: override.reason.trim(),
        timestamp: new Date().toISOString(),
      },
    };
  }
}

export const moderationPipeline = new ModerationPipeline();
