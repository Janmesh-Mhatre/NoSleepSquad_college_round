import { BaseModerationProvider } from "./base.js";
import type { ModerationResultSchema, ModerationClassification, ModerationSeverity } from "../schemas/moderationResult.js";
import { DETERMINISTIC_RULES } from "../rules/deterministicRules.js";
import { textNormalizer } from "../normalizer.js";
import { promptInjectionDefense } from "../injectionDefense.js";
import { CURRENT_MODERATION_POLICY } from "../policies/index.js";

export class DeterministicModerationProvider extends BaseModerationProvider {
  readonly name = "deterministic-rule-engine";
  readonly modelVersion = "rules-2026.5";

  async isAvailable(): Promise<boolean> {
    return true;
  }

  async moderate(rawText: string, categoryId: string): Promise<ModerationResultSchema> {
    const normalized = textNormalizer.normalize(rawText);
    const leetExpanded = textNormalizer.expandLeetspeak(normalized);
    const combined = `${normalized} ${leetExpanded}`;

    // Prompt injection check
    const injection = promptInjectionDefense.detectInjection(normalized);

    const signals: string[] = [];
    let urgencyScore = 20;

    if (injection.isSuspicious) {
      signals.push("Adversarial Instruction Marker Detected");
      urgencyScore += 30;
    }

    // Evaluate all deterministic rules
    for (const rule of DETERMINISTIC_RULES) {
      const match = rule.keywords.some((kw) => combined.includes(kw.toLowerCase()));
      if (match) {
        signals.push(`${rule.category}: ${rule.name}`);
        urgencyScore += rule.urgencyDelta;
      }
    }

    // Category risk tier adjustment
    const categoryRisk = CURRENT_MODERATION_POLICY.categoryRiskTiers[categoryId] || "standard";
    if (categoryRisk === "urgent") {
      urgencyScore += 15;
    } else if (categoryRisk === "elevated") {
      urgencyScore += 10;
    }

    urgencyScore = Math.min(100, Math.max(10, urgencyScore));

    let classification: ModerationClassification = "cleared";
    let severity: ModerationSeverity = "low";

    if (urgencyScore >= CURRENT_MODERATION_POLICY.escalationThreshold) {
      classification = "escalated";
      severity = "critical";
    } else if (urgencyScore >= CURRENT_MODERATION_POLICY.flagThreshold || signals.length > 0) {
      classification = "flagged";
      severity = urgencyScore >= 60 ? "high" : "medium";
    }

    const recommendedAction = classification === "escalated"
      ? "escalate"
      : classification === "flagged"
      ? "flag"
      : "approve";

    const confidence = Math.min(0.98, parseFloat((0.82 + signals.length * 0.04).toFixed(2)));

    return {
      category: categoryId,
      classification,
      severity,
      confidence,
      recommendedAction,
      explanation: signals.length > 0
        ? `Identified ${signals.length} safety signal(s): ${signals.slice(0, 3).join(", ")}`
        : "Standard non-urgent disclosure evaluation.",
      detectedSignals: signals.length > 0 ? signals : ["Standard Content Evaluation"],
      urgencyScore,
      policyVersion: CURRENT_MODERATION_POLICY.policyVersion,
      modelVersion: this.modelVersion,
      provider: this.name,
      reviewStatus: "automated",
    };
  }
}

export const deterministicProvider = new DeterministicModerationProvider();
