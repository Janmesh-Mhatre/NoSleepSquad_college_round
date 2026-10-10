import { BaseModerationProvider } from "./base.js";
import type { ModerationResultSchema } from "../schemas/moderationResult.js";

export class MockModerationProvider extends BaseModerationProvider {
  readonly name = "mock-moderation-provider";
  readonly modelVersion = "mock-v1";

  private shouldFail = false;
  private failureMode: "timeout" | "malformed_json" | "server_error" | "rate_limit" | null = null;
  private customResult: Partial<ModerationResultSchema> | null = null;

  setSimulatedFailure(mode: "timeout" | "malformed_json" | "server_error" | "rate_limit" | null) {
    this.failureMode = mode;
    this.shouldFail = mode !== null;
  }

  setCustomResult(result: Partial<ModerationResultSchema> | null) {
    this.customResult = result;
  }

  async isAvailable(): Promise<boolean> {
    return !this.shouldFail;
  }

  async moderate(normalizedText: string, categoryId: string): Promise<ModerationResultSchema> {
    if (this.shouldFail) {
      if (this.failureMode === "timeout") {
        throw new Error("PROVIDER_TIMEOUT: Request exceeded configured timeout threshold (3000ms)");
      }
      if (this.failureMode === "rate_limit") {
        throw new Error("PROVIDER_RATE_LIMIT: 429 Too Many Requests");
      }
      if (this.failureMode === "server_error") {
        throw new Error("PROVIDER_OUTAGE: 503 Service Unavailable");
      }
      if (this.failureMode === "malformed_json") {
        throw new Error("PROVIDER_MALFORMED_OUTPUT: Unexpected token < in JSON at position 0");
      }
    }

    if (this.customResult) {
      return {
        category: categoryId,
        classification: this.customResult.classification || "cleared",
        severity: this.customResult.severity || "low",
        confidence: this.customResult.confidence || 0.9,
        recommendedAction: this.customResult.recommendedAction || "approve",
        explanation: this.customResult.explanation || "Mock provider custom evaluation",
        detectedSignals: this.customResult.detectedSignals || ["Mock Signal"],
        urgencyScore: this.customResult.urgencyScore || 30,
        policyVersion: "2026.5-mock",
        modelVersion: this.modelVersion,
        provider: this.name,
        reviewStatus: "automated",
      };
    }

    // Default mock behavior based on keywords
    const lower = normalizedText.toLowerCase();
    const isEscalated = lower.includes("hazard") || lower.includes("threat") || lower.includes("dhamki");
    const isFlagged = lower.includes("cheat") || lower.includes("bribe") || lower.includes("ragging");

    const classification = isEscalated ? "escalated" : isFlagged ? "flagged" : "cleared";
    const urgencyScore = isEscalated ? 80 : isFlagged ? 55 : 25;

    return {
      category: categoryId,
      classification,
      severity: isEscalated ? "high" : isFlagged ? "medium" : "low",
      confidence: 0.95,
      recommendedAction: isEscalated ? "escalate" : isFlagged ? "flag" : "approve",
      explanation: "Offline deterministic mock provider evaluation.",
      detectedSignals: [classification],
      urgencyScore,
      policyVersion: "2026.5-mock",
      modelVersion: this.modelVersion,
      provider: this.name,
      reviewStatus: "automated",
    };
  }
}

export const mockModerationProvider = new MockModerationProvider();
