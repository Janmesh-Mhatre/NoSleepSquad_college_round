import type { ModerationResultSchema } from "../schemas/moderationResult.js";

export interface ModerationProviderOptions {
  apiKey?: string;
  model?: string;
  timeoutMs?: number;
  maxRetries?: number;
}

export abstract class BaseModerationProvider {
  abstract readonly name: string;
  abstract readonly modelVersion: string;

  /**
   * Health check to confirm provider readiness.
   */
  abstract isAvailable(): Promise<boolean>;

  /**
   * Evaluates scrubbed & normalized report text.
   * Strictly guarantees that NO student credentials, tokens, IP, or identity metadata are passed.
   */
  abstract moderate(
    normalizedText: string,
    categoryId: string
  ): Promise<ModerationResultSchema>;
}
