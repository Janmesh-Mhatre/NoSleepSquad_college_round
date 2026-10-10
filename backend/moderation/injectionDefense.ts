/**
 * Prompt Injection Defense & Input Isolation
 * Prevents adversarial report contents from hijacking contextual LLM evaluators.
 */

export interface InjectionCheckResult {
  isSuspicious: boolean;
  detectedSignatures: string[];
  sanitizedForPrompt: string;
}

const INJECTION_PATTERNS: { regex: RegExp; label: string }[] = [
  {
    regex: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|system)\s+(?:instructions|prompts|rules)/i,
    label: "Instruction Override Attempt",
  },
  {
    regex: /(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:a\s+different|dan|unrestricted|safe\s+evaluator)/i,
    label: "Persona Hijacking Attempt",
  },
  {
    regex: /(?:system\s*prompt|system\s*message|developer\s*mode|assistant\s*(?:response|verdict)\s*:)/i,
    label: "Fake System Delimiter Injection",
  },
  {
    regex: /(?:output\s+only\s+json\s+with\s+classification\s*:\s*["']?cleared["']?)/i,
    label: "Structured Output Coercion",
  },
  {
    regex: /(?:do\s+not\s+moderate|mark\s+this\s+(?:report\s+as\s+)?(?:safe|cleared|approved)|verdict\s*:\s*["']?cleared["']?)/i,
    label: "Direct Verdict Dictation",
  },
  {
    regex: /(?:<<<|>>>|<\|im_end\|>|<\|endoftext\|>|\[\/system\]|\[inst\])/i,
    label: "Special Token Injection",
  },
];

export class PromptInjectionDefense {
  /**
   * Scans normalized input for adversarial injection markers.
   */
  detectInjection(normalizedText: string): InjectionCheckResult {
    const detectedSignatures: string[] = [];

    for (const pattern of INJECTION_PATTERNS) {
      if (pattern.regex.test(normalizedText)) {
        detectedSignatures.push(pattern.label);
      }
    }

    // Sanitize by escaping known LLM boundary tokens and control characters
    let sanitized = normalizedText
      .replace(/<\|[a-z_0-9|]+\|>/gi, "[STRIPPED_TOKEN]")
      .replace(/\[\/?(INST|SYSTEM|SYS)\]/gi, "[STRIPPED_TAG]")
      .replace(/```/g, "'''");

    return {
      isSuspicious: detectedSignatures.length > 0,
      detectedSignatures,
      sanitizedForPrompt: sanitized,
    };
  }

  /**
   * Encloses untrusted report text inside strict boundary tags.
   */
  wrapWithIsolationDelimiters(text: string): string {
    return [
      "<<<BEGIN_UNTRUSTED_ANONYMOUS_REPORT_CONTENT>>>",
      text,
      "<<<END_UNTRUSTED_ANONYMOUS_REPORT_CONTENT>>>",
    ].join("\n");
  }
}

export const promptInjectionDefense = new PromptInjectionDefense();
