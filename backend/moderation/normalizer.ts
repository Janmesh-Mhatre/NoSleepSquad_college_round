/**
 * Robust Text Normalizer for Multi-lingual and Adversarially Obfuscated Content
 * Supports English, Hindi (Devanagari), Hinglish, leetspeak, homoglyphs, and PII pre-scrubbing.
 */

// Common homoglyph substitutions (Cyrillic, Greek, mathematical lookalikes -> Latin)
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic lookalikes
  а: "a",
  е: "e",
  о: "o",
  р: "p",
  с: "c",
  у: "y",
  х: "x",
  і: "i",
  ј: "j",
  ѕ: "s",
  т: "t",
  к: "k",
  м: "m",
  н: "h",
  в: "b",
  д: "d",
  п: "n",
  // Common fullwidth characters
  "ａ": "a",
  "ｂ": "b",
  "ｃ": "c",
  "ｄ": "d",
  "ｅ": "e",
  "ｆ": "f",
  "ｇ": "g",
  "ｈ": "h",
  "ｉ": "i",
  "ｊ": "j",
  "ｋ": "k",
  "ｌ": "l",
  "ｍ": "m",
  "ｎ": "n",
  "ｏ": "o",
  "ｐ": "p",
  "ｑ": "q",
  "ｒ": "r",
  "ｓ": "s",
  "ｔ": "t",
  "ｕ": "u",
  "ｖ": "v",
  "ｗ": "w",
  "ｘ": "x",
  "ｙ": "y",
  "ｚ": "z",
  "０": "0",
  "１": "1",
  "２": "2",
  "３": "3",
  "４": "4",
  "５": "5",
  "６": "6",
  "７": "7",
  "８": "8",
  "９": "9",
};

// Common leetspeak substitutions
const LEETSPEAK_MAP: Record<string, string> = {
  "0": "o",
  "1": "i",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  "@": "a",
  $: "s",
  "+": "t",
};

export class TextNormalizer {
  /**
   * Performs full multi-step normalization pipeline:
   * 1. Unicode NFKC normalization
   * 2. Homoglyph substitution
   * 3. Invisible character stripping
   * 4. De-obfuscating intra-character delimiter chains (e.g. "t-h-r-e-a-t", "d_h_a_m_k_i")
   * 5. Repeated character compression (e.g. "khaaatraaa" -> "khatra")
   * 6. Whitespace collapse
   */
  normalize(text: string): string {
    if (!text || typeof text !== "string") return "";

    // 1. Unicode NFKC Normalization & lowercase
    let result = text.normalize("NFKC").toLowerCase();

    // 2. Homoglyph substitution
    let homoglyphClean = "";
    for (const char of result) {
      homoglyphClean += HOMOGLYPH_MAP[char] || char;
    }
    result = homoglyphClean;

    // 3. Strip zero-width spaces, soft hyphens, and invisible formatting
    result = result.replace(/[\u200B-\u200D\uFEFF\u00AD]/g, "");

    // 4. De-obfuscate intra-word separators between single characters (e.g. "t-h-r-e-a-t", "d.h.a.m.k.i")
    result = result.replace(/\b([a-z0-9](?:[-._*\/][a-z0-9])+)\b/gi, (match) =>
      match.replace(/[-._*\/]/g, "")
    );

    // 5. Repeated character reduction: compress 3+ repeating chars into 1 (e.g. "dhhhaaamkiiii" -> "dhamki")
    result = result.replace(/(.)\1{2,}/g, "$1");

    // 6. Whitespace collapse
    result = result.replace(/\s+/g, " ").trim();

    return result;
  }

  /**
   * Applies leetspeak replacement to expand masked words
   */
  expandLeetspeak(text: string): string {
    let expanded = text.toLowerCase();
    // Context-sensitive '1': if after consonant cluster like 'b', 'c', 'f', 'g', 'p', 's' followed by vowel -> 'l'
    expanded = expanded.replace(/([bcfgps])1([aeiou])/gi, "$1l$2");
    for (const [leet, normal] of Object.entries(LEETSPEAK_MAP)) {
      expanded = expanded.split(leet).join(normal);
    }
    return expanded;
  }

  /**
   * Scrubs Personal Identifiable Information (PII) before transmission to external AI models.
   * Redacts emails, phone numbers, and student/employee IDs.
   */
  scrubPII(text: string): string {
    if (!text || typeof text !== "string") return "";
    return text
      // Replace emails
      .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]")
      // Replace phone numbers (international & domestic)
      .replace(/(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g, "[REDACTED_PHONE]")
      // Replace student / employee registration and roll numbers
      .replace(/\b(?:STU|EMP|ID|ROLL|REG|PRN|UID)?\d{6,10}\b/gi, "[REDACTED_ID]");
  }
}

export const textNormalizer = new TextNormalizer();
