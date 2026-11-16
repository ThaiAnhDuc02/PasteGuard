/**
 * Custom detection rule types.
 */
import type { SecretCategory, ConfidenceLevel } from './detection'
import type { MaskingStrategy } from './redaction'

export interface CustomRule {
  /** Unique stable identifier (UUID or user-supplied). */
  id: string
  /** Human-readable name. */
  name: string
  /**
   * Field name keywords to match (e.g. ["mySecret", "my_token"]).
   * Used in key-based scanning.
   */
  fieldNames: string[]
  /**
   * Optional regex pattern string applied to the full text.
   * Must be validated before saving.
   */
  regexPattern?: string
  /** Category to assign detections from this rule. */
  category: SecretCategory
  /** Override masking strategy for this rule. null = use global. */
  maskingStrategy: MaskingStrategy | null
  /** Confidence level to assign. */
  confidence: ConfidenceLevel
  enabled: boolean
}

export interface ValidationResult {
  valid: boolean
  error?: string
}

/**
 * Nested quantifiers such as `(a+)+`, `(\w*)*`, `(a|aa)+` or `(.*)+` are the
 * classic catastrophic-backtracking shapes. Rejected up front.
 */
const NESTED_QUANTIFIER = /\((?:\?:)?[^()]*(?:[+*]|\{\d+,\d*\})[^()]*\)(?:[+*]|\{\d+,\d*\})/
const ALTERNATION_UNDER_QUANTIFIER = /\((?:\?:)?[^()]*\|[^()]*\)(?:[+*]|\{\d+,\d*\})/

/**
 * Validate a regex pattern string.
 * - Must parse without syntax error.
 * - Must not contain nested quantifiers (static check).
 * - Must finish quickly on several adversarial inputs (measured after the
 *   fact — JavaScript cannot interrupt a running regex).
 *
 * This is a first line of defence. The real guarantee is that detection runs
 * in a Web Worker with a hard timeout (see useRedaction), which terminates a
 * runaway pattern instead of freezing the page.
 */
export function validateRegexPattern(pattern: string): ValidationResult {
  if (!pattern.trim()) return { valid: true }
  if (pattern.length > 10_000) return { valid: false, error: 'Regex is too long (max 10 000 chars).' }

  // Parse check
  try {
    new RegExp(pattern)
  } catch (e) {
    return { valid: false, error: `Invalid regex: ${(e as Error).message}` }
  }

  if (NESTED_QUANTIFIER.test(pattern) || ALTERNATION_UNDER_QUANTIFIER.test(pattern)) {
    return {
      valid: false,
      error: 'Nested quantifiers like (a+)+ or (a|b)* can freeze the page — please simplify the pattern.',
    }
  }

  // Runtime probe on several adversarial shapes
  const probes = ['a'.repeat(30) + '!', '1'.repeat(30) + 'x', ' '.repeat(30) + '!', 'aB1_'.repeat(10) + '\n']
  const start = Date.now()
  try {
    for (const probe of probes) {
      new RegExp(pattern, 'g').exec(probe)
      if (Date.now() - start > 50) {
        return { valid: false, error: 'Regex may cause catastrophic backtracking — too slow on test input.' }
      }
    }
  } catch {
    return { valid: false, error: 'Regex threw during test execution.' }
  }

  return { valid: true }
}
