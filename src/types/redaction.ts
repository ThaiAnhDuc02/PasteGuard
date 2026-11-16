/**
 * Redaction strategy types.
 */

export type MaskingStrategy =
  | 'FULL_MASK' // Replace entire value with ********
  | 'FIXED_MASK' // Replace with exactly *****
  | 'PLACEHOLDER' // Replace with [CATEGORY_N]
  | 'PARTIAL_MASK' // Keep first/last N chars, mask the rest

export interface MaskingOptions {
  strategy: MaskingStrategy
  /** For PARTIAL_MASK: number of leading characters to keep. Default 2. */
  leadingChars?: number
  /** For PARTIAL_MASK: number of trailing characters to keep. Default 4. */
  trailingChars?: number
  /** Character to use for masking. Default '*'. */
  maskChar?: string
  /** For FULL_MASK: fixed length of mask. Default 8. */
  fullMaskLength?: number
}

export const DEFAULT_MASKING_OPTIONS: MaskingOptions = {
  strategy: 'FULL_MASK',
  leadingChars: 2,
  trailingChars: 4,
  maskChar: '*',
  fullMaskLength: 8,
}

export interface RedactionResult {
  /** The sanitized output text. */
  maskedText: string
  /** Number of distinct spans redacted. */
  redactedCount: number
  /**
   * Map from placeholder label to the count of occurrences,
   * used for PLACEHOLDER strategy to show consistency.
   */
  placeholderMap: Map<string, number>
}
