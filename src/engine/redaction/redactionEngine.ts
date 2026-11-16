/**
 * Redaction Engine
 *
 * Takes the original text and a list of DetectionResult objects, resolves
 * overlaps, and rebuilds the output string in a single forward pass using
 * character-offset substitution.
 *
 * Key guarantee: every character between substitution spans is copied from
 * the original string byte-for-byte.  No parsing, no serialization.
 * Whitespace, indentation, line endings, and structure are all preserved.
 *
 * Security guarantee: the original secret values are never stored in a log,
 * error message, or return value other than the opaque `placeholderMap`
 * which maps replacement labels → occurrence counts (not the values).
 */

import type { DetectionResult } from '../../types/detection'
import type { MaskingOptions, RedactionResult } from '../../types/redaction'
import { DEFAULT_MASKING_OPTIONS } from '../../types/redaction'
import { resolveOverlaps } from './overlapResolver'
import {
  maskValue,
  createPlaceholderCounter,
  createPlaceholderValueMap,
  type MaskContext,
} from './maskingStrategies'

export interface RedactionEngineOptions {
  maskingOptions?: MaskingOptions
}

/**
 * Redact the given text using the provided detection results.
 *
 * @param text       The original input string.
 * @param detections Raw (possibly overlapping) DetectionResult list.
 * @param options    Masking configuration.
 * @returns          RedactionResult with the sanitised text and statistics.
 */
export function redactText(
  text: string,
  detections: DetectionResult[],
  options: RedactionEngineOptions = {},
): RedactionResult {
  const maskingOptions: MaskingOptions = {
    ...DEFAULT_MASKING_OPTIONS,
    ...(options.maskingOptions ?? {}),
  }

  if (detections.length === 0) {
    return {
      maskedText: text,
      redactedCount: 0,
      placeholderMap: new Map(),
    }
  }

  // Resolve overlaps to get a clean, non-overlapping, sorted list
  const resolved = resolveOverlaps(detections)

  const ctx: MaskContext = {
    options: maskingOptions,
    counter: createPlaceholderCounter(),
    valueMap: createPlaceholderValueMap(),
  }

  // Build the output string in a single forward pass
  const parts: string[] = []
  let cursor = 0

  for (const detection of resolved) {
    const { start, end, category, maskingStrategy } = detection

    // Safety: skip malformed ranges
    if (start < 0 || end > text.length || start >= end) continue
    // Skip if the cursor has already passed this range (shouldn't happen after
    // overlap resolution, but guard defensively)
    if (start < cursor) continue

    // Copy the unchanged prefix
    if (start > cursor) {
      parts.push(text.slice(cursor, start))
    }

    // Extract the secret span and produce its replacement
    const secretValue = text.slice(start, end)
    const replacement = maskValue(secretValue, category, ctx, maskingStrategy)
    parts.push(replacement)

    cursor = end
  }

  // Append any trailing unchanged text
  if (cursor < text.length) {
    parts.push(text.slice(cursor))
  }

  const maskedText = parts.join('')

  // Build the placeholder map (label → occurrence count) for the UI.
  // This map contains NO original secret values.
  const placeholderMap = new Map<string, number>()
  for (const [_value, label] of ctx.valueMap) {
    placeholderMap.set(label, (placeholderMap.get(label) ?? 0) + 1)
  }

  return {
    maskedText,
    redactedCount: resolved.length,
    placeholderMap,
  }
}

export { resolveOverlaps }
