/**
 * Overlap Resolver
 *
 * Given a list of DetectionResult objects (possibly overlapping), produces a
 * non-overlapping, sorted list suitable for linear redaction.
 *
 * Strategy:
 *   1. Sort by start ascending, then by span length descending (prefer larger
 *      spans so we don't leave fragments visible).
 *   2. Walk the list; whenever a new range overlaps the current active range,
 *      merge them into a single range that covers both.  The merged range keeps
 *      the category and ruleId of whichever had higher confidence.
 *
 * This guarantees:
 *   - No two output ranges overlap.
 *   - Every character covered by at least one input range is covered in output.
 *   - No original secret character leaks between adjacent redactions.
 */

import type { DetectionResult } from '../../types/detection'

const CONFIDENCE_RANK: Record<string, number> = { HIGH: 3, MEDIUM: 2, LOW: 1 }

export function resolveOverlaps(results: DetectionResult[]): DetectionResult[] {
  if (results.length === 0) return []

  // Sort: start asc, then span length desc (larger spans first at same start)
  const sorted = [...results].sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start
    const lenDiff = b.end - b.start - (a.end - a.start)
    if (lenDiff !== 0) return lenDiff
    return CONFIDENCE_RANK[b.confidence] - CONFIDENCE_RANK[a.confidence]
  })

  const merged: DetectionResult[] = []
  let current = sorted[0]

  for (let i = 1; i < sorted.length; i++) {
    const next = sorted[i]

    if (next.start < current.end) {
      // Overlapping or contained — merge
      const mergedEnd = Math.max(current.end, next.end)
      // Keep whichever has higher confidence; if equal, keep current (earlier)
      const winner = CONFIDENCE_RANK[next.confidence] > CONFIDENCE_RANK[current.confidence] ? next : current

      current = {
        ...winner,
        start: current.start,
        end: mergedEnd,
        // Compose rule names so the UI can show both sources
        ruleName:
          next.ruleId !== current.ruleId ? `${current.ruleName} / ${next.ruleName}` : current.ruleName,
      }
    } else {
      // No overlap — emit current and advance
      merged.push(current)
      current = next
    }
  }

  merged.push(current)
  return merged
}

/**
 * Quick check: does a list of results have any overlaps?
 * Used in tests and for fast-path skipping in the redaction engine.
 */
export function hasOverlaps(results: DetectionResult[]): boolean {
  if (results.length < 2) return false
  const sorted = [...results].sort((a, b) => a.start - b.start)
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].start < sorted[i - 1].end) return true
  }
  return false
}
