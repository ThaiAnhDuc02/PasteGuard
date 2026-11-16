/**
 * Detection Engine Orchestrator
 *
 * Coordinates all detectors, deduplicates results, and returns a
 * sorted, normalised list of DetectionResult objects.
 *
 * Order of execution:
 *   1. privateKeyDetector  — large blocks; run first so they can be excluded
 *                            from subsequent key-based scans if needed
 *   2. tokenDetector       — structured token patterns (JWT, AWS, GitHub…)
 *   3. connectionStringDetector — URL-style and JDBC connection strings
 *   4. keyBasedDetector    — field-name heuristics
 *   5. customDetector      — user-defined rules (last, lowest priority for dedup)
 *
 * Post-processing:
 *   - Sort by start offset ascending.
 *   - Remove exact duplicates (same start+end from different detectors).
 *   - The overlap resolver (phase 3) handles true overlaps at redaction time.
 */

import type { DetectionResult, DetectionSummary, SecretCategory } from '../types/detection'
import type { CustomRule } from '../types/rules'
import { privateKeyDetector } from './detectors/privateKeyDetector'
import { tokenDetector } from './detectors/tokenDetector'
import { connectionStringDetector } from './detectors/connectionStringDetector'
import { keyBasedDetector } from './detectors/keyBasedDetector'
import { customDetector } from './detectors/customDetector'

export interface DetectionEngineOptions {
  /** Set to false to skip individual detector families. */
  enableKeyBased?: boolean
  enableTokens?: boolean
  enableConnectionStrings?: boolean
  enablePrivateKeys?: boolean
  enableCustom?: boolean
  /** Flag high-entropy values under unknown keys (LOW confidence). */
  enableEntropy?: boolean
  /** Custom rules to pass to the custom detector. */
  customRules?: CustomRule[]
  /**
   * Strict mode: include LOW confidence results.
   * When false (default), LOW confidence results are still returned
   * but flagged so the UI can warn the user.
   */
  strictMode?: boolean
}

export interface DetectionEngineResult {
  detections: DetectionResult[]
  summary: DetectionSummary
}

export function runDetection(text: string, options: DetectionEngineOptions = {}): DetectionEngineResult {
  if (!text || text.length === 0) {
    return { detections: [], summary: emptySummary() }
  }

  const {
    enableKeyBased = true,
    enableTokens = true,
    enableConnectionStrings = true,
    enablePrivateKeys = true,
    enableCustom = true,
    enableEntropy = true,
    customRules = [],
  } = options

  // Configure custom detector
  customDetector.setRules(customRules)

  const all: DetectionResult[] = []

  if (enablePrivateKeys) {
    privateKeyDetector.enabled = true
    all.push(...privateKeyDetector.detect(text))
  }

  if (enableTokens) {
    tokenDetector.enabled = true
    all.push(...tokenDetector.detect(text))
  }

  if (enableConnectionStrings) {
    connectionStringDetector.enabled = true
    all.push(...connectionStringDetector.detect(text))
  }

  if (enableKeyBased) {
    keyBasedDetector.enabled = true
    keyBasedDetector.entropyFallback = enableEntropy
    all.push(...keyBasedDetector.detect(text))
  }

  if (enableCustom && customRules.length > 0) {
    customDetector.enabled = true
    all.push(...customDetector.detect(text))
  }

  // Sort by start offset ascending, then by confidence descending so the
  // best match wins during deduplication.
  const confidenceOrder: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 }
  all.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start
    return confidenceOrder[a.confidence] - confidenceOrder[b.confidence]
  })

  // Deduplicate: remove results with identical [start, end] keeping the first
  // (highest confidence due to sort above).
  const seen = new Set<string>()
  const deduped: DetectionResult[] = []
  for (const r of all) {
    const key = `${r.start}:${r.end}`
    if (!seen.has(key)) {
      seen.add(key)
      deduped.push(r)
    }
  }

  const summary = buildSummary(deduped)
  return { detections: deduped, summary }
}

function emptySummary(): DetectionSummary {
  return { total: 0, byCategory: {}, hasLowConfidence: false }
}

function buildSummary(results: DetectionResult[]): DetectionSummary {
  const byCategory: Partial<Record<SecretCategory, number>> = {}
  let hasLowConfidence = false

  for (const r of results) {
    byCategory[r.category] = (byCategory[r.category] ?? 0) + 1
    if (r.confidence === 'LOW') hasLowConfidence = true
  }

  return { total: results.length, byCategory, hasLowConfidence }
}
