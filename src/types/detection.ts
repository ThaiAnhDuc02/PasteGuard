/**
 * Core detection types.
 * All detectors return DetectionResult[].
 * Offsets are character positions in the original input string.
 */
import type { MaskingStrategy } from './redaction'

export type SecretCategory =
  | 'PASSWORD'
  | 'USERNAME'
  | 'API_KEY'
  | 'TOKEN'
  | 'CONNECTION_STRING'
  | 'PRIVATE_KEY'
  | 'BEARER_TOKEN'
  | 'BASIC_AUTH'
  | 'AWS_CREDENTIAL'
  | 'GITHUB_TOKEN'
  | 'JWT'
  | 'OAUTH_SECRET'
  | 'GENERIC_SECRET'
  | 'CUSTOM'

export type ConfidenceLevel = 'HIGH' | 'MEDIUM' | 'LOW'

export type InputFormat =
  | 'AUTO'
  | 'PLAIN_TEXT'
  | 'JSON'
  | 'YAML'
  | 'XML'
  | 'SQL'
  | 'SOURCE_CODE'
  | 'ENV'
  | 'SHELL'
  | 'DOCKER'
  | 'KUBERNETES'
  | 'LOG'
  | 'HTTP_HEADERS'

/** A single detected secret span in the original string. */
export interface DetectionResult {
  /** Inclusive start character offset in the original string. */
  start: number
  /** Exclusive end character offset in the original string. */
  end: number
  /** The category of the secret found. */
  category: SecretCategory
  /** Unique identifier for the rule that produced this result. */
  ruleId: string
  /** Human-readable rule name. */
  ruleName: string
  /** Confidence in the detection. */
  confidence: ConfidenceLevel
  /** 1-based line number where the match begins. */
  line: number
  /** Whether the detection is from a custom user-defined rule. */
  isCustom?: boolean
  /** Per-detection masking override (custom rules). Undefined = global strategy. */
  maskingStrategy?: MaskingStrategy
}

/** Summary statistics over all detections in one processing pass. */
export interface DetectionSummary {
  total: number
  byCategory: Partial<Record<SecretCategory, number>>
  /** True if any low-confidence results are present (strict mode warning). */
  hasLowConfidence: boolean
}

/** Interface every detector must implement. */
export interface Detector {
  /** Unique stable identifier for this detector. */
  readonly id: string
  /** Whether this detector is currently enabled. */
  enabled: boolean
  /** Run detection against the full input text. */
  detect(text: string): DetectionResult[]
}

// Line-start index for the most recently scanned text. Every detector in one
// run scans the same string, so the index is built once (O(n)) and each lookup
// is a binary search (O(log n)) instead of a rescan from offset 0.
let indexedText: string | null = null
let lineStarts: number[] = [0]

function getLineStarts(text: string): number[] {
  if (text !== indexedText) {
    const starts = [0]
    let i = text.indexOf('\n')
    while (i !== -1) {
      starts.push(i + 1)
      i = text.indexOf('\n', i + 1)
    }
    indexedText = text
    lineStarts = starts
  }
  return lineStarts
}

/** Utility — compute 1-based line number for a given char offset. */
export function offsetToLine(text: string, offset: number): number {
  const starts = getLineStarts(text)
  let lo = 0
  let hi = starts.length - 1
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1
    if (starts[mid] <= offset) lo = mid
    else hi = mid - 1
  }
  return lo + 1
}
