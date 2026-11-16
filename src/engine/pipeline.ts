/**
 * Full detect → redact → verify pipeline.
 *
 * Shared by the Web Worker (production UI) and the synchronous fallback
 * (tests, environments without Worker support).
 *
 * Verification ("second pass"): after redaction the masked output is scanned
 * again. Anything still detected — other than the masks themselves — is
 * reported as `residual` so the UI can warn before the user copies the text.
 */

import type { DetectionResult, DetectionSummary } from '../types/detection'
import type { MaskingOptions } from '../types/redaction'
import { DEFAULT_MASKING_OPTIONS } from '../types/redaction'
import { runDetection, type DetectionEngineOptions } from './detectionEngine'
import { redactText } from './redaction/redactionEngine'

export interface PipelineResult {
  maskedText: string
  detections: DetectionResult[]
  summary: DetectionSummary
  /** Detections still found in the masked output (should be empty). */
  residual: DetectionResult[]
}

const PLACEHOLDER_LABEL = /^\[[A-Z_]+_\d+\]$/

export function runPipeline(
  text: string,
  engineOptions: DetectionEngineOptions = {},
  maskingOptions: MaskingOptions = DEFAULT_MASKING_OPTIONS,
): PipelineResult {
  const opts = { ...DEFAULT_MASKING_OPTIONS, ...maskingOptions }
  const { detections, summary } = runDetection(text, engineOptions)
  const { maskedText } = redactText(text, detections, { maskingOptions: opts })

  let residual: DetectionResult[] = []
  if (detections.length > 0) {
    const maskRun = (opts.maskChar ?? '*').repeat(4)
    residual = runDetection(maskedText, { ...engineOptions, enableEntropy: false }).detections.filter(d => {
      if (d.confidence === 'LOW') return false
      const span = maskedText.slice(d.start, d.end)
      return !span.includes(maskRun) && !PLACEHOLDER_LABEL.test(span)
    })
  }

  return { maskedText, detections, summary, residual }
}
