/**
 * Web Worker entry: runs the detect → redact → verify pipeline off the main
 * thread. The UI enforces a hard timeout and terminates this worker if it
 * exceeds it (e.g. a pathological custom regex), so the page never freezes.
 *
 * Input text and results only ever travel between this worker and the page
 * via postMessage — nothing is logged or sent anywhere else.
 */
import { runPipeline } from './pipeline'
import type { DetectionEngineOptions } from './detectionEngine'
import type { MaskingOptions } from '../types/redaction'

export interface PipelineRequest {
  id: number
  text: string
  engineOptions: DetectionEngineOptions
  maskingOptions: MaskingOptions
}

const scope = self as unknown as {
  onmessage: ((e: MessageEvent<PipelineRequest>) => void) | null
  postMessage(message: unknown): void
}

scope.onmessage = e => {
  const { id, text, engineOptions, maskingOptions } = e.data
  try {
    const result = runPipeline(text, engineOptions, maskingOptions)
    scope.postMessage({ id, ok: true, result })
  } catch (err) {
    // Error type/message only — never the input or detected values
    scope.postMessage({ id, ok: false, error: (err as Error).message })
  }
}
