/**
 * useRedaction hook
 *
 * Orchestrates the full detect → redact → verify pipeline and exposes state to
 * the UI. Processing runs in a Web Worker with a hard timeout, so large inputs
 * keep the page responsive and a pathological custom regex cannot hang it.
 * All sensitive data stays in local memory; nothing is persisted.
 */

import { useState, useCallback, useRef, useEffect } from 'react'
import type { DetectionResult, DetectionSummary } from '../types/detection'
import type { MaskingOptions } from '../types/redaction'
import type { CustomRule } from '../types/rules'
import type { DetectionEngineOptions } from '../engine/detectionEngine'
import { runPipeline, type PipelineResult } from '../engine/pipeline'
import type { PipelineRequest } from '../engine/pipeline.worker'
import { DEFAULT_MASKING_OPTIONS } from '../types/redaction'

export interface RedactionState {
  maskedText: string
  detections: DetectionResult[]
  summary: DetectionSummary
  /** Detections still found when re-scanning the masked output. */
  residualCount: number
  isProcessing: boolean
  error: string | null
  hasRun: boolean
}

export interface RedactionControls {
  maskSecrets: (text: string) => void
  reset: () => void
  setMaskingOptions: (opts: Partial<MaskingOptions>) => void
  setCustomRules: (rules: CustomRule[]) => void
  setEngineOptions: (opts: Partial<DetectionEngineOptions>) => void
  maskingOptions: MaskingOptions
  customRules: CustomRule[]
  engineOptions: DetectionEngineOptions
}

/** Hard limit for one processing run before the worker is killed. */
const PROCESSING_TIMEOUT_MS = 15_000

const INITIAL_SUMMARY: DetectionSummary = {
  total: 0,
  byCategory: {},
  hasLowConfidence: false,
}

const EMPTY_STATE: RedactionState = {
  maskedText: '',
  detections: [],
  summary: INITIAL_SUMMARY,
  residualCount: 0,
  isProcessing: false,
  error: null,
  hasRun: false,
}

type WorkerReply = { id: number; ok: true; result: PipelineResult } | { id: number; ok: false; error: string }

function createWorker(): Worker | null {
  if (typeof Worker === 'undefined') return null
  try {
    return new Worker(new URL('../engine/pipeline.worker.ts', import.meta.url), { type: 'module' })
  } catch {
    return null
  }
}

export function useRedaction(): [RedactionState, RedactionControls] {
  const [state, setState] = useState<RedactionState>(EMPTY_STATE)

  const [maskingOptions, setMaskingOptionsState] = useState<MaskingOptions>(DEFAULT_MASKING_OPTIONS)
  const [customRules, setCustomRulesState] = useState<CustomRule[]>([])
  const [engineOptions, setEngineOptionsState] = useState<DetectionEngineOptions>({
    enableKeyBased: true,
    enableTokens: true,
    enableConnectionStrings: true,
    enablePrivateKeys: true,
    enableCustom: true,
    enableEntropy: true,
  })

  // Monotonic run id: replies for anything but the latest run are ignored
  const runIdRef = useRef(0)
  const workerRef = useRef<Worker | null>(null)
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const clearTimer = () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current)
    timeoutRef.current = null
  }

  const killWorker = () => {
    workerRef.current?.terminate()
    workerRef.current = null
  }

  useEffect(
    () => () => {
      clearTimer()
      killWorker()
    },
    [],
  )

  const applyResult = (result: PipelineResult) => {
    setState({
      maskedText: result.maskedText,
      detections: result.detections,
      summary: result.summary,
      residualCount: result.residual.length,
      isProcessing: false,
      error: null,
      hasRun: true,
    })
  }

  const applyError = (message: string) => {
    setState(prev => ({ ...prev, isProcessing: false, error: message, hasRun: true }))
  }

  const maskSecrets = useCallback(
    (text: string) => {
      if (!text || text.trim().length === 0) {
        runIdRef.current++
        setState({ ...EMPTY_STATE, hasRun: true })
        return
      }

      const id = ++runIdRef.current
      const opts: DetectionEngineOptions = { ...engineOptions, customRules }

      if (!workerRef.current) workerRef.current = createWorker()
      const worker = workerRef.current

      // Fallback: no Worker support → run synchronously
      if (!worker) {
        try {
          applyResult(runPipeline(text, opts, maskingOptions))
        } catch (err) {
          applyError('An unexpected error occurred during processing.')
          console.error('[PasteGuard] Processing error:', (err as Error).message)
        }
        return
      }

      setState(prev => ({ ...prev, isProcessing: true, error: null }))
      clearTimer()

      worker.onmessage = (e: MessageEvent<WorkerReply>) => {
        if (e.data.id !== runIdRef.current) return
        clearTimer()
        if (e.data.ok) applyResult(e.data.result)
        else {
          applyError('An unexpected error occurred during processing.')
          console.error('[PasteGuard] Processing error:', e.data.error)
        }
      }
      worker.onerror = () => {
        if (id !== runIdRef.current) return
        clearTimer()
        killWorker()
        applyError('The processing worker failed. Please try again.')
      }

      timeoutRef.current = setTimeout(() => {
        if (id !== runIdRef.current) return
        killWorker() // a fresh worker is created on the next run
        applyError(
          `Processing took longer than ${PROCESSING_TIMEOUT_MS / 1000}s and was stopped. ` +
            'A custom regex rule may be too slow — check your custom rules.',
        )
      }, PROCESSING_TIMEOUT_MS)

      const request: PipelineRequest = { id, text, engineOptions: opts, maskingOptions }
      worker.postMessage(request)
    },
    [engineOptions, customRules, maskingOptions],
  )

  const reset = useCallback(() => {
    runIdRef.current++ // ignore any in-flight reply
    clearTimer()
    setState(EMPTY_STATE)
  }, [])

  const setMaskingOptions = useCallback((opts: Partial<MaskingOptions>) => {
    setMaskingOptionsState(prev => ({ ...prev, ...opts }))
  }, [])

  const setCustomRules = useCallback((rules: CustomRule[]) => {
    setCustomRulesState(rules)
  }, [])

  const setEngineOptions = useCallback((opts: Partial<DetectionEngineOptions>) => {
    setEngineOptionsState(prev => ({ ...prev, ...opts }))
  }, [])

  const controls: RedactionControls = {
    maskSecrets,
    reset,
    setMaskingOptions,
    setCustomRules,
    setEngineOptions,
    maskingOptions,
    customRules,
    engineOptions,
  }

  return [state, controls]
}
