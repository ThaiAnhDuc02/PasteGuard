/**
 * useEditor hook
 *
 * Manages the input editor state: content, detected format, and
 * the Monaco editor instance reference.
 */

import { useState, useCallback, useRef } from 'react'
import type { editor as MonacoEditor } from 'monaco-editor'
import type { InputFormat } from '../types/detection'
import { detectFormat, formatToMonacoLanguage } from '../engine/parser/formatDetector'

export interface EditorState {
  inputText: string
  detectedFormat: InputFormat
  selectedFormat: InputFormat
  monacoLanguage: string
}

export interface EditorControls {
  setInputText: (text: string) => void
  setSelectedFormat: (format: InputFormat) => void
  clearInput: () => void
  editorRef: React.MutableRefObject<MonacoEditor.IStandaloneCodeEditor | null>
  outputEditorRef: React.MutableRefObject<MonacoEditor.IStandaloneCodeEditor | null>
}

export function useEditor(): [EditorState, EditorControls] {
  const [inputText, setInputTextState] = useState('')
  const [selectedFormat, setSelectedFormatState] = useState<InputFormat>('AUTO')
  const [detectedFormat, setDetectedFormat] = useState<InputFormat>('PLAIN_TEXT')

  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null)
  const outputEditorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null)

  const setInputText = useCallback(
    (text: string) => {
      setInputTextState(text)
      if (selectedFormat === 'AUTO') {
        const detected = detectFormat(text)
        setDetectedFormat(detected)
      }
    },
    [selectedFormat],
  )

  const setSelectedFormat = useCallback(
    (format: InputFormat) => {
      setSelectedFormatState(format)
      if (format !== 'AUTO') {
        setDetectedFormat(format)
      } else {
        setDetectedFormat(detectFormat(inputText))
      }
    },
    [inputText],
  )

  const clearInput = useCallback(() => {
    setInputTextState('')
    setDetectedFormat('PLAIN_TEXT')
    if (editorRef.current) {
      editorRef.current.setValue('')
    }
    if (outputEditorRef.current) {
      outputEditorRef.current.setValue('')
    }
  }, [])

  const effectiveFormat = selectedFormat === 'AUTO' ? detectedFormat : selectedFormat
  const monacoLanguage = formatToMonacoLanguage(effectiveFormat)

  return [
    { inputText, detectedFormat, selectedFormat, monacoLanguage },
    { setInputText, setSelectedFormat, clearInput, editorRef, outputEditorRef },
  ]
}
