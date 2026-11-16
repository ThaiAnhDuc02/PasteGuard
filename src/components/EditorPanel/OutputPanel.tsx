import { type FC, useCallback, useState } from 'react'
import Editor from '@monaco-editor/react'
import type { editor as MonacoEditorNS } from 'monaco-editor'
import { copyToClipboard } from '../../utils/clipboard'
import { downloadText, getDownloadFilename } from '../../utils/download'
import { formatBytes, countLines } from '../../utils/textUtils'
import type { InputFormat } from '../../types/detection'

interface OutputPanelProps {
  value: string
  language: string
  hasRun: boolean
  redactedCount: number
  format: InputFormat
  outputEditorRef: React.MutableRefObject<MonacoEditorNS.IStandaloneCodeEditor | null>
}

const MONACO_OPTIONS: MonacoEditorNS.IStandaloneEditorConstructionOptions = {
  readOnly: true,
  minimap: { enabled: false },
  fontSize: 13,
  fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
  lineNumbers: 'on',
  wordWrap: 'on',
  scrollBeyondLastLine: false,
  renderWhitespace: 'boundary',
  tabSize: 2,
  automaticLayout: true,
  theme: 'vs-dark',
  padding: { top: 8, bottom: 8 },
  overviewRulerLanes: 0,
  scrollbar: { verticalScrollbarSize: 6, horizontalScrollbarSize: 6 },
  domReadOnly: true,
  cursorStyle: 'line',
}

type CopyState = 'idle' | 'copied' | 'error'

const OutputPanel: FC<OutputPanelProps> = ({
  value,
  language,
  hasRun,
  redactedCount,
  format,
  outputEditorRef,
}) => {
  const [copyState, setCopyState] = useState<CopyState>('idle')

  const handleMount = useCallback(
    (editor: MonacoEditorNS.IStandaloneCodeEditor) => {
      outputEditorRef.current = editor
    },
    [outputEditorRef],
  )

  const handleCopy = async () => {
    if (!value) return
    try {
      await copyToClipboard(value)
      setCopyState('copied')
      setTimeout(() => setCopyState('idle'), 2000)
    } catch {
      setCopyState('error')
      setTimeout(() => setCopyState('idle'), 2000)
    }
  }

  const handleDownload = () => {
    if (!value) return
    downloadText(value, getDownloadFilename(format))
  }

  const lineCount = countLines(value)
  const byteCount = new TextEncoder().encode(value).length

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Panel header */}
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <span>Masked Output</span>
          {hasRun && value.length > 0 && (
            <span className="text-gray-500 font-mono normal-case text-xs">
              {lineCount} {lineCount === 1 ? 'line' : 'lines'} · {formatBytes(byteCount)}
            </span>
          )}
          {hasRun && redactedCount > 0 && (
            <span className="badge badge-red text-xs normal-case font-medium">{redactedCount} redacted</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <button
            onClick={handleCopy}
            disabled={!value}
            className="px-2 py-0.5 text-xs rounded transition-colors disabled:opacity-30
                       text-gray-400 hover:text-sky-300 hover:bg-sky-900/30"
            title="Copy to clipboard"
          >
            {copyState === 'copied' ? '✓ Copied' : copyState === 'error' ? '✗ Failed' : '⎘ Copy'}
          </button>
          <button
            onClick={handleDownload}
            disabled={!value}
            className="px-2 py-0.5 text-xs rounded transition-colors disabled:opacity-30
                       text-gray-400 hover:text-sky-300 hover:bg-sky-900/30"
            title="Download result"
          >
            ↓ Download
          </button>
        </div>
      </div>

      {/* Monaco editor */}
      <div className="flex-1 min-h-0 relative">
        {!hasRun && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <div className="text-center space-y-2 opacity-30">
              <div className="text-4xl">🔒</div>
              <p className="text-sm text-gray-400">Sanitized output will appear here</p>
            </div>
          </div>
        )}
        {hasRun && value.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <div className="text-center space-y-2 opacity-50">
              <div className="text-4xl">✅</div>
              <p className="text-sm text-gray-400">No secrets detected — input is clean</p>
            </div>
          </div>
        )}
        <Editor
          language={language}
          value={value}
          onMount={handleMount}
          options={MONACO_OPTIONS}
          theme="vs-dark"
          loading={
            <div className="flex items-center justify-center h-full text-gray-500 text-sm">
              Loading editor…
            </div>
          }
        />
      </div>

      {/* Footer */}
      <div className="px-3 py-2 bg-gray-800 border-t border-gray-700/60 flex items-center gap-2">
        <button
          onClick={handleCopy}
          disabled={!value}
          className="btn-secondary text-xs py-1 disabled:opacity-30"
        >
          ⎘ Copy Result
        </button>
        <button
          onClick={handleDownload}
          disabled={!value}
          className="btn-secondary text-xs py-1 disabled:opacity-30"
        >
          ↓ Download
        </button>
      </div>
    </div>
  )
}

export default OutputPanel
