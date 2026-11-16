import { type FC, useCallback } from 'react'
import Editor from '@monaco-editor/react'
import type { editor as MonacoEditorNS } from 'monaco-editor'
import { formatBytes, countLines } from '../../utils/textUtils'

interface InputPanelProps {
  value: string
  language: string
  onChange: (text: string) => void
  onClear: () => void
  onMaskSecrets: () => void
  isProcessing: boolean
  editorRef: React.MutableRefObject<MonacoEditorNS.IStandaloneCodeEditor | null>
}

const MONACO_OPTIONS: MonacoEditorNS.IStandaloneEditorConstructionOptions = {
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
}

const InputPanel: FC<InputPanelProps> = ({
  value,
  language,
  onChange,
  onClear,
  onMaskSecrets,
  isProcessing,
  editorRef,
}) => {
  const handleMount = useCallback(
    (editor: MonacoEditorNS.IStandaloneCodeEditor) => {
      editorRef.current = editor
    },
    [editorRef],
  )

  const lineCount = countLines(value)
  const byteCount = new TextEncoder().encode(value).length

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Panel header */}
      <div className="panel-header">
        <div className="flex items-center gap-2">
          <span>Original Input</span>
          {value.length > 0 && (
            <span className="text-gray-500 font-mono normal-case text-xs">
              {lineCount} {lineCount === 1 ? 'line' : 'lines'} · {formatBytes(byteCount)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {value.length > 0 && (
            <button
              onClick={onClear}
              className="px-2 py-0.5 text-xs text-gray-500 hover:text-red-400 transition-colors rounded"
              title="Clear input"
            >
              ✕ Clear
            </button>
          )}
        </div>
      </div>

      {/* Monaco editor */}
      <div className="flex-1 min-h-0 relative">
        {value.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
            <div className="text-center space-y-2 opacity-30">
              <div className="text-4xl">📋</div>
              <p className="text-sm text-gray-400">Paste your content here</p>
              <p className="text-xs text-gray-500">JSON · YAML · SQL · .env · source code · logs · …</p>
            </div>
          </div>
        )}
        <Editor
          language={language}
          value={value}
          onChange={v => onChange(v ?? '')}
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

      {/* MASK SECRETS button */}
      <div className="px-3 py-2.5 bg-gray-800 border-t border-gray-700/60 flex items-center gap-2">
        <button
          onClick={onMaskSecrets}
          disabled={isProcessing || value.trim().length === 0}
          className="flex-1 py-2.5 text-sm font-semibold tracking-wide rounded-lg
                     bg-sky-600 hover:bg-sky-500 active:bg-sky-700 text-white
                     disabled:opacity-50 disabled:cursor-not-allowed
                     transition-colors duration-150
                     flex items-center justify-center gap-2"
        >
          {isProcessing ? (
            <>
              <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                />
              </svg>
              Processing…
            </>
          ) : (
            <>
              <span>🛡️</span>
              MASK SECRETS
            </>
          )}
        </button>
      </div>
    </div>
  )
}

export default InputPanel
