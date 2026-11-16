import type { FC } from 'react'
import type { InputFormat } from '../../types/detection'
import type { MaskingStrategy } from '../../types/redaction'
import type { DetectionEngineOptions } from '../../engine/detectionEngine'

interface ToolbarProps {
  selectedFormat: InputFormat
  detectedFormat: InputFormat
  maskingStrategy: MaskingStrategy
  engineOptions: DetectionEngineOptions
  onFormatChange: (f: InputFormat) => void
  onStrategyChange: (s: MaskingStrategy) => void
  onEngineOptionsChange: (opts: Partial<DetectionEngineOptions>) => void
  onClear: () => void
  onCustomRulesClick: () => void
  inputLength: number
}

const FORMAT_OPTIONS: { value: InputFormat; label: string }[] = [
  { value: 'AUTO', label: 'Auto Detect' },
  { value: 'PLAIN_TEXT', label: 'Plain Text' },
  { value: 'JSON', label: 'JSON' },
  { value: 'YAML', label: 'YAML' },
  { value: 'XML', label: 'XML' },
  { value: 'SQL', label: 'SQL' },
  { value: 'ENV', label: '.env' },
  { value: 'SHELL', label: 'Shell / CLI' },
  { value: 'DOCKER', label: 'Docker' },
  { value: 'KUBERNETES', label: 'Kubernetes' },
  { value: 'LOG', label: 'Logs' },
  { value: 'HTTP_HEADERS', label: 'HTTP Headers' },
  { value: 'SOURCE_CODE', label: 'Source Code' },
]

const STRATEGY_OPTIONS: { value: MaskingStrategy; label: string; desc: string }[] = [
  { value: 'FULL_MASK', label: 'Full Mask', desc: 'password=********' },
  { value: 'FIXED_MASK', label: 'Fixed Mask', desc: 'password=*****' },
  { value: 'PLACEHOLDER', label: 'Placeholder', desc: '[PASSWORD_1]' },
  { value: 'PARTIAL_MASK', label: 'Partial Mask', desc: 'sk****1234 (long tokens only)' },
]

const Toolbar: FC<ToolbarProps> = ({
  selectedFormat,
  detectedFormat,
  maskingStrategy,
  engineOptions,
  onFormatChange,
  onStrategyChange,
  onEngineOptionsChange,
  onClear,
  onCustomRulesClick,
  inputLength,
}) => {
  const toggle = (key: keyof DetectionEngineOptions) => {
    onEngineOptionsChange({ [key]: !engineOptions[key] })
  }

  return (
    <div className="flex flex-wrap items-center gap-2 px-4 py-2.5 bg-gray-850 border-b border-gray-700/60 bg-gray-800/60">
      {/* Format selector */}
      <div className="flex items-center gap-1.5">
        <label className="text-xs text-gray-400 whitespace-nowrap">Format:</label>
        <select
          value={selectedFormat}
          onChange={e => onFormatChange(e.target.value as InputFormat)}
          className="select-sm text-xs py-1"
          aria-label="Input format"
        >
          {FORMAT_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>
              {o.value === 'AUTO' && detectedFormat !== 'PLAIN_TEXT' ? `Auto (${detectedFormat})` : o.label}
            </option>
          ))}
        </select>
      </div>

      <div className="w-px h-5 bg-gray-600" />

      {/* Masking strategy */}
      <div className="flex items-center gap-1.5">
        <label className="text-xs text-gray-400 whitespace-nowrap">Strategy:</label>
        <select
          value={maskingStrategy}
          onChange={e => onStrategyChange(e.target.value as MaskingStrategy)}
          className="select-sm text-xs py-1"
          aria-label="Masking strategy"
        >
          {STRATEGY_OPTIONS.map(o => (
            <option key={o.value} value={o.value} title={o.desc}>
              {o.label}
            </option>
          ))}
        </select>
        <span className="hidden lg:block text-xs text-gray-500 font-mono">
          {STRATEGY_OPTIONS.find(o => o.value === maskingStrategy)?.desc}
        </span>
      </div>

      <div className="w-px h-5 bg-gray-600" />

      {/* Detection toggles */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs text-gray-400">Detect:</span>
        {(
          [
            ['enableKeyBased', 'Keys'],
            ['enableTokens', 'Tokens'],
            ['enableConnectionStrings', 'Conn.Strings'],
            ['enablePrivateKeys', 'PEM Keys'],
            ['enableEntropy', 'Entropy'],
          ] as [keyof DetectionEngineOptions, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => toggle(key)}
            className={`px-2 py-0.5 rounded text-xs font-medium border transition-colors ${
              engineOptions[key]
                ? 'bg-sky-900/60 border-sky-700/60 text-sky-300'
                : 'bg-gray-700/40 border-gray-600/40 text-gray-500'
            }`}
            aria-pressed={!!engineOptions[key]}
            title={`Toggle ${label} detection`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="w-px h-5 bg-gray-600" />

      {/* Custom rules */}
      <button
        onClick={onCustomRulesClick}
        className="btn-secondary text-xs py-1 flex items-center gap-1"
        title="Manage custom detection rules"
      >
        <svg className="w-3.5 h-3.5" viewBox="0 0 20 20" fill="currentColor">
          <path d="M10.75 4.75a.75.75 0 0 0-1.5 0v4.5h-4.5a.75.75 0 0 0 0 1.5h4.5v4.5a.75.75 0 0 0 1.5 0v-4.5h4.5a.75.75 0 0 0 0-1.5h-4.5v-4.5Z" />
        </svg>
        Custom Rules
      </button>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Input size indicator */}
      {inputLength > 0 && (
        <span className="text-xs text-gray-500 tabular-nums">{inputLength.toLocaleString()} chars</span>
      )}

      {/* Clear button */}
      <button
        onClick={onClear}
        className="btn-secondary text-xs py-1 text-red-400 hover:text-red-300 hover:bg-red-900/30"
        disabled={inputLength === 0}
        title="Clear all content"
      >
        Clear All
      </button>
    </div>
  )
}

export default Toolbar
