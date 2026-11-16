import { type FC, useState } from 'react'
import type { CustomRule } from '../../types/rules'
import type { SecretCategory, ConfidenceLevel } from '../../types/detection'
import type { MaskingStrategy } from '../../types/redaction'
import { validateRegexPattern } from '../../types/rules'

interface SettingsPanelProps {
  isOpen: boolean
  onClose: () => void
  customRules: CustomRule[]
  onRulesChange: (rules: CustomRule[]) => void
}

const CATEGORY_OPTIONS: SecretCategory[] = [
  'PASSWORD',
  'USERNAME',
  'API_KEY',
  'TOKEN',
  'GENERIC_SECRET',
  'OAUTH_SECRET',
  'CONNECTION_STRING',
  'CUSTOM',
]

const CONFIDENCE_OPTIONS: ConfidenceLevel[] = ['HIGH', 'MEDIUM', 'LOW']

const STRATEGY_OPTIONS: { value: MaskingStrategy | null; label: string }[] = [
  { value: null, label: 'Use global strategy' },
  { value: 'FULL_MASK', label: 'Full Mask (********)' },
  { value: 'FIXED_MASK', label: 'Fixed Mask (*****)' },
  { value: 'PLACEHOLDER', label: 'Placeholder ([CATEGORY_N])' },
  { value: 'PARTIAL_MASK', label: 'Partial Mask (sk-****1234)' },
]

/**
 * crypto.randomUUID() only exists in secure contexts (HTTPS / localhost), so
 * it is undefined when the app is opened as http://<ip>:8080. getRandomValues
 * works everywhere.
 */
function newRuleId(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID()
  const bytes = crypto.getRandomValues(new Uint8Array(16))
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('')
}

function newRule(): CustomRule {
  return {
    id: newRuleId(),
    name: '',
    fieldNames: [],
    regexPattern: '',
    category: 'CUSTOM',
    maskingStrategy: null,
    confidence: 'MEDIUM',
    enabled: true,
  }
}

const SettingsPanel: FC<SettingsPanelProps> = ({ isOpen, onClose, customRules, onRulesChange }) => {
  const [editingRule, setEditingRule] = useState<CustomRule | null>(null)
  const [fieldNamesInput, setFieldNamesInput] = useState('')
  const [validationError, setValidationError] = useState<string | null>(null)

  if (!isOpen) return null

  const startEdit = (rule: CustomRule) => {
    setEditingRule({ ...rule })
    setFieldNamesInput(rule.fieldNames.join(', '))
    setValidationError(null)
  }

  const startNew = () => {
    setEditingRule(newRule())
    setFieldNamesInput('')
    setValidationError(null)
  }

  const cancelEdit = () => {
    setEditingRule(null)
    setValidationError(null)
  }

  const saveRule = () => {
    if (!editingRule) return
    if (!editingRule.name.trim()) {
      setValidationError('Rule name is required.')
      return
    }
    if (editingRule.regexPattern) {
      const result = validateRegexPattern(editingRule.regexPattern)
      if (!result.valid) {
        setValidationError(result.error ?? 'Invalid regex pattern.')
        return
      }
    }
    const fieldNames = fieldNamesInput
      .split(',')
      .map(s => s.trim())
      .filter(Boolean)
    const finalRule: CustomRule = { ...editingRule, fieldNames }
    const isExisting = customRules.some(r => r.id === finalRule.id)
    onRulesChange(
      isExisting
        ? customRules.map(r => (r.id === finalRule.id ? finalRule : r))
        : [...customRules, finalRule],
    )
    setEditingRule(null)
    setValidationError(null)
  }

  const deleteRule = (id: string) => {
    onRulesChange(customRules.filter(r => r.id !== id))
    if (editingRule?.id === id) setEditingRule(null)
  }

  const toggleRule = (id: string) => {
    onRulesChange(customRules.map(r => (r.id === id ? { ...r, enabled: !r.enabled } : r)))
  }

  const updateEditing = (patch: Partial<CustomRule>) => {
    setEditingRule(prev => (prev ? { ...prev, ...patch } : null))
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} aria-hidden />

      {/* Modal */}
      <div className="relative z-10 w-full max-w-2xl max-h-[90vh] flex flex-col bg-gray-900 border border-gray-700 rounded-xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700/60 shrink-0">
          <h2 className="text-base font-semibold text-white">Settings &amp; Custom Rules</h2>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded transition-colors"
            aria-label="Close settings"
          >
            ✕
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {/* Custom rules header */}
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-300">Custom Detection Rules</h3>
            <button onClick={startNew} className="btn-secondary text-xs py-1">
              + Add Rule
            </button>
          </div>

          {customRules.length === 0 && !editingRule && (
            <p className="text-sm text-gray-500 italic py-2 text-center">
              No custom rules defined. Click "Add Rule" to create one.
            </p>
          )}

          {/* Rule list */}
          {customRules.length > 0 && (
            <div className="space-y-2">
              {customRules.map(rule => (
                <div
                  key={rule.id}
                  className={`flex items-center justify-between gap-2 px-3 py-2 rounded-lg border transition-opacity
                    ${
                      rule.enabled
                        ? 'bg-gray-800 border-gray-700'
                        : 'bg-gray-800/40 border-gray-700/40 opacity-50'
                    }`}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <input
                      type="checkbox"
                      checked={rule.enabled}
                      onChange={() => toggleRule(rule.id)}
                      className="w-3.5 h-3.5 accent-sky-500 shrink-0"
                      aria-label={`Toggle "${rule.name}"`}
                    />
                    <span className="text-sm text-gray-200 truncate">{rule.name}</span>
                    <span className="badge badge-blue shrink-0">{rule.category}</span>
                    {rule.fieldNames.length > 0 && (
                      <span className="text-xs text-gray-500 font-mono truncate hidden sm:block">
                        {rule.fieldNames.join(', ')}
                      </span>
                    )}
                  </div>
                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      onClick={() => startEdit(rule)}
                      className="px-2 py-0.5 text-xs text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => deleteRule(rule.id)}
                      className="px-2 py-0.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-900/30 rounded transition-colors"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Rule editor */}
          {editingRule && (
            <div className="bg-gray-800 border border-sky-800/50 rounded-lg p-4 space-y-3">
              <h4 className="text-sm font-medium text-sky-300">
                {customRules.some(r => r.id === editingRule.id) ? 'Edit Rule' : 'New Rule'}
              </h4>

              {/* Name */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">Rule Name *</label>
                <input
                  type="text"
                  value={editingRule.name}
                  onChange={e => updateEditing({ name: e.target.value })}
                  placeholder="e.g. Internal API Token"
                  className="w-full bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5
                             focus:outline-none focus:ring-1 focus:ring-sky-500 focus:border-sky-500"
                />
              </div>

              {/* Field names */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  Field Names <span className="text-gray-500">(comma-separated, e.g. myToken, my_token)</span>
                </label>
                <input
                  type="text"
                  value={fieldNamesInput}
                  onChange={e => setFieldNamesInput(e.target.value)}
                  placeholder="myToken, my_token, MY_TOKEN"
                  className="w-full bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5
                             focus:outline-none focus:ring-1 focus:ring-sky-500 focus:border-sky-500 font-mono"
                />
              </div>

              {/* Regex pattern */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">
                  Regex Pattern{' '}
                  <span className="text-gray-500">(optional — use capture group for the secret span)</span>
                </label>
                <input
                  type="text"
                  value={editingRule.regexPattern ?? ''}
                  onChange={e => updateEditing({ regexPattern: e.target.value })}
                  placeholder="e.g. myapp_[A-Za-z0-9]{32}"
                  className="w-full bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5
                             focus:outline-none focus:ring-1 focus:ring-sky-500 focus:border-sky-500 font-mono"
                />
              </div>

              {/* Category + Confidence row */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Category</label>
                  <select
                    value={editingRule.category}
                    onChange={e => updateEditing({ category: e.target.value as SecretCategory })}
                    className="select-sm w-full text-sm"
                  >
                    {CATEGORY_OPTIONS.map(c => (
                      <option key={c} value={c}>
                        {c.replace(/_/g, ' ')}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-gray-400 mb-1">Confidence</label>
                  <select
                    value={editingRule.confidence}
                    onChange={e => updateEditing({ confidence: e.target.value as ConfidenceLevel })}
                    className="select-sm w-full text-sm"
                  >
                    {CONFIDENCE_OPTIONS.map(c => (
                      <option key={c} value={c}>
                        {c}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              {/* Masking strategy override */}
              <div>
                <label className="block text-xs text-gray-400 mb-1">Masking Strategy Override</label>
                <select
                  value={editingRule.maskingStrategy ?? ''}
                  onChange={e =>
                    updateEditing({
                      maskingStrategy: (e.target.value || null) as MaskingStrategy | null,
                    })
                  }
                  className="select-sm w-full text-sm"
                >
                  {STRATEGY_OPTIONS.map(o => (
                    <option key={String(o.value)} value={o.value ?? ''}>
                      {o.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Validation error */}
              {validationError && (
                <p className="text-xs text-red-400 bg-red-900/30 border border-red-700/50 rounded px-3 py-2">
                  ⚠ {validationError}
                </p>
              )}

              {/* Form actions */}
              <div className="flex items-center gap-2 pt-1">
                <button onClick={saveRule} className="btn-primary text-sm py-1.5 px-4">
                  Save Rule
                </button>
                <button onClick={cancelEdit} className="btn-secondary text-sm py-1.5 px-4">
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Info box */}
          <div className="bg-gray-800/50 border border-gray-700/50 rounded-lg px-4 py-3 text-xs text-gray-400 space-y-1">
            <p className="font-medium text-gray-300">About Custom Rules</p>
            <p>
              Field Names scan for <code className="font-mono text-sky-400">key = value</code> and{' '}
              <code className="font-mono text-sky-400">"key": "value"</code> patterns.
            </p>
            <p>
              Regex patterns are validated for syntax and tested against a backtracking probe before saving.
            </p>
            <p>
              Use a capture group <code className="font-mono text-sky-400">(…)</code> in your regex to mark
              exactly the secret span to redact.
            </p>
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-gray-700/60 flex justify-end shrink-0">
          <button onClick={onClose} className="btn-primary text-sm py-1.5 px-5">
            Done
          </button>
        </div>
      </div>
    </div>
  )
}

export default SettingsPanel
