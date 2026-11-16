import { useState } from 'react'
import Header from './components/Header/Header'
import Toolbar from './components/Toolbar/Toolbar'
import InputPanel from './components/EditorPanel/InputPanel'
import OutputPanel from './components/EditorPanel/OutputPanel'
import DetectionSummary from './components/DetectionSummary/DetectionSummary'
import DetectionList from './components/DetectionList/DetectionList'
import SettingsPanel from './components/SettingsPanel/SettingsPanel'
import { useRedaction } from './hooks/useRedaction'
import { useEditor } from './hooks/useEditor'

function App() {
  const [settingsOpen, setSettingsOpen] = useState(false)

  const [editorState, editorControls] = useEditor()
  const [redactionState, redactionControls] = useRedaction()

  const handleMaskSecrets = () => {
    redactionControls.maskSecrets(editorState.inputText)
  }

  const handleClearAll = () => {
    editorControls.clearInput()
    redactionControls.reset()
  }

  const handleInputChange = (text: string) => {
    editorControls.setInputText(text)
    // Reset output when input changes
    if (redactionState.hasRun) {
      redactionControls.reset()
    }
  }

  const effectiveFormat =
    editorState.selectedFormat === 'AUTO' ? editorState.detectedFormat : editorState.selectedFormat

  return (
    <div className="flex flex-col h-screen bg-gray-950 text-gray-100 overflow-hidden">
      {/* ── Header ── */}
      <Header onSettingsClick={() => setSettingsOpen(true)} />

      {/* ── Toolbar ── */}
      <Toolbar
        selectedFormat={editorState.selectedFormat}
        detectedFormat={editorState.detectedFormat}
        maskingStrategy={redactionControls.maskingOptions.strategy}
        engineOptions={redactionControls.engineOptions}
        onFormatChange={editorControls.setSelectedFormat}
        onStrategyChange={strategy => redactionControls.setMaskingOptions({ strategy })}
        onEngineOptionsChange={redactionControls.setEngineOptions}
        onClear={handleClearAll}
        onCustomRulesClick={() => setSettingsOpen(true)}
        inputLength={editorState.inputText.length}
      />

      {/* ── Detection summary (shown after run) ── */}
      {redactionState.hasRun && (
        <DetectionSummary summary={redactionState.summary} hasRun={redactionState.hasRun} />
      )}

      {/* ── Second-pass warning: something still looks like a secret ── */}
      {redactionState.hasRun && redactionState.residualCount > 0 && (
        <div
          role="alert"
          className="px-4 py-2 bg-amber-900/40 border-b border-amber-700/50 text-sm text-amber-200 flex items-center gap-2"
        >
          <span>⚠</span>
          <span>
            Verification re-scan still found {redactionState.residualCount} possible secret
            {redactionState.residualCount !== 1 ? 's' : ''} in the masked output. Review it before copying.
          </span>
        </div>
      )}

      {/* ── Error banner ── */}
      {redactionState.error && (
        <div className="px-4 py-2 bg-red-900/40 border-b border-red-700/50 text-sm text-red-300 flex items-center gap-2">
          <span>⚠</span>
          <span>{redactionState.error}</span>
        </div>
      )}

      {/* ── Main workspace ── */}
      <main className="flex-1 min-h-0 flex flex-col lg:flex-row gap-0">
        {/* Left — Input */}
        <div className="flex-1 min-h-0 min-w-0 flex flex-col border-r border-gray-700/60">
          <InputPanel
            value={editorState.inputText}
            language={editorState.monacoLanguage}
            onChange={handleInputChange}
            onClear={handleClearAll}
            onMaskSecrets={handleMaskSecrets}
            isProcessing={redactionState.isProcessing}
            editorRef={editorControls.editorRef}
          />
        </div>

        {/* Right — Output */}
        <div className="flex-1 min-h-0 min-w-0 flex flex-col">
          <OutputPanel
            value={redactionState.maskedText}
            language={editorState.monacoLanguage}
            hasRun={redactionState.hasRun}
            redactedCount={redactionState.summary.total}
            format={effectiveFormat}
            outputEditorRef={editorControls.outputEditorRef}
          />
        </div>
      </main>

      {/* ── Detection list (shown below editors when results exist) ── */}
      {redactionState.hasRun && redactionState.detections.length > 0 && (
        <DetectionList detections={redactionState.detections} hasRun={redactionState.hasRun} />
      )}

      {/* ── Settings / Custom Rules modal ── */}
      <SettingsPanel
        isOpen={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        customRules={redactionControls.customRules}
        onRulesChange={redactionControls.setCustomRules}
      />
    </div>
  )
}

export default App
