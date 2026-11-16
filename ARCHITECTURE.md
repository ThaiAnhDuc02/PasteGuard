# PasteGuard — Architecture

## Overview

PasteGuard is a pure-browser React application. It has no backend, no database, and no external API calls. The entire detect-and-redact pipeline runs in the browser's JavaScript engine.

```
┌─────────────────────────────────────────────────────┐
│                     Browser Tab                     │
│                                                     │
│  ┌──────────┐    ┌────────────────┐    ┌─────────┐  │
│  │ Monaco   │───▶│ Detection      │───▶│Redaction│  │
│  │ Editor   │    │ Engine         │    │ Engine  │  │
│  │ (input)  │    │                │    │         │  │
│  └──────────┘    │ keyBased       │    │ FULL    │  │
│                  │ token          │    │ FIXED   │  │
│  ┌──────────┐    │ connectionStr  │    │ PARTIAL │  │
│  │ Monaco   │◀───│ privateKey     │    │ PLACEHOLDER│
│  │ Editor   │    │ custom         │    └─────────┘  │
│  │ (output) │    └────────────────┘                 │
│  └──────────┘                                       │
└─────────────────────────────────────────────────────┘
```

---

## Directory Structure

```
src/
  engine/                    ← Pure TypeScript, zero React dependency
    pipeline.ts              ← detect → redact → verify (shared by worker + fallback)
    pipeline.worker.ts       ← Web Worker entry (runs pipeline off the main thread)
    detectors/
      keyBasedDetector.ts    ← Generic key/value scanner + suffix-word keyword match + entropy fallback
      tokenDetector.ts       ← Structural token patterns (JWT, AWS, GitHub, …)
      connectionStringDetector.ts  ← URL-scheme and JDBC credential extraction
      privateKeyDetector.ts  ← PEM block detection
      customDetector.ts      ← User-defined field names and regex rules
    redaction/
      maskingStrategies.ts   ← FULL / FIXED / PARTIAL / PLACEHOLDER functions
      overlapResolver.ts     ← Merge overlapping DetectionResult ranges
      redactionEngine.ts     ← Single-pass string substitution
    parser/
      formatDetector.ts      ← Heuristic format sniffing (JSON / YAML / SQL / …)

  monaco/
    setup.ts                 ← Local Monaco bundle + workers (no CDN), slim language set

  components/
    Header/                  ← Logo, description, local-processing badge
    Toolbar/                 ← Format selector, strategy selector, detector toggles
    EditorPanel/
      InputPanel.tsx         ← Monaco input + MASK SECRETS button
      OutputPanel.tsx        ← Read-only Monaco output + copy/download
    DetectionSummary/        ← Counts by category, low-confidence warning
    DetectionList/           ← Paginated table: category, line, rule, confidence
    SettingsPanel/           ← Custom rule editor modal

  hooks/
    useRedaction.ts          ← Orchestrates detection + redaction, owns all state
    useEditor.ts             ← Monaco refs, format selection, input text

  types/
    detection.ts             ← DetectionResult, Detector interface, SecretCategory
    redaction.ts             ← MaskingStrategy, MaskingOptions, RedactionResult
    rules.ts                 ← CustomRule, validateRegexPattern

  utils/
    clipboard.ts             ← Clipboard API + textarea fallback
    download.ts              ← Blob URL file download
    textUtils.ts             ← truncate, formatBytes, countLines, plural

  tests/
    detectors/               ← Unit tests per detector
    redaction/               ← Unit tests for masking + overlap + engine
    integration/             ← End-to-end pipeline tests

  App.tsx                    ← Root component, wires hooks to components
  main.tsx                   ← ReactDOM mount point
```

---

## Data Flow

```
User types / pastes text
        │
        ▼
  useEditor.setInputText()
        │  (auto-detects format)
        ▼
  User clicks MASK SECRETS
        │
        ▼
  useRedaction.maskSecrets(text)
        │
        ├─▶ runDetection(text, options)
        │       ├─▶ privateKeyDetector.detect(text)
        │       ├─▶ tokenDetector.detect(text)
        │       ├─▶ connectionStringDetector.detect(text)
        │       ├─▶ keyBasedDetector.detect(text)
        │       └─▶ customDetector.detect(text)
        │       → sort + deduplicate → DetectionResult[]
        │
        ├─▶ redactText(text, detections, { maskingOptions })
        │       ├─▶ resolveOverlaps(detections)
        │       └─▶ single forward pass → maskedText
        │
        └─▶ setState({ maskedText, detections, summary })
                │
                ▼
          OutputPanel renders maskedText in Monaco (read-only)
          DetectionSummary renders counts
          DetectionList renders paginated findings
```

---

## Key Design Decisions

### Offset-based redaction
The redaction engine works on character offsets into the original string. It never parses or serializes the text. A single forward pass copies unchanged characters and substitutes detected spans. This guarantees byte-identical preservation of everything outside the secret spans.

### Detector independence
Each detector is a class implementing `Detector { detect(text): DetectionResult[] }`. The orchestrator calls them in priority order and deduplicates by `[start, end]` key. Detectors are entirely stateless during a scan.

### Overlap resolution before redaction
The `overlapResolver` merges overlapping ranges into a single non-overlapping, sorted list before the redaction engine sees it. This prevents double-substitution bugs and ensures no secret character leaks between adjacent replacements.

### No server round-trips
`@monaco-editor/react` downloads Monaco from cdn.jsdelivr.net by default. `src/monaco/setup.ts` bundles Monaco from node_modules instead and calls `loader.config({ monaco })`; only the languages the app maps formats to are registered, and the editor/JSON workers are same-origin files. The production CSP (`script-src 'self'`, `connect-src 'self'`) would block any other host, and `npm run preview` serves the build with the same CSP so regressions show up locally.

### Web Worker pipeline
`useRedaction` posts the text to `src/engine/pipeline.worker.ts`, which runs `runPipeline()` (detect → redact → verify) off the main thread. A 15 s hard timeout terminates the worker if a run hangs (e.g. a pathological custom regex); a fresh worker is created on the next run. A monotonic run id discards stale replies. Without Worker support, the same `runPipeline()` runs synchronously.

### Verification pass
`runPipeline()` re-scans the masked output. Remaining HIGH/MEDIUM detections that are not masks themselves are returned as `residual`, and the UI shows a warning banner.

### Linear-time detection
- Line numbers come from a cached line-start index (binary search), not a rescan from offset 0 per hit (previously ~110 s for 20 000 hits in 1 MB; now < 0.1 s).
- The key-based detector is one generic key/value scan plus O(1) keyword lookups, instead of two regex scans per keyword.
- Regexes are written so each match is bounded: separators live inside the value regex, and no two whitespace quantifiers overlap.
- `regression.test.ts` enforces time budgets on 1 MB and adversarial inputs.
