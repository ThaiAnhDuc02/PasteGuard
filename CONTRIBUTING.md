# Contributing to PasteGuard

## Prerequisites

- Node.js ≥ 22 (24 LTS recommended)
- npm ≥ 10

```bash
npm install
```

---

## Development Workflow

```bash
npm run dev          # Vite dev server on http://localhost:5173
npm run test         # Run all tests once (Vitest)
npm run test:watch   # Vitest watch mode
npm run typecheck    # Strict TypeScript check (no emit)
npm run build        # Production bundle in dist/
npm run preview      # Serve dist/ with the production CSP
npm run check        # typecheck + lint + format check + tests
```

---

## Project Structure

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full directory layout and data-flow diagram.

---

## Adding a New Detector

1. Create `src/engine/detectors/myDetector.ts`.

2. Implement the `Detector` interface:

```typescript
import type { DetectionResult, Detector } from '../../types/detection'
import { offsetToLine } from '../../types/detection'

export class MyDetector implements Detector {
  readonly id = 'my-detector'
  enabled = true

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []
    // ... scan text and push DetectionResult objects ...
    return results
  }
}

export const myDetector = new MyDetector()
```

3. Register it in `src/engine/detectionEngine.ts`:
   - Import the singleton.
   - Add a call to `myDetector.detect(text)` inside `runDetection()`.
   - Add an `enableMyDetector` option to `DetectionEngineOptions` if needed.

4. Add a toggle button in `src/components/Toolbar/Toolbar.tsx` if the detector should be user-toggleable.

5. Write tests in `src/tests/detectors/myDetector.test.ts`. Cover:
   - Positive cases (detects the target pattern).
   - Negative cases (does not flag non-secrets).
   - Edge cases (empty string, unicode, very large input).
   - Security regression: verify the detected span is fully removed after redaction.

---

## Adding a New Masking Strategy

1. Add the new strategy name to the `MaskingStrategy` union in `src/types/redaction.ts`.
2. Implement the pure function in `src/engine/redaction/maskingStrategies.ts`.
3. Add a `case` to the `maskValue` dispatcher.
4. Add the option to the `STRATEGY_OPTIONS` array in `src/components/Toolbar/Toolbar.tsx`.
5. Write tests in `src/tests/redaction/maskingStrategies.test.ts`.

---

## Writing Tests

Tests live in `src/tests/` and use Vitest with `globals: true`.

```typescript
import { describe, it, expect, beforeEach } from 'vitest'
```

**Security regression tests** must check that no original secret value survives:

```typescript
it('fully removes the secret', () => {
  const secret = 'my-fake-secret-value'
  const text = `api_key=${secret}`
  const { detections } = runDetection(text)
  const { maskedText } = redactText(text, detections, { maskingOptions: FULL })
  expect(maskedText).not.toContain(secret)
})
```

Always use **fake credentials** in tests. Never commit real secrets.

---

## Code Style

- TypeScript strict mode is enforced (`strict: true`).
- Unused variables and parameters are errors (`noUnusedLocals`, `noUnusedParameters`).
- Format with Prettier: `npm run format`.
- Lint with ESLint: `npm run lint`.

---

## Pull Request Checklist

- [ ] `npm run check` passes (typecheck, lint, format, tests).
- [ ] `npm run test` passes with zero failures.
- [ ] New detector has unit tests covering positive, negative, and edge cases.
- [ ] Security regression test included for any new secret type.
- [ ] No `console.log` calls that could expose secret values.
- [ ] No new `localStorage` / `sessionStorage` writes.
- [ ] `DETECTION_RULES.md` updated if a new rule was added.

---

## Docker Build

```bash
docker compose up --build
```

The app is served on **http://localhost:8080**. The image build runs the test suite, so failing tests fail the build.

To build only the image:

```bash
docker build -t pasteguard:dev .
```
