/**
 * Custom Rule Detector
 *
 * Runs user-defined detection rules.
 * Each rule can specify field names (matched with the same key/value scanner
 * as the built-in key-based detector, so JSON, YAML, ENV, headers, … all work)
 * and/or a regex pattern applied to the full text.
 *
 * Field-name matching is suffix-based on words, like the built-in keywords:
 * a rule for `my_token` matches `MY_TOKEN`, `myToken`, `"my-token"` and
 * `APP_MY_TOKEN`.
 *
 * Security:
 *   - Patterns are validated before being used (see validateRegexPattern).
 *   - Execution uses a recreated RegExp per call to reset lastIndex safely.
 *   - Pattern is capped at 10 000 chars to avoid memory abuse.
 *   - The whole pipeline runs in a Web Worker with a hard timeout (see
 *     useRedaction), so a pathological pattern cannot freeze the page.
 */

import type { DetectionResult, Detector } from '../../types/detection'
import { offsetToLine } from '../../types/detection'
import type { CustomRule } from '../../types/rules'
import { validateRegexPattern } from '../../types/rules'
import { scanKeyValues, keySuffixes, normaliseKey, isNonSecretValue } from './keyBasedDetector'

export class CustomDetector implements Detector {
  readonly id = 'custom'
  enabled = true

  private rules: CustomRule[] = []

  setRules(rules: CustomRule[]): void {
    this.rules = rules.filter(r => r.enabled)
  }

  getRules(): CustomRule[] {
    return [...this.rules]
  }

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []
    if (!text || this.rules.length === 0) return results

    // ── field-name scanning (one scan shared by all rules) ──────────────────
    const fieldRules = this.rules
      .map(rule => ({
        rule,
        fields: new Map(
          rule.fieldNames
            .map(f => f.trim())
            .filter(Boolean)
            .map(f => [normaliseKey(f), f] as const),
        ),
      }))
      .filter(r => r.fields.size > 0)

    if (fieldRules.length > 0) {
      for (const kv of scanKeyValues(text)) {
        if (isNonSecretValue(kv.value, kv.quoted)) continue
        const suffixes = keySuffixes(kv.key)
        for (const { rule, fields } of fieldRules) {
          const matched = suffixes.find(s => fields.has(s))
          if (matched === undefined) continue
          const fieldName = fields.get(matched)!
          results.push({
            start: kv.valueStart,
            end: kv.valueEnd,
            category: rule.category,
            ruleId: `custom:${rule.id}:field:${matched}`,
            ruleName: `${rule.name} (field: ${fieldName})`,
            confidence: rule.confidence,
            line: offsetToLine(text, kv.valueStart),
            isCustom: true,
            maskingStrategy: rule.maskingStrategy ?? undefined,
          })
        }
      }
    }

    // ── regex pattern scanning ──────────────────────────────────────────────
    for (const rule of this.rules) {
      if (!rule.regexPattern) continue
      const patternStr = rule.regexPattern.slice(0, 10000)
      const validation = validateRegexPattern(patternStr)
      if (!validation.valid) continue

      try {
        const re = new RegExp(patternStr, 'gi')
        let match: RegExpExecArray | null

        while ((match = re.exec(text)) !== null) {
          // If the pattern has a capture group, use that as the secret span;
          // otherwise use the entire match.
          const secret = match[1] !== undefined ? match[1] : match[0]
          if (!secret || secret.length < 3) {
            if (match[0].length === 0) re.lastIndex++
            continue
          }

          const secretStart = match.index + (match[1] !== undefined ? match[0].indexOf(match[1]) : 0)
          const secretEnd = secretStart + secret.length

          results.push({
            start: secretStart,
            end: secretEnd,
            category: rule.category,
            ruleId: `custom:${rule.id}:pattern`,
            ruleName: `${rule.name} (pattern)`,
            confidence: rule.confidence,
            line: offsetToLine(text, secretStart),
            isCustom: true,
            maskingStrategy: rule.maskingStrategy ?? undefined,
          })

          if (match[0].length === 0) re.lastIndex++
        }
      } catch {
        // Swallow runtime errors from user patterns; validation should catch most
      }
    }

    return results
  }
}

export const customDetector = new CustomDetector()
