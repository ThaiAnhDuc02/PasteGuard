import { describe, it, expect, beforeEach } from 'vitest'
import { CustomDetector } from '../../engine/detectors/customDetector'
import type { CustomRule } from '../../types/rules'

function makeRule(overrides: Partial<CustomRule> = {}): CustomRule {
  return {
    id: 'test-rule-1',
    name: 'Test Rule',
    fieldNames: [],
    regexPattern: '',
    category: 'CUSTOM',
    maskingStrategy: null,
    confidence: 'HIGH',
    enabled: true,
    ...overrides,
  }
}

describe('CustomDetector', () => {
  let detector: CustomDetector

  beforeEach(() => {
    detector = new CustomDetector()
  })

  describe('field-name scanning', () => {
    it('detects custom field name in JSON', () => {
      const rule = makeRule({ fieldNames: ['mytoken'] })
      detector.setRules([rule])
      const text = `{"mytoken":"custom-secret-value-123"}`
      const results = detector.detect(text)
      expect(results.some(r => r.isCustom)).toBe(true)
      expect(results.some(r => text.slice(r.start, r.end) === 'custom-secret-value-123')).toBe(true)
    })

    it('detects multiple field names', () => {
      const rule = makeRule({ fieldNames: ['internalKey', 'internal_key'] })
      detector.setRules([rule])
      const text = `internalKey=secret-a\ninternal_key: "secret-b"`
      const results = detector.detect(text)
      expect(results.length).toBeGreaterThanOrEqual(2)
    })

    it('skips disabled rules', () => {
      const rule = makeRule({ fieldNames: ['mytoken'], enabled: false })
      detector.setRules([rule])
      const results = detector.detect(`{"mytoken":"should-not-detect"}`)
      expect(results).toHaveLength(0)
    })

    it('does not flag ignored values (true, null, etc.)', () => {
      const rule = makeRule({ fieldNames: ['flag'] })
      detector.setRules([rule])
      expect(detector.detect(`{"flag":true}`)).toHaveLength(0)
      expect(detector.detect(`{"flag":null}`)).toHaveLength(0)
    })
  })

  describe('regex pattern scanning', () => {
    it('detects via regex pattern', () => {
      const rule = makeRule({ regexPattern: 'myapp_[A-Za-z0-9]{8,}' })
      detector.setRules([rule])
      const text = `token=myapp_abcdef1234567`
      const results = detector.detect(text)
      expect(results.some(r => r.isCustom)).toBe(true)
    })

    it('uses capture group for secret span', () => {
      const rule = makeRule({ regexPattern: 'token=([A-Za-z0-9]{10,})' })
      detector.setRules([rule])
      const text = `token=secretvalue123`
      const results = detector.detect(text)
      expect(results).toHaveLength(1)
      expect(text.slice(results[0].start, results[0].end)).toBe('secretvalue123')
    })

    it('rejects invalid regex patterns silently', () => {
      const rule = makeRule({ regexPattern: '[invalid(' })
      detector.setRules([rule])
      // Should not throw, should return no results
      expect(() => detector.detect('some text')).not.toThrow()
    })

    it('returns no results for empty text', () => {
      const rule = makeRule({ regexPattern: 'myapp_\\w+' })
      detector.setRules([rule])
      expect(detector.detect('')).toHaveLength(0)
    })
  })

  describe('rule management', () => {
    it('replaces rules on setRules', () => {
      detector.setRules([makeRule({ fieldNames: ['a'] })])
      detector.setRules([makeRule({ fieldNames: ['b'] })])
      const results = detector.detect(`{"a":"value123"}`)
      expect(results).toHaveLength(0)
    })

    it('returns copy of rules from getRules', () => {
      const rules = [makeRule()]
      detector.setRules(rules)
      const got = detector.getRules()
      expect(got).toHaveLength(1)
      got.pop()
      expect(detector.getRules()).toHaveLength(1) // original unaffected
    })
  })
})
