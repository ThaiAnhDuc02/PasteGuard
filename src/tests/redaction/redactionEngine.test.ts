import { describe, it, expect } from 'vitest'
import { redactText } from '../../engine/redaction/redactionEngine'
import type { DetectionResult } from '../../types/detection'
import type { MaskingOptions } from '../../types/redaction'
import { FAKE } from '../fixtures'

function det(
  start: number,
  end: number,
  category: DetectionResult['category'] = 'PASSWORD',
): DetectionResult {
  return {
    start,
    end,
    category,
    ruleId: 'test',
    ruleName: 'Test Rule',
    confidence: 'HIGH',
    line: 1,
  }
}

const FULL: MaskingOptions = { strategy: 'FULL_MASK', maskChar: '*', fullMaskLength: 8 }
const FIXED: MaskingOptions = { strategy: 'FIXED_MASK', maskChar: '*' }
const PARTIAL: MaskingOptions = {
  strategy: 'PARTIAL_MASK',
  leadingChars: 2,
  trailingChars: 4,
  maskChar: '*',
  fullMaskLength: 8,
}
const PLACEHOLDER: MaskingOptions = { strategy: 'PLACEHOLDER', maskChar: '*', fullMaskLength: 8 }

describe('redactText', () => {
  describe('FULL_MASK strategy', () => {
    it('replaces a single secret with ********', () => {
      const text = 'password=supersecret'
      const { maskedText } = redactText(text, [det(9, 20)], { maskingOptions: FULL })
      expect(maskedText).toBe('password=********')
    })

    it('preserves text before and after the secret', () => {
      const text = 'prefix--secret--suffix'
      const { maskedText } = redactText(text, [det(8, 14)], { maskingOptions: FULL })
      expect(maskedText.startsWith('prefix--')).toBe(true)
      expect(maskedText.endsWith('--suffix')).toBe(true)
    })

    it('returns original text when no detections', () => {
      const text = 'no secrets here'
      const { maskedText } = redactText(text, [], { maskingOptions: FULL })
      expect(maskedText).toBe(text)
    })

    it('returns 0 redactedCount when no detections', () => {
      const { redactedCount } = redactText('clean text', [], { maskingOptions: FULL })
      expect(redactedCount).toBe(0)
    })
  })

  describe('FIXED_MASK strategy', () => {
    it('replaces with exactly *****', () => {
      const text = 'token=abcdefgh'
      const { maskedText } = redactText(text, [det(6, 14)], { maskingOptions: FIXED })
      expect(maskedText).toBe('token=*****')
    })
  })

  describe('PARTIAL_MASK strategy', () => {
    it('preserves leading and trailing characters', () => {
      const text = 'key=sk-myLongSecretValue1234'
      const { maskedText } = redactText(text, [det(4, 28, 'API_KEY')], { maskingOptions: PARTIAL })
      expect(maskedText.startsWith('key=sk')).toBe(true)
      expect(maskedText.endsWith('1234')).toBe(true)
    })

    it('never partially reveals passwords', () => {
      const text = 'password=sk-myLongSecretValue1234'
      const { maskedText } = redactText(text, [det(9, 33, 'PASSWORD')], { maskingOptions: PARTIAL })
      expect(maskedText).toBe('password=********')
    })

    it('fully masks short values even for API keys', () => {
      const text = 'key=Hunter2!!xyz'
      const { maskedText } = redactText(text, [det(4, 16, 'API_KEY')], { maskingOptions: PARTIAL })
      expect(maskedText).toBe('key=********')
    })

    it('applies a custom rule strategy override', () => {
      const text = 'x=topsecretvalue'
      const d = { ...det(2, 16, 'CUSTOM'), maskingStrategy: 'PLACEHOLDER' as const }
      const { maskedText } = redactText(text, [d], { maskingOptions: PARTIAL })
      expect(maskedText).toBe('x=[SECRET_1]')
    })
  })

  describe('PLACEHOLDER strategy', () => {
    it('replaces with [CATEGORY_N]', () => {
      const text = 'password=supersecret'
      const { maskedText } = redactText(text, [det(9, 20, 'PASSWORD')], { maskingOptions: PLACEHOLDER })
      expect(maskedText).toBe('password=[PASSWORD_1]')
    })

    it('gives same placeholder to repeated secret value', () => {
      const text = 'a=sameSecret b=sameSecret'
      const detections = [det(2, 12), det(15, 25)]
      const { maskedText } = redactText(text, detections, { maskingOptions: PLACEHOLDER })
      const parts = maskedText.split(' ')
      const label1 = parts[0].split('=')[1]
      const label2 = parts[1].split('=')[1]
      expect(label1).toBe(label2)
    })

    it('gives different placeholders to different secrets', () => {
      const text = 'a=secretOne b=secretTwo'
      const detections = [det(2, 11), det(14, 23)]
      const { maskedText } = redactText(text, detections, { maskingOptions: PLACEHOLDER })
      const labels = maskedText.match(/\[PASSWORD_\d+\]/g) ?? []
      expect(new Set(labels).size).toBe(2)
    })
  })

  describe('formatting preservation', () => {
    it('preserves JSON structure', () => {
      const text = '{\n  "password": "mySecret"\n}'
      // Secret value span: "mySecret" (without quotes)
      const idx = text.indexOf('mySecret')
      const { maskedText } = redactText(text, [det(idx, idx + 8)], { maskingOptions: FULL })
      expect(maskedText).toContain('"password": "')
      expect(maskedText).toContain('"')
      expect(maskedText).not.toContain('mySecret')
    })

    it('preserves newlines around secret', () => {
      const text = 'line1\npassword=secret\nline3'
      const idx = text.indexOf('secret')
      const { maskedText } = redactText(text, [det(idx, idx + 6)], { maskingOptions: FULL })
      const lines = maskedText.split('\n')
      expect(lines).toHaveLength(3)
      expect(lines[0]).toBe('line1')
      expect(lines[2]).toBe('line3')
    })

    it('preserves whitespace and indentation', () => {
      const text = '    password:   "secretval"'
      const idx = text.indexOf('secretval')
      const { maskedText } = redactText(text, [det(idx, idx + 9)], { maskingOptions: FULL })
      expect(maskedText.startsWith('    password:   "')).toBe(true)
    })
  })

  describe('overlapping detections', () => {
    it('handles overlapping results without corrupting text', () => {
      const text = 'prefix-secretvalue-suffix'
      // Two overlapping detections over the same span
      const d1 = det(7, 18)
      const d2 = det(10, 20)
      const { maskedText } = redactText(text, [d1, d2], { maskingOptions: FULL })
      expect(maskedText).not.toContain('secretvalue')
      expect(maskedText.startsWith('prefix-')).toBe(true)
    })
  })

  describe('edge cases', () => {
    it('handles empty text', () => {
      const { maskedText, redactedCount } = redactText('', [], { maskingOptions: FULL })
      expect(maskedText).toBe('')
      expect(redactedCount).toBe(0)
    })

    it('handles detection at start of string', () => {
      const text = 'secretvalue rest of text'
      const { maskedText } = redactText(text, [det(0, 11)], { maskingOptions: FULL })
      expect(maskedText.startsWith('********')).toBe(true)
      expect(maskedText.endsWith(' rest of text')).toBe(true)
    })

    it('handles detection at end of string', () => {
      const text = 'prefix: secretvalue'
      const { maskedText } = redactText(text, [det(8, 19)], { maskingOptions: FULL })
      expect(maskedText).toBe('prefix: ********')
    })

    it('handles detection spanning entire string', () => {
      const text = 'entiresecret'
      const { maskedText } = redactText(text, [det(0, 12)], { maskingOptions: FULL })
      expect(maskedText).toBe('********')
    })

    it('handles unicode text', () => {
      // Secret is ASCII; surrounding text has unicode
      const text = '日本語テキスト password=secret123 more日本語'
      const idx = text.indexOf('secret123')
      const { maskedText } = redactText(text, [det(idx, idx + 9)], { maskingOptions: FULL })
      expect(maskedText).toContain('日本語テキスト')
      expect(maskedText).not.toContain('secret123')
    })

    it('handles multiple non-overlapping detections in one pass', () => {
      const text = 'a=sec1 b=sec2 c=sec3'
      const detections = [det(2, 6), det(9, 13), det(16, 20)]
      const { maskedText, redactedCount } = redactText(text, detections, { maskingOptions: FULL })
      expect(redactedCount).toBe(3)
      expect(maskedText).not.toContain('sec1')
      expect(maskedText).not.toContain('sec2')
      expect(maskedText).not.toContain('sec3')
      expect(maskedText).toContain('a=')
      expect(maskedText).toContain('b=')
      expect(maskedText).toContain('c=')
    })

    it('placeholderMap contains no original secret values', () => {
      const text = 'password=mysecretvalue'
      const idx = text.indexOf('mysecretvalue')
      const { placeholderMap } = redactText(text, [det(idx, idx + 13)], { maskingOptions: PLACEHOLDER })
      for (const key of placeholderMap.keys()) {
        expect(key).not.toContain('mysecretvalue')
      }
    })
  })

  describe('security regression — secret removal', () => {
    const secrets = [
      'supersecret',
      FAKE.githubPat,
      FAKE.awsAccessKeyId,
      'eyJhbGciOiJIUzI1NiJ9.payload.sig',
      'mongodb_password_xyz',
    ]

    for (const secret of secrets) {
      it(`fully removes "${secret.slice(0, 12)}…" from output`, () => {
        const text = `key=${secret}`
        const idx = text.indexOf(secret)
        const { maskedText } = redactText(text, [det(idx, idx + secret.length)], { maskingOptions: FULL })
        expect(maskedText).not.toContain(secret)
      })
    }
  })
})
