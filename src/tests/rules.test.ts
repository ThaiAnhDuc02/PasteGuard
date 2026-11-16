import { describe, it, expect } from 'vitest'
import { validateRegexPattern } from '../types/rules'

describe('validateRegexPattern', () => {
  it('accepts normal patterns', () => {
    for (const p of ['myapp_[A-Za-z0-9]{8,}', 'token=([A-Za-z0-9]{10,})', '(?:foo|bar)_\\d+', '']) {
      expect(validateRegexPattern(p).valid).toBe(true)
    }
  })

  it('rejects syntax errors', () => {
    expect(validateRegexPattern('[invalid(').valid).toBe(false)
  })

  it('rejects nested quantifiers', () => {
    for (const p of ['(a+)+$', '(\\w*)*x', '(a|aa)+$', '(?:.*){2,}z', '([a-z]+){1,}!']) {
      expect(validateRegexPattern(p).valid, p).toBe(false)
    }
  })

  it('rejects overly long patterns', () => {
    expect(validateRegexPattern('a'.repeat(10_001)).valid).toBe(false)
  })
})
