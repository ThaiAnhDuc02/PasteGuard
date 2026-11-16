import { describe, it, expect } from 'vitest'
import {
  applyFullMask,
  applyFixedMask,
  applyPartialMask,
  applyPlaceholder,
  maskValue,
  createPlaceholderCounter,
  createPlaceholderValueMap,
  type MaskContext,
} from '../../engine/redaction/maskingStrategies'
import type { MaskingOptions } from '../../types/redaction'

const DEFAULT: MaskingOptions = {
  strategy: 'FULL_MASK',
  leadingChars: 2,
  trailingChars: 4,
  maskChar: '*',
  fullMaskLength: 8,
}

describe('applyFullMask', () => {
  it('returns 8 stars by default', () => {
    expect(applyFullMask(DEFAULT)).toBe('********')
  })

  it('respects fullMaskLength', () => {
    expect(applyFullMask({ ...DEFAULT, fullMaskLength: 4 })).toBe('****')
  })

  it('respects maskChar', () => {
    expect(applyFullMask({ ...DEFAULT, maskChar: '#', fullMaskLength: 3 })).toBe('###')
  })
})

describe('applyFixedMask', () => {
  it('always returns exactly 5 stars', () => {
    expect(applyFixedMask(DEFAULT)).toBe('*****')
  })

  it('uses custom maskChar', () => {
    expect(applyFixedMask({ ...DEFAULT, maskChar: 'X' })).toBe('XXXXX')
  })
})

describe('applyPartialMask', () => {
  it('preserves leading and trailing chars', () => {
    const result = applyPartialMask('sk-mySecretKey1234', DEFAULT)
    expect(result.startsWith('sk')).toBe(true)
    expect(result.endsWith('1234')).toBe(true)
  })

  it('masks the middle', () => {
    const result = applyPartialMask('sk-mySecretKey1234', DEFAULT)
    const middle = result.slice(2, result.length - 4)
    expect(middle).toMatch(/^\*+$/)
  })

  it('falls back to FULL_MASK for short values', () => {
    // value.length <= lead + trail → full mask
    const result = applyPartialMask('abc', { ...DEFAULT, leadingChars: 2, trailingChars: 4 })
    expect(result).toBe('********')
  })

  it('masks at least 4 stars', () => {
    const result = applyPartialMask('abcdefghi', { ...DEFAULT, leadingChars: 2, trailingChars: 3 })
    const middle = result.slice(2, result.length - 3)
    expect(middle.length).toBeGreaterThanOrEqual(4)
  })
})

describe('applyPlaceholder', () => {
  it('generates a labeled placeholder', () => {
    const counter = createPlaceholderCounter()
    const valueMap = createPlaceholderValueMap()
    const result = applyPlaceholder('secret123', 'PASSWORD', counter, valueMap)
    expect(result).toBe('[PASSWORD_1]')
  })

  it('increments counter per category', () => {
    const counter = createPlaceholderCounter()
    const valueMap = createPlaceholderValueMap()
    applyPlaceholder('secret1', 'PASSWORD', counter, valueMap)
    const result = applyPlaceholder('secret2', 'PASSWORD', counter, valueMap)
    expect(result).toBe('[PASSWORD_2]')
  })

  it('returns same placeholder for repeated value', () => {
    const counter = createPlaceholderCounter()
    const valueMap = createPlaceholderValueMap()
    const r1 = applyPlaceholder('same-secret', 'API_KEY', counter, valueMap)
    const r2 = applyPlaceholder('same-secret', 'API_KEY', counter, valueMap)
    expect(r1).toBe(r2)
    expect(counter.get('API_KEY')).toBe(1) // only incremented once
  })

  it('uses separate counters for different categories', () => {
    const counter = createPlaceholderCounter()
    const valueMap = createPlaceholderValueMap()
    const p = applyPlaceholder('p1', 'PASSWORD', counter, valueMap)
    const a = applyPlaceholder('a1', 'API_KEY', counter, valueMap)
    expect(p).toBe('[PASSWORD_1]')
    expect(a).toBe('[API_KEY_1]')
  })
})

describe('maskValue dispatcher', () => {
  function ctx(strategy: MaskingOptions['strategy']): MaskContext {
    return {
      options: { ...DEFAULT, strategy },
      counter: createPlaceholderCounter(),
      valueMap: createPlaceholderValueMap(),
    }
  }

  it('dispatches FULL_MASK', () => {
    expect(maskValue('anySecret', 'PASSWORD', ctx('FULL_MASK'))).toBe('********')
  })

  it('dispatches FIXED_MASK', () => {
    expect(maskValue('anySecret', 'PASSWORD', ctx('FIXED_MASK'))).toBe('*****')
  })

  it('dispatches PLACEHOLDER', () => {
    expect(maskValue('anySecret', 'PASSWORD', ctx('PLACEHOLDER'))).toBe('[PASSWORD_1]')
  })

  it('dispatches PARTIAL_MASK', () => {
    const result = maskValue('sk-longSecretValue1234', 'API_KEY', ctx('PARTIAL_MASK'))
    expect(result).not.toBe('sk-longSecretValue1234')
    expect(result.startsWith('sk')).toBe(true)
  })

  it('handles empty value safely', () => {
    expect(() => maskValue('', 'PASSWORD', ctx('FULL_MASK'))).not.toThrow()
  })
})
