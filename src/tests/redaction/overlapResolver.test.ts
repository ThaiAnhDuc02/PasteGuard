import { describe, it, expect } from 'vitest'
import { resolveOverlaps, hasOverlaps } from '../../engine/redaction/overlapResolver'
import type { DetectionResult } from '../../types/detection'

function r(start: number, end: number, confidence: DetectionResult['confidence'] = 'HIGH'): DetectionResult {
  return {
    start,
    end,
    category: 'PASSWORD',
    ruleId: `r-${start}-${end}`,
    ruleName: `Rule ${start}-${end}`,
    confidence,
    line: 1,
  }
}

describe('resolveOverlaps', () => {
  it('returns empty for empty input', () => {
    expect(resolveOverlaps([])).toHaveLength(0)
  })

  it('returns single item unchanged', () => {
    const result = resolveOverlaps([r(5, 10)])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(5)
    expect(result[0].end).toBe(10)
  })

  it('sorts non-overlapping ranges', () => {
    const result = resolveOverlaps([r(20, 30), r(0, 10), r(10, 20)])
    expect(result.map(x => x.start)).toEqual([0, 10, 20])
  })

  it('merges two overlapping ranges', () => {
    const result = resolveOverlaps([r(0, 10), r(5, 15)])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(0)
    expect(result[0].end).toBe(15)
  })

  it('merges a contained range', () => {
    const result = resolveOverlaps([r(0, 20), r(5, 10)])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(0)
    expect(result[0].end).toBe(20)
  })

  it('merges a chain of three overlapping ranges', () => {
    const result = resolveOverlaps([r(0, 10), r(8, 18), r(15, 25)])
    expect(result).toHaveLength(1)
    expect(result[0].start).toBe(0)
    expect(result[0].end).toBe(25)
  })

  it('keeps two adjacent non-overlapping ranges separate', () => {
    const result = resolveOverlaps([r(0, 10), r(10, 20)])
    expect(result).toHaveLength(2)
  })

  it('prefers higher confidence in merged result', () => {
    const low = r(0, 10, 'LOW')
    const high = r(5, 15, 'HIGH')
    const result = resolveOverlaps([low, high])
    expect(result[0].confidence).toBe('HIGH')
  })

  it('output has no overlaps', () => {
    const input = [r(0, 15), r(5, 10), r(12, 25), r(20, 30), r(35, 40)]
    const output = resolveOverlaps(input)
    expect(hasOverlaps(output)).toBe(false)
  })

  it('covers all original characters', () => {
    // Every char in [0,15) must appear in some output range
    const input = [r(0, 10), r(5, 15)]
    const output = resolveOverlaps(input)
    for (let i = 0; i < 15; i++) {
      expect(output.some(x => x.start <= i && i < x.end)).toBe(true)
    }
  })
})

describe('hasOverlaps', () => {
  it('returns false for empty list', () => {
    expect(hasOverlaps([])).toBe(false)
  })

  it('returns false for single item', () => {
    expect(hasOverlaps([r(0, 10)])).toBe(false)
  })

  it('returns false for non-overlapping', () => {
    expect(hasOverlaps([r(0, 5), r(5, 10), r(10, 20)])).toBe(false)
  })

  it('returns true for overlapping', () => {
    expect(hasOverlaps([r(0, 10), r(8, 15)])).toBe(true)
  })
})
