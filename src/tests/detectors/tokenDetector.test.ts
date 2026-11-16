import { describe, it, expect, beforeEach } from 'vitest'
import { TokenDetector } from '../../engine/detectors/tokenDetector'
import { FAKE } from '../fixtures'

describe('TokenDetector', () => {
  let detector: TokenDetector

  beforeEach(() => {
    detector = new TokenDetector()
  })

  // ── JWT ──────────────────────────────────────────────────────────────────

  describe('JWT tokens', () => {
    const fakeJwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
      '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0' +
      '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

    it('detects a JWT token', () => {
      const results = detector.detect(`Authorization: Bearer ${fakeJwt}`)
      expect(results.some(r => r.category === 'JWT' || r.category === 'BEARER_TOKEN')).toBe(true)
    })

    it('detects standalone JWT', () => {
      const text = `token=${fakeJwt}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'JWT')).toBe(true)
    })

    it('captures the correct JWT span', () => {
      const results = detector.detect(fakeJwt)
      const jwt = results.find(r => r.category === 'JWT')
      expect(jwt).toBeDefined()
      expect(fakeJwt.slice(jwt!.start, jwt!.end)).toBe(fakeJwt)
    })
  })

  // ── AWS ──────────────────────────────────────────────────────────────────

  describe('AWS credentials', () => {
    it('detects AWS Access Key ID', () => {
      const text = `aws_access_key_id = ${FAKE.awsAccessKeyId}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'AWS_CREDENTIAL')).toBe(true)
    })

    it('captures the full AWS key', () => {
      const text = FAKE.awsAccessKeyId
      const results = detector.detect(text)
      const aws = results.find(r => r.category === 'AWS_CREDENTIAL')
      expect(aws).toBeDefined()
      expect(text.slice(aws!.start, aws!.end)).toBe(FAKE.awsAccessKeyId)
    })

    it('detects ASIA prefix (STS credentials)', () => {
      const text = `ASIAIOSFODNN7EXAMPLE`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'AWS_CREDENTIAL')).toBe(true)
    })
  })

  // ── GitHub tokens ─────────────────────────────────────────────────────────

  describe('GitHub tokens', () => {
    it('detects classic PAT', () => {
      const text = `GITHUB_TOKEN=${FAKE.githubPat}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'GITHUB_TOKEN')).toBe(true)
    })

    it('detects GitHub OAuth token', () => {
      const text = `token=gho_16C7e42F292c6912E7710c838347Ae178B4a`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'GITHUB_TOKEN')).toBe(true)
    })
  })

  // ── Bearer / Basic ────────────────────────────────────────────────────────

  describe('Authorization headers', () => {
    it('detects Bearer token in HTTP header', () => {
      const text = `Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.some-payload.some-sig`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'BEARER_TOKEN')).toBe(true)
    })

    it('detects Basic auth header', () => {
      const text = `Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'BASIC_AUTH')).toBe(true)
    })

    it('captures only the token value, not the keyword', () => {
      const token = 'dXNlcm5hbWU6cGFzc3dvcmQ='
      const text = `Authorization: Basic ${token}`
      const results = detector.detect(text)
      const basic = results.find(r => r.category === 'BASIC_AUTH')
      expect(basic).toBeDefined()
      expect(text.slice(basic!.start, basic!.end)).toBe(token)
    })
  })

  // ── Vendor-specific API keys ───────────────────────────────────────────────

  describe('vendor API keys', () => {
    it('detects OpenAI key', () => {
      const text = `OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })

    it('detects Stripe live key', () => {
      const text = FAKE.stripeLive
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })

    it('detects Slack token', () => {
      const text = `SLACK_TOKEN=${FAKE.slackBot}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'TOKEN')).toBe(true)
    })
  })

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('returns empty for empty string', () => {
      expect(detector.detect('')).toHaveLength(0)
    })

    it('does not detect very short strings as tokens', () => {
      const results = detector.detect('abc123')
      expect(results.filter(r => r.category === 'JWT')).toHaveLength(0)
    })

    it('handles multiple tokens in one string', () => {
      const jwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
      const text = `token1=${jwt} key=${FAKE.awsAccessKeyId}`
      const results = detector.detect(text)
      const categories = results.map(r => r.category)
      expect(categories).toContain('JWT')
      expect(categories).toContain('AWS_CREDENTIAL')
    })
  })
})
