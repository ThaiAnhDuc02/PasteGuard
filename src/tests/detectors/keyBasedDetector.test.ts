import { describe, it, expect, beforeEach } from 'vitest'
import { KeyBasedDetector } from '../../engine/detectors/keyBasedDetector'

describe('KeyBasedDetector', () => {
  let detector: KeyBasedDetector

  beforeEach(() => {
    detector = new KeyBasedDetector()
  })

  // ── JSON ──────────────────────────────────────────────────────────────────

  describe('JSON key-value', () => {
    it('detects password in JSON', () => {
      const text = `{"username":"admin","password":"s3cr3t!Pass"}`
      const results = detector.detect(text)
      const pw = results.find(r => r.category === 'PASSWORD')
      expect(pw).toBeDefined()
      expect(text.slice(pw!.start, pw!.end)).toBe('s3cr3t!Pass')
    })

    it('detects api_key in JSON', () => {
      const text = `{"api_key":"sk-example123456789"}`
      const results = detector.detect(text)
      const ak = results.find(r => r.category === 'API_KEY')
      expect(ak).toBeDefined()
      expect(text.slice(ak!.start, ak!.end)).toBe('sk-example123456789')
    })

    it('detects access_token in JSON', () => {
      const text = `{"access_token":"eyJfaketoken123456"}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'TOKEN')).toBe(true)
    })

    it('detects client_secret in JSON', () => {
      const text = `{"client_secret":"oauth-secret-value-xyz"}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'OAUTH_SECRET')).toBe(true)
    })

    it('detects nested JSON password', () => {
      const text = `{"db":{"password":"dbP@ssword99"}}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'PASSWORD')).toBe(true)
    })
  })

  // ── ENV / shell ────────────────────────────────────────────────────────────

  describe('ENV variables', () => {
    it('detects PASSWORD= in .env', () => {
      const text = `DATABASE_URL=postgres://localhost/db\nDATABASE_PASSWORD=supersecret\nPORT=5432`
      const results = detector.detect(text)
      const pw = results.find(r => r.category === 'PASSWORD')
      expect(pw).toBeDefined()
      expect(text.slice(pw!.start, pw!.end)).toBe('supersecret')
    })

    it('detects API_KEY= in .env', () => {
      const text = `API_KEY=abc123defg456hijklmno`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })

    it('detects export SECRET= in shell', () => {
      const text = `export MY_SERVICE_SECRET=my-very-secret-value`
      const results = detector.detect(text)
      const hit = results.find(r => r.category === 'GENERIC_SECRET')
      expect(hit).toBeDefined()
      expect(text.slice(hit!.start, hit!.end)).toBe('my-very-secret-value')
    })

    it('classifies APP_SECRET by its most specific keyword (app_secret → API_KEY)', () => {
      const text = `export APP_SECRET=my-very-secret-value`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })
  })

  // ── YAML ──────────────────────────────────────────────────────────────────

  describe('YAML', () => {
    it('detects password in YAML', () => {
      const text = `database:\n  password: "yamlP@ss123"\n  host: localhost`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'PASSWORD')).toBe(true)
    })

    it('detects api_key in YAML', () => {
      const text = `service:\n  api_key: "yaml-api-key-value-123"`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })
  })

  // ── camelCase / kebab variants ────────────────────────────────────────────

  describe('naming variants', () => {
    it('detects camelCase apiKey', () => {
      const text = `{"apiKey":"camel-case-key-value-12345"}`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'API_KEY')).toBe(true)
    })

    it('detects accessToken camelCase', () => {
      const text = `const accessToken = "token-value-abcdef123456"`
      const results = detector.detect(text)
      expect(results.some(r => r.category === 'TOKEN')).toBe(true)
    })
  })

  // ── False positive avoidance ──────────────────────────────────────────────

  describe('false positive avoidance', () => {
    it('does not flag "password": true', () => {
      const text = `{"requirePassword": true}`
      const results = detector.detect(text)
      expect(results.filter(r => r.category === 'PASSWORD')).toHaveLength(0)
    })

    it('does not flag "password": null', () => {
      const text = `{"password": null}`
      const results = detector.detect(text)
      expect(results.filter(r => r.category === 'PASSWORD')).toHaveLength(0)
    })

    it('does not flag very short values (< 3 chars)', () => {
      const text = `{"pwd":"ab"}`
      const results = detector.detect(text)
      expect(results.filter(r => r.category === 'PASSWORD')).toHaveLength(0)
    })

    it('returns empty array for empty input', () => {
      expect(detector.detect('')).toHaveLength(0)
    })
  })

  // ── Confidence levels ─────────────────────────────────────────────────────

  describe('confidence levels', () => {
    it('assigns HIGH to password', () => {
      const text = `{"password":"high-conf-value-xyz"}`
      const results = detector.detect(text)
      const pw = results.find(r => r.category === 'PASSWORD')
      expect(pw?.confidence).toBe('HIGH')
    })

    it('assigns MEDIUM to username', () => {
      const text = `{"username":"adminuser"}`
      const results = detector.detect(text)
      const u = results.find(r => r.category === 'USERNAME')
      expect(u?.confidence).toBe('MEDIUM')
    })
  })

  // ── Line numbers ──────────────────────────────────────────────────────────

  it('reports correct line number', () => {
    const text = `line1\nline2\npassword: "secret-value-xyz"`
    const results = detector.detect(text)
    const pw = results.find(r => r.category === 'PASSWORD')
    expect(pw?.line).toBe(3)
  })
})
