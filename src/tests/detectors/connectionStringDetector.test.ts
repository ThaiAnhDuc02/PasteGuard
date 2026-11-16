import { describe, it, expect, beforeEach } from 'vitest'
import { ConnectionStringDetector } from '../../engine/detectors/connectionStringDetector'

describe('ConnectionStringDetector', () => {
  let detector: ConnectionStringDetector

  beforeEach(() => {
    detector = new ConnectionStringDetector()
  })

  // ── URL-style ─────────────────────────────────────────────────────────────

  describe('URL-style connection strings', () => {
    it('detects PostgreSQL password', () => {
      const url = 'postgres://admin:secret123@db.internal:5432/app'
      const results = detector.detect(url)
      const pw = results.find(r => r.ruleId === 'conn-str:url-password')
      expect(pw).toBeDefined()
      expect(url.slice(pw!.start, pw!.end)).toBe('secret123')
    })

    it('detects PostgreSQL username', () => {
      const url = 'postgres://adminuser:secret123@db.internal:5432/app'
      const results = detector.detect(url)
      const user = results.find(r => r.ruleId === 'conn-str:url-username')
      expect(user).toBeDefined()
      expect(url.slice(user!.start, user!.end)).toBe('adminuser')
    })

    it('detects MySQL password', () => {
      const url = 'mysql://dbuser:dbpassword@mysql.host:3306/mydb'
      const results = detector.detect(url)
      expect(results.some(r => r.ruleId === 'conn-str:url-password')).toBe(true)
    })

    it('detects MongoDB password', () => {
      const url = 'mongodb://admin:mongoSecret@mongo.internal:27017/database'
      const results = detector.detect(url)
      const pw = results.find(r => r.ruleId === 'conn-str:url-password')
      expect(pw).toBeDefined()
      expect(url.slice(pw!.start, pw!.end)).toBe('mongoSecret')
    })

    it('detects MongoDB+srv password', () => {
      const url = 'mongodb+srv://user:atlaspass@cluster.mongodb.net/prod'
      const results = detector.detect(url)
      expect(results.some(r => r.ruleId === 'conn-str:url-password')).toBe(true)
    })

    it('detects Redis password (no username)', () => {
      const url = 'redis://:redisSecret@redis.internal:6379'
      const results = detector.detect(url)
      const pw = results.find(r => r.ruleId === 'conn-str:url-password')
      expect(pw).toBeDefined()
      expect(url.slice(pw!.start, pw!.end)).toBe('redisSecret')
    })

    it('preserves hostname after redaction reference', () => {
      // Verify we did NOT capture the hostname as part of the secret
      const url = 'postgres://admin:secret123@db.internal:5432/app'
      const results = detector.detect(url)
      for (const r of results) {
        const span = url.slice(r.start, r.end)
        expect(span).not.toContain('db.internal')
        expect(span).not.toContain('5432')
      }
    })
  })

  // ── Query parameters ──────────────────────────────────────────────────────

  describe('query parameter credentials', () => {
    it('detects ?password= in URL', () => {
      const url = 'https://api.example.com/db?password=querySecret&ssl=true'
      const results = detector.detect(url)
      const pw = results.find(r => r.ruleId.includes('query-param'))
      expect(pw).toBeDefined()
      expect(url.slice(pw!.start, pw!.end)).toBe('querySecret')
    })

    it('detects &password= mid-querystring', () => {
      const url = 'jdbc:mysql://host/db?user=admin&password=anotherSecret'
      const results = detector.detect(url)
      expect(results.some(r => url.slice(r.start, r.end) === 'anotherSecret')).toBe(true)
    })
  })

  // ── Edge cases ────────────────────────────────────────────────────────────

  describe('edge cases', () => {
    it('returns empty for plain text', () => {
      expect(detector.detect('hello world no secrets here')).toHaveLength(0)
    })

    it('returns empty for empty string', () => {
      expect(detector.detect('')).toHaveLength(0)
    })

    it('handles multiple connection strings in one block', () => {
      const text = ['postgres://user1:pass1@host1:5432/db1', 'mysql://user2:pass2@host2:3306/db2'].join('\n')
      const results = detector.detect(text)
      const passwords = results.filter(r => r.ruleId === 'conn-str:url-password')
      expect(passwords.length).toBeGreaterThanOrEqual(2)
    })
  })
})
