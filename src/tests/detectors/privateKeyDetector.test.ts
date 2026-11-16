import { describe, it, expect, beforeEach } from 'vitest'
import { PrivateKeyDetector } from '../../engine/detectors/privateKeyDetector'

// Fake PEM blocks — not real keys
const FAKE_RSA_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29L2rFMBmUFakE
FakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
FakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
-----END RSA PRIVATE KEY-----`

const FAKE_EC_KEY = `-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIOaFkGNGqGqFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
FakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
-----END EC PRIVATE KEY-----`

const FAKE_OPENSSH_KEY = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
FakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
-----END OPENSSH PRIVATE KEY-----`

describe('PrivateKeyDetector', () => {
  let detector: PrivateKeyDetector

  beforeEach(() => {
    detector = new PrivateKeyDetector()
  })

  it('detects RSA PRIVATE KEY block', () => {
    const results = detector.detect(FAKE_RSA_KEY)
    expect(results).toHaveLength(1)
    expect(results[0].category).toBe('PRIVATE_KEY')
    expect(results[0].confidence).toBe('HIGH')
  })

  it('captures the entire RSA block', () => {
    const results = detector.detect(FAKE_RSA_KEY)
    expect(FAKE_RSA_KEY.slice(results[0].start, results[0].end)).toBe(FAKE_RSA_KEY)
  })

  it('detects EC PRIVATE KEY block', () => {
    const results = detector.detect(FAKE_EC_KEY)
    expect(results.some(r => r.ruleId.includes('ec-private-key'))).toBe(true)
  })

  it('detects OPENSSH PRIVATE KEY block', () => {
    const results = detector.detect(FAKE_OPENSSH_KEY)
    expect(results.some(r => r.ruleId.includes('openssh-private-key'))).toBe(true)
  })

  it('detects key embedded in larger text', () => {
    const text = `# Config file\nhost=example.com\n${FAKE_RSA_KEY}\nport=443`
    const results = detector.detect(text)
    expect(results).toHaveLength(1)
    expect(results[0].category).toBe('PRIVATE_KEY')
  })

  it('detects multiple keys in one document', () => {
    const text = `${FAKE_RSA_KEY}\n\n${FAKE_EC_KEY}`
    const results = detector.detect(text)
    expect(results.length).toBeGreaterThanOrEqual(2)
  })

  it('reports correct start line for embedded key', () => {
    const text = `line1\nline2\n${FAKE_RSA_KEY}`
    const results = detector.detect(text)
    expect(results[0].line).toBe(3)
  })

  it('returns empty for text with no PEM blocks', () => {
    expect(detector.detect('{"key":"value","password":"secret"}')).toHaveLength(0)
  })

  it('returns empty for empty string', () => {
    expect(detector.detect('')).toHaveLength(0)
  })

  it('fails closed: redacts the body of a BEGIN without END (truncated paste)', () => {
    const body = 'MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9vQ'
    const text = `-----BEGIN RSA PRIVATE KEY-----\n${body}\n${body}`
    const results = detector.detect(text)
    expect(results).toHaveLength(1)
    expect(results[0].start).toBe(0)
    expect(results[0].end).toBe(text.length)
  })

  it('unterminated block stops at the first non-key line', () => {
    const text = `-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nThanks for the help!`
    const results = detector.detect(text)
    expect(results).toHaveLength(1)
    expect(text.slice(results[0].end)).toBe('\nThanks for the help!')
  })

  it('handles JSON-escaped PEM (GCP service account style)', () => {
    const text = `{"private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\\nBKcwggSjAgEAAoIBAQC7\\n-----END PRIVATE KEY-----\\n"}`
    const results = detector.detect(text)
    expect(results).toHaveLength(1)
    expect(text.slice(results[0].start, results[0].end)).toContain('BKcwggSjAgEAAoIBAQC7')
  })
})
