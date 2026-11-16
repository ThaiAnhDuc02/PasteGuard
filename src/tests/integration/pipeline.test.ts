/**
 * Integration tests: full detect → redact pipeline.
 *
 * These tests verify that realistic input texts produce correct masked output
 * and that no original secret values survive in the result.
 */
import { describe, it, expect } from 'vitest'
import { runDetection } from '../../engine/detectionEngine'
import { redactText } from '../../engine/redaction/redactionEngine'
import type { MaskingOptions } from '../../types/redaction'
import { FAKE } from '../fixtures'

const FULL: MaskingOptions = { strategy: 'FULL_MASK', maskChar: '*', fullMaskLength: 8 }
const PH: MaskingOptions = { strategy: 'PLACEHOLDER', maskChar: '*', fullMaskLength: 8 }

/** Run the full pipeline and return the masked text. */
function mask(text: string, opts: MaskingOptions = FULL): string {
  const { detections } = runDetection(text)
  return redactText(text, detections, { maskingOptions: opts }).maskedText
}

/** Assert no substring from `secrets` appears in `output`. */
function assertSecretsRemoved(output: string, secrets: string[]) {
  for (const s of secrets) {
    expect(output, `"${s.slice(0, 20)}…" should not appear in output`).not.toContain(s)
  }
}

// ── Structured formats ────────────────────────────────────────────────────────

describe('JSON credentials', () => {
  it('masks passwords and api_keys while keeping JSON structure intact', () => {
    const input = JSON.stringify(
      {
        username: 'admin',
        password: 'jsonP@ssword99',
        api_key: 'sk-jsonapikey123456789',
        host: 'db.internal',
        port: 5432,
      },
      null,
      2,
    )

    const output = mask(input)

    assertSecretsRemoved(output, ['jsonP@ssword99', 'sk-jsonapikey123456789'])
    // Structure preserved — these non-secret fields should survive
    expect(output).toContain('"host"')
    expect(output).toContain('db.internal')
    expect(output).toContain('"port"')
    expect(output).toContain('5432')
    // JSON is still parseable after masking
    expect(() => JSON.parse(output)).not.toThrow()
  })

  it('masks repeated password occurrences', () => {
    const input = `{"password":"sameSecret","confirm_password":"sameSecret"}`
    const output = mask(input)
    assertSecretsRemoved(output, ['sameSecret'])
  })
})

describe('YAML credentials', () => {
  it('masks YAML database credentials', () => {
    const input = `
database:
  host: db.internal
  port: 5432
  username: yamlAdmin
  password: "yamlP@ssword!"
  api_key: yaml-api-key-value-999
`.trim()

    const output = mask(input)
    assertSecretsRemoved(output, ['yamlP@ssword!', 'yaml-api-key-value-999'])
    expect(output).toContain('host: db.internal')
    expect(output).toContain('port: 5432')
  })
})

describe('.env files', () => {
  it('masks .env secrets preserving variable names', () => {
    const input = `
NODE_ENV=production
DATABASE_PASSWORD=envDbSecret99
API_KEY=env-api-key-value-123456
REDIS_URL=redis://:envRedisPass@redis.host:6379
PORT=3000
`.trim()

    const output = mask(input)
    assertSecretsRemoved(output, ['envDbSecret99', 'env-api-key-value-123456', 'envRedisPass'])
    expect(output).toContain('NODE_ENV=production')
    expect(output).toContain('PORT=3000')
    expect(output).toContain('DATABASE_PASSWORD=')
    expect(output).toContain('API_KEY=')
  })
})

// ── Connection strings ────────────────────────────────────────────────────────

describe('Connection strings', () => {
  it('masks postgres credentials preserving host/port/db', () => {
    const url = 'postgres://pgUser:pgSecret123@db.internal:5432/appdb'
    const output = mask(url)
    assertSecretsRemoved(output, ['pgUser', 'pgSecret123'])
    expect(output).toContain('db.internal')
    expect(output).toContain('5432')
    expect(output).toContain('appdb')
  })

  it('masks mongodb credentials', () => {
    const url = 'mongodb://mongoAdmin:mongoSecret456@mongo.host:27017/mydb'
    const output = mask(url)
    assertSecretsRemoved(output, ['mongoAdmin', 'mongoSecret456'])
    expect(output).toContain('mongo.host')
    expect(output).toContain('27017')
    expect(output).toContain('mydb')
  })

  it('masks redis password-only URL', () => {
    const url = 'redis://:redisPassword789@redis.host:6379'
    const output = mask(url)
    assertSecretsRemoved(output, ['redisPassword789'])
    expect(output).toContain('redis.host')
    expect(output).toContain('6379')
  })

  it('masks query-string password parameter', () => {
    const url = 'https://api.internal/db?user=apiUser&password=qsSecret&ssl=true'
    const output = mask(url)
    assertSecretsRemoved(output, ['qsSecret'])
    expect(output).toContain('ssl=true')
  })
})

// ── Token patterns ────────────────────────────────────────────────────────────

describe('Token patterns', () => {
  it('masks JWT in Authorization header', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
    const input = `GET /api/data HTTP/1.1\nAuthorization: Bearer ${jwt}\nContent-Type: application/json`
    const output = mask(input)
    assertSecretsRemoved(output, [jwt])
    expect(output).toContain('GET /api/data HTTP/1.1')
    expect(output).toContain('Content-Type: application/json')
  })

  it('masks AWS access key ID', () => {
    const input = `aws_access_key_id = ${FAKE.awsAccessKeyId}\nregion = us-east-1`
    const output = mask(input)
    assertSecretsRemoved(output, [FAKE.awsAccessKeyId])
    expect(output).toContain('region = us-east-1')
  })

  it('masks GitHub PAT', () => {
    const input = `GITHUB_TOKEN=${FAKE.githubPat}`
    const output = mask(input)
    assertSecretsRemoved(output, [FAKE.githubPat])
  })
})

// ── Private keys ──────────────────────────────────────────────────────────────

describe('Private key blocks', () => {
  it('masks entire PEM block', () => {
    const keyBody = 'MIIEowIBAAKCAQEA2a2rwplBQLzFakeFakeFakeFakeFakeFakeFakeFakeFakeBody'
    const input = `# SSH Config\nhost=example.com\n-----BEGIN RSA PRIVATE KEY-----\n${keyBody}\n-----END RSA PRIVATE KEY-----\nport=22`
    const output = mask(input)
    expect(output).not.toContain('BEGIN RSA PRIVATE KEY')
    expect(output).not.toContain(keyBody)
    expect(output).toContain('host=example.com')
    expect(output).toContain('port=22')
  })
})

// ── Shell / Docker / K8s ─────────────────────────────────────────────────────

describe('Shell commands', () => {
  it('masks secrets in shell export commands', () => {
    const input = `#!/bin/bash\nexport DB_PASSWORD=shellDbSecret\nexport API_KEY=shell-api-key-value\necho "Starting server"`
    const output = mask(input)
    assertSecretsRemoved(output, ['shellDbSecret', 'shell-api-key-value'])
    expect(output).toContain('echo "Starting server"')
  })
})

describe('Docker environment', () => {
  it('masks secrets in docker-compose environment block', () => {
    const input = `version: "3"\nservices:\n  app:\n    environment:\n      - DATABASE_PASSWORD=dockerSecret\n      - API_KEY=docker-api-key-123\n      - PORT=8080`
    const output = mask(input)
    assertSecretsRemoved(output, ['dockerSecret', 'docker-api-key-123'])
    expect(output).toContain('PORT=8080')
  })
})

// ── Multiline logs ────────────────────────────────────────────────────────────

describe('Application logs', () => {
  it('masks secrets embedded in log lines without altering timestamps', () => {
    const input = [
      '2026-11-16T08:00:00Z INFO  Starting application',
      '2026-11-16T08:00:01Z DEBUG api_key=log-api-key-secret123',
      '2026-11-16T08:00:02Z INFO  Connected to database',
      '2026-11-16T08:00:03Z DEBUG password=logDbSecret456',
    ].join('\n')

    const output = mask(input)
    assertSecretsRemoved(output, ['log-api-key-secret123', 'logDbSecret456'])
    expect(output).toContain('2026-11-16T08:00:00Z')
    expect(output).toContain('Starting application')
    expect(output).toContain('Connected to database')
  })
})

// ── Kubernetes manifests ──────────────────────────────────────────────────────

describe('Kubernetes manifests', () => {
  it('masks secrets in K8s Secret manifest', () => {
    const input = `
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  password: "k8sSecretPassword"
  api_key: "k8s-api-key-value-123"
`.trim()

    const output = mask(input)
    assertSecretsRemoved(output, ['k8sSecretPassword', 'k8s-api-key-value-123'])
    expect(output).toContain('apiVersion: v1')
    expect(output).toContain('kind: Secret')
    expect(output).toContain('name: app-secrets')
  })
})

// ── Edge cases ────────────────────────────────────────────────────────────────

describe('Edge cases', () => {
  it('handles empty input', () => {
    const { detections } = runDetection('')
    expect(detections).toHaveLength(0)
    const { maskedText } = redactText('', [], { maskingOptions: FULL })
    expect(maskedText).toBe('')
  })

  it('returns unchanged text with no secrets', () => {
    const input = 'This is a plain text string with no secrets at all.'
    const output = mask(input)
    expect(output).toBe(input)
  })

  it('handles malformed JSON without crashing', () => {
    const input = `{invalid json "password": "broken`
    expect(() => mask(input)).not.toThrow()
  })

  it('handles special characters in values', () => {
    const input = `password="p@$$w0rd!#%^&*()"`
    const output = mask(input)
    expect(output).not.toContain('p@$$w0rd!#%^&*()')
  })

  it('handles very large input without freezing', () => {
    const line = 'api_key=sk-reallylargeapikeythatislong1234567890\n'
    const input = line.repeat(500) // 500 lines
    const start = Date.now()
    expect(() => mask(input)).not.toThrow()
    expect(Date.now() - start).toBeLessThan(5000) // must finish in <5 s
  })

  it('placeholder strategy gives consistent labels across the full pipeline', () => {
    const input = `first_password=sharedSecret\nsecond_password=sharedSecret`
    const { detections } = runDetection(input)
    const { maskedText } = redactText(input, detections, { maskingOptions: PH })
    // All occurrences of sharedSecret should use the same placeholder
    const labels = [...maskedText.matchAll(/\[PASSWORD_\d+\]/g)].map(m => m[0])
    expect(new Set(labels).size).toBe(1)
  })

  it('detection summary counts are accurate', () => {
    const input = `{"password":"pw1","api_key":"ak1","username":"u1"}`
    const { summary } = runDetection(input)
    expect(summary.total).toBeGreaterThanOrEqual(2)
    expect(summary.byCategory['PASSWORD']).toBeGreaterThanOrEqual(1)
    expect(summary.byCategory['API_KEY']).toBeGreaterThanOrEqual(1)
  })
})

// ── Security regression suite ─────────────────────────────────────────────────

describe('Security regression — no secret survives masking', () => {
  const cases: Array<{ label: string; input: string; secrets: string[] }> = [
    {
      label: 'JSON config',
      input: `{"password":"Regr3ss!on","api_key":"regr-api-key-999","client_secret":"oauth-sec-abc"}`,
      secrets: ['Regr3ss!on', 'regr-api-key-999', 'oauth-sec-abc'],
    },
    {
      label: 'Postgres URL',
      input: 'postgres://regrUser:regrPass@host:5432/db',
      secrets: ['regrUser', 'regrPass'],
    },
    {
      label: 'Bearer header',
      input: 'Authorization: Bearer regrBearerTokenValue12345678',
      secrets: ['regrBearerTokenValue12345678'],
    },
    {
      label: '.env file',
      input: 'SECRET_KEY=regrEnvSecretValue\nDATABASE_URL=postgres://u:regrDbPass@h/db',
      secrets: ['regrEnvSecretValue', 'regrDbPass'],
    },
  ]

  for (const { label, input, secrets } of cases) {
    it(`[${label}] all secrets removed`, () => {
      const output = mask(input)
      assertSecretsRemoved(output, secrets)
    })
  }
})
