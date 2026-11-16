/**
 * Regression suite for leaks found in the audit, plus false-positive guards
 * and a performance budget. All values are fake.
 */
import { describe, it, expect } from 'vitest'
import { runDetection } from '../../engine/detectionEngine'
import { runPipeline } from '../../engine/pipeline'
import type { CustomRule } from '../../types/rules'
import { FAKE } from '../fixtures'

const mask = (text: string) => runPipeline(text).maskedText

describe('Leak regressions — secret must not survive', () => {
  const cases: Array<[string, string, string]> = [
    [
      'prefixed JSON key (confirm_password)',
      '{"password":"sameSecret","confirm_password":"sameSecret"}',
      'sameSecret',
    ],
    [
      'prefixed snake key (first_password)',
      'first_password=sharedSecret\nsecond_password=sharedSecret',
      'sharedSecret',
    ],
    ['prefixed env key (STRIPE_SECRET_KEY)', 'STRIPE_SECRET_KEY=zzSecretValue99', 'zzSecretValue99'],
    ['GITHUB_TOKEN with non-ghp value', 'GITHUB_TOKEN=abcdefghijklmnop123', 'abcdefghijklmnop123'],
    ['bare "token" JSON key', '{"token": "tokValue12345"}', 'tokValue12345'],
    ['X-API-Key header', 'X-API-Key: hdrKeyValue123', 'hdrKeyValue123'],
    ['X-Auth-Token header', 'X-Auth-Token: hdrTokValue987', 'hdrTokValue987'],
    ['concatenated APIKEY', 'APIKEY=concatKeyValue42', 'concatKeyValue42'],
    ['camelCase dbPassword', 'const dbPassword = "camelPw!42"', 'camelPw!42'],
    ['dotted properties key', 'spring.datasource.password=propPw123', 'propPw123'],
    ['PHP array', "'client_secret' => 'phpClientSecret9'", 'phpClientSecret9'],
    ['CLI flag', 'mytool --api-key=cliKeyValue77 --verbose', 'cliKeyValue77'],
    ['escaped quote in JSON value', '{"password":"ab\\"cdEFGH"}', 'cdEFGH'],
    [
      'YAML block scalar',
      'secret: |\n  multiLineSecretValue\n  secondLineValue\nother: x',
      'multiLineSecretValue',
    ],
    ['k8s env name/value list', 'env:\n  - name: DB_PASSWORD\n    value: k8sPw!secret', 'k8sPw!secret'],
    ['ECS JSON name/value', '{"name": "API_TOKEN", "value": "ecsTokValue123"}', 'ecsTokValue123'],
    ['Dockerfile ENV space form', 'ENV DB_PASSWORD dockerPw123', 'dockerPw123'],
    ['OpenAI project key', `use ${FAKE.openaiProject} to call`, FAKE.openaiProject],
    ['Anthropic key', `ANTHROPIC_API_KEY=${FAKE.anthropic}`, 'AbCdEf1234567890_xyzXYZ'],
    ['Google API key', `key here ${FAKE.googleApiKey}`, FAKE.googleApiKey],
    ['Hugging Face token', FAKE.huggingFace, FAKE.huggingFace],
    ['GitLab token', FAKE.gitlabPat, FAKE.gitlabPat],
    ['Slack webhook', FAKE.slackWebhookUrl, 'XXXXXXXXXXXXXXXXXXXXXXXX'],
    [
      'standalone Bearer in curl',
      'curl -H "Authorization: Bearer abcDEF123456ghiJKL789"',
      'abcDEF123456ghiJKL789',
    ],
    ['Bearer in prose', 'the header was Bearer abcDEF123456ghiJKL789xyz', 'abcDEF123456ghiJKL789xyz'],
    ['curl -u short password', 'curl -u admin:pass1 https://api.example.com', 'pass1'],
    ['HTTPS URL credentials', 'git clone https://deploy:gitPassw0rd@git.example.com/repo.git', 'gitPassw0rd'],
    ['AMQP URL credentials', 'amqp://guest:amqpSecret1@rabbit:5672/', 'amqpSecret1'],
    [
      'Azure connection string',
      'DefaultEndpointsProtocol=https;AccountName=acct;AccountKey=azKeyAbc123+/==;EndpointSuffix=core.windows.net',
      'azKeyAbc123+/==',
    ],
    ['ADO.NET connection string', 'Server=db;Database=app;User Id=sa;Password=adoPw!99;', 'adoPw!99'],
    [
      'S3 presigned signature',
      'https://b.s3.amazonaws.com/f?X-Amz-Signature=abcdef0123456789&X-Amz-Date=1',
      'abcdef0123456789',
    ],
    [
      'unterminated PEM',
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA2a2rZZZZZZZZZZZZZZZZZZZZ',
      'MIIEowIBAAKCAQEA2a2r',
    ],
  ]

  for (const [label, input, secret] of cases) {
    it(label, () => {
      expect(mask(input)).not.toContain(secret)
    })
  }

  it('keeps non-secret query params (no over-redaction across &)', () => {
    const out = mask('https://h/db?user=apiUser&password=qsSecret&ssl=true')
    expect(out).not.toContain('qsSecret')
    expect(out).toContain('ssl=true')
  })

  it('keeps the Bearer scheme word visible', () => {
    expect(mask('Authorization: Bearer abcDEF123456ghiJKL789')).toBe('Authorization: Bearer ********')
  })

  it('keeps the rest of a connection string', () => {
    const out = mask('Server=db;Database=app;Password=adoPw!99;Encrypt=true')
    expect(out).toContain('Database=app')
    expect(out).toContain('Encrypt=true')
  })

  it('custom rule matches JSON, ENV and prefixed keys', () => {
    const rule: CustomRule = {
      id: 'r',
      name: 'Internal',
      fieldNames: ['my_token'],
      category: 'CUSTOM',
      maskingStrategy: null,
      confidence: 'HIGH',
      enabled: true,
    }
    const text = '{"myToken":"aaa111bbb"}\nAPP_MY_TOKEN=ccc222ddd'
    const out = runPipeline(text, { customRules: [rule] }).maskedText
    expect(out).not.toContain('aaa111bbb')
    expect(out).not.toContain('ccc222ddd')
  })
})

describe('False-positive guards', () => {
  const clean: Array<[string, string]> = [
    ['keys that start with a keyword', 'password_hash=bcryptish\ntoken_type=bearer\npassword_min_length=12'],
    ['keyword inside a word', 'monkey=banana\nbypass=enabled\nsuperuser_mode=on'],
    ['env references', 'DB_PASSWORD=${DB_PASSWORD}\napi_key: {{ .Values.apiKey }}\ntoken: process.env.TOKEN'],
    ['type annotations', 'password: string\napiKey: str'],
    ['already masked text', 'password=********\napi_key=[API_KEY_1]'],
    ['lockfile integrity', '"integrity": "sha512-Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"'],
    ['UUID under unknown key', 'request: 3f2b8c1e-9d4a-4b6f-8e2a-1c3d5e7f9a0b'],
    ['plain prose', 'Please reset your password using the link we sent.'],
    ['https URL with port and email', 'https://host.example.com:8080/path?email=a@b.com'],
  ]
  for (const [label, input] of clean) {
    it(label, () => {
      const { detections } = runDetection(input)
      expect(detections.filter(d => d.confidence !== 'LOW')).toHaveLength(0)
    })
  }
})

describe('Entropy fallback', () => {
  it('flags a random credential under an unknown key as LOW', () => {
    const { detections } = runDetection('stripe_rk: Zx9Kq2Lm8Vb4Np7Rt1Wy5Hc3Jd6Fg0Sa')
    expect(detections.some(d => d.ruleId === 'entropy:key-value' && d.confidence === 'LOW')).toBe(true)
  })

  it('can be disabled', () => {
    const { detections } = runDetection('stripe_rk: Zx9Kq2Lm8Vb4Np7Rt1Wy5Hc3Jd6Fg0Sa', {
      enableEntropy: false,
    })
    expect(detections).toHaveLength(0)
  })
})

describe('Second-pass verification', () => {
  it('reports no residual detections for normal masking', () => {
    const r = runPipeline('password=abc12345\nAuthorization: Bearer abcDEF123456ghiJKL789')
    expect(r.residual).toHaveLength(0)
  })

  it('does not count placeholder labels as residual leaks', () => {
    const r = runPipeline('password=abc12345', {}, { strategy: 'PLACEHOLDER' })
    expect(r.maskedText).toBe('password=[PASSWORD_1]')
    expect(r.residual).toHaveLength(0)
  })
})

describe('Performance', () => {
  it('handles ~1 MB with 20 000 hits well under the budget', () => {
    const input = 'api_key=sk-reallylargeapikeythatislong1234567890\n'.repeat(20000)
    const t0 = performance.now()
    const { detections } = runDetection(input)
    const ms = performance.now() - t0
    expect(detections.length).toBeGreaterThanOrEqual(20000)
    expect(ms).toBeLessThan(5000)
  })

  it('stays linear on adversarial inputs (no catastrophic backtracking)', () => {
    const inputs = [
      'password=' + ' '.repeat(200_000),
      'user=' + 'a=b&'.repeat(50_000),
      '-----BEGIN PRIVATE KEY-----\n'.repeat(5_000),
      'ENV DB_PASSWORD' + ' '.repeat(200_000),
      '"password":' + '\n'.repeat(200_000),
      ('"' + 'a'.repeat(199)).repeat(1_000),
    ]
    for (const input of inputs) {
      const t0 = performance.now()
      runPipeline(input)
      expect(performance.now() - t0).toBeLessThan(2000)
    }
  })

  it('reports correct line numbers on large input', () => {
    const input = 'x=1\n'.repeat(5000) + 'password=lineCheck99'
    const hit = runDetection(input).detections.find(d => d.category === 'PASSWORD')
    expect(hit?.line).toBe(5001)
  })
})
