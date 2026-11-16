/**
 * Key-Based Detector
 *
 * Finds `key <sep> value` pairs in any common syntax and flags the value when
 * the key name identifies a secret:
 *
 *   JSON / JS objects   "password": "value"     apiKey: 'value'
 *   ENV / shell / INI   DB_PASSWORD=value        export APP_SECRET="value"
 *   YAML / TOML         password: value          token = "value"
 *   XML attributes      password="value"
 *   Source code         const accessToken = "value"
 *   PHP arrays          'client_secret' => 'value'
 *   HTTP headers        X-API-Key: value         Authorization: Bearer value
 *   Properties          db.password=value
 *   K8s / ECS env lists - name: DB_PASSWORD  ⏎  value: secret
 *   Dockerfile          ENV DB_PASSWORD secret
 *
 * Key matching
 * ------------
 * The key is split into words on `_`, `-`, `.`, whitespace and camelCase
 * boundaries (`STRIPE_SECRET_KEY` → [stripe, secret, key],
 * `X-Api-Key` → [x, api, key], `dbPassword` → [db, password]).
 * A keyword matches when it equals a *suffix* of that word list, either word by
 * word or concatenated (`APIKEY` matches `api_key`). The longest (most
 * specific) keyword wins. Suffix matching means prefixed keys such as
 * `confirm_password` are caught, while keys that merely *start* with a keyword
 * (`password_hash`, `token_type`) or contain it inside a word (`monkey`,
 * `bypass`) are not.
 *
 * Entropy fallback
 * ----------------
 * When the key is not a known keyword but the value looks like a random
 * credential (long, high Shannon entropy, mixed character classes), the value
 * is reported as GENERIC_SECRET with LOW confidence. This catches new vendor
 * token formats that no structural rule knows about yet.
 */

import type { DetectionResult, Detector, SecretCategory, ConfidenceLevel } from '../../types/detection'
import { offsetToLine } from '../../types/detection'

// ── keyword table ─────────────────────────────────────────────────────────────

export interface KeywordEntry {
  keywords: string[]
  category: SecretCategory
  confidence: ConfidenceLevel
}

const KEYWORD_TABLE: KeywordEntry[] = [
  {
    keywords: [
      'password',
      'passwd',
      'pwd',
      'passphrase',
      'db_pass',
      'database_password',
      'db_password',
      'db_pwd',
      'mysql_password',
      'postgres_password',
      'root_password',
      'admin_password',
      'master_password',
    ],
    category: 'PASSWORD',
    confidence: 'HIGH',
  },
  {
    keywords: ['pass'],
    category: 'PASSWORD',
    confidence: 'MEDIUM',
  },
  {
    keywords: [
      'api_key',
      'api_secret',
      'access_key',
      'secret_key',
      'signing_key',
      'encryption_key',
      'app_key',
      'app_secret',
      'master_key',
      'license_key',
      'subscription_key',
      'account_key',
      'service_key',
      'client_key',
      'auth_key',
      'access_key_secret',
      'secret_access_key',
      'webhook_secret',
      'signing_secret',
    ],
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    keywords: [
      'token',
      'access_token',
      'refresh_token',
      'auth_token',
      'id_token',
      'bearer_token',
      'jwt_token',
      'session_token',
      'csrf_token',
      'api_token',
      'security_token',
      'private_token',
      'personal_access_token',
      'pat',
    ],
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    keywords: ['auth', 'session_id', 'sessionid', 'session_key', 'cookie', 'set_cookie'],
    category: 'TOKEN',
    confidence: 'MEDIUM',
  },
  {
    keywords: ['client_secret', 'oauth_secret', 'consumer_secret', 'oauth_token_secret'],
    category: 'OAUTH_SECRET',
    confidence: 'HIGH',
  },
  {
    keywords: ['secret', 'private_key', 'secret_value', 'secret_token', 'salt', 'pepper'],
    category: 'GENERIC_SECRET',
    confidence: 'HIGH',
  },
  {
    keywords: ['authorization', 'proxy_authorization', 'bearer'],
    category: 'BEARER_TOKEN',
    confidence: 'HIGH',
  },
  {
    keywords: ['credential', 'credentials', 'dsn'],
    category: 'GENERIC_SECRET',
    confidence: 'MEDIUM',
  },
  {
    keywords: ['username', 'user_name', 'login'],
    category: 'USERNAME',
    confidence: 'MEDIUM',
  },
  {
    keywords: ['user'],
    category: 'USERNAME',
    confidence: 'LOW',
  },
  {
    keywords: ['client_id'],
    category: 'OAUTH_SECRET',
    confidence: 'LOW',
  },
]

/** Normalise a keyword / field name to its concatenated lowercase form. */
export function normaliseKey(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]/g, '')
}

const BUILTIN_KEYWORDS: Map<string, { keyword: string; entry: KeywordEntry }> = new Map()
for (const entry of KEYWORD_TABLE) {
  for (const kw of entry.keywords) BUILTIN_KEYWORDS.set(normaliseKey(kw), { keyword: kw, entry })
}

/**
 * Split an identifier into lowercase words:
 *   STRIPE_SECRET_KEY → [stripe, secret, key]
 *   X-Api-Key         → [x, api, key]
 *   dbPassword        → [db, password]
 *   HTTPAuthToken     → [http, auth, token]
 */
export function splitKeyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean)
}

/** All concatenated suffixes of the word list, longest first. */
export function keySuffixes(key: string): string[] {
  const words = splitKeyWords(key)
  const out: string[] = []
  for (let i = 0; i < words.length; i++) out.push(words.slice(i).join(''))
  return out
}

// ── generic key/value scanner (shared with the custom detector) ───────────────

/** One key/value pair found in the text. Offsets point at the value. */
export interface KeyValueMatch {
  key: string
  value: string
  valueStart: number
  valueEnd: number
  /** True when the value was quoted in the source. */
  quoted: boolean
}

// Escape-aware quoted strings so `"pa\"ss"` is captured whole.
const DQ = String.raw`"((?:[^"\\\n]|\\.)*)"`
const SQ = String.raw`'((?:[^'\\\n]|\\.)*)'`
// Unquoted value: up to whitespace, a quote, or a structural separator —
// `&name=` (query string), `;name=` (connection string), `, ` (lists),
// literal `\n` escapes. Boundaries live in the regex (not a post-trim) so a
// match never consumes the rest of a long line: that kept scanning linear.
const UQ = String.raw`((?:[^\s"'\x60&;,\\]|&(?![\w.%-]+=)|;(?!\s*[\w.%-]+=)|,(?![\s"']|$)|\\(?![nr]))+)`
// Auth schemes are skipped so `Authorization: Bearer <tok>` captures <tok>.
const SCHEME = String.raw`(?:(?:Bearer|Basic|Token|Digest|Bot|ApiKey)[ \t]+)?`
// Each alternative owns its leading whitespace. Never put another whitespace
// quantifier directly before VALUE: overlapping `[ \t]*\s*` backtracks
// quadratically on long runs of spaces.
const VALUE = String.raw`(?:\s*${DQ}|\s*${SQ}|[ \t]*${SCHEME}${UQ})`

// key <sep> value — key may be quoted or a bare identifier (with optional
// leading dashes for CLI flags such as --password=value).
const KV_PATTERN = new RegExp(
  String.raw`(?:"([^"\\\n]{1,200})"|'([^'\\\n]{1,200})'|(?<![\w.$-])-{0,2}([A-Za-z_][\w.-]{0,200}))` +
    String.raw`\s*(?::=|=>|[=:])` +
    VALUE,
  'g',
)

// name/value pairs: Kubernetes env, ECS task definitions, GitHub/Azure API JSON
const NAME_VALUE_PATTERN = new RegExp(
  String.raw`\bname["']?\s*[:=]\s*["']?([A-Za-z_][\w.-]{0,200})["']?\s*,?\s*(?:-\s*)?["']?value["']?\s*[:=]` +
    VALUE,
  'g',
)

// Dockerfile `ENV KEY value` (space-separated form)
const DOCKER_ENV_PATTERN = new RegExp(String.raw`^[ \t]*ENV[ \t]+([A-Za-z_][\w.-]*)(?=[ \t])` + VALUE, 'gm')

/**
 * Trim trailing characters that belong to the container, not the value:
 * trailing `,` / `;` and unbalanced closing brackets (`{"a": x}`).
 */
function trimUnquoted(v: string): string {
  let out = v
  for (;;) {
    const last = out.slice(-1)
    if (last === ',' || last === ';') {
      out = out.slice(0, -1)
      continue
    }
    const pairs: Record<string, string> = { '}': '{', ']': '[', ')': '(', '>': '<' }
    const opener = pairs[last]
    if (opener !== undefined && count(out, opener) < count(out, last)) {
      out = out.slice(0, -1)
      continue
    }
    break
  }
  return out
}

function count(s: string, ch: string): number {
  let n = 0
  for (const c of s) if (c === ch) n++
  return n
}

/** YAML block scalar (`key: |` / `key: >-`) → span of the indented block. */
function blockScalarSpan(text: string, indicatorEnd: number, keyIndex: number): [number, number] | null {
  const lineStart = text.lastIndexOf('\n', keyIndex) + 1
  const keyIndent = keyIndex - lineStart
  let pos = text.indexOf('\n', indicatorEnd)
  if (pos === -1) return null
  pos++
  const blockStart = pos
  let blockEnd = -1
  while (pos < text.length) {
    const nl = text.indexOf('\n', pos)
    const lineEnd = nl === -1 ? text.length : nl
    const line = text.slice(pos, lineEnd)
    if (line.trim().length > 0) {
      const indent = line.length - line.trimStart().length
      if (indent <= keyIndent) break
      blockEnd = lineEnd
    }
    if (nl === -1) break
    pos = nl + 1
  }
  if (blockEnd === -1) return null
  // Start at first non-space char of the block
  let s = blockStart
  while (s < blockEnd && /\s/.test(text[s])) s++
  return s < blockEnd ? [s, blockEnd] : null
}

function collect(pattern: RegExp, keyGroups: number[], text: string, out: KeyValueMatch[]): void {
  const re = new RegExp(pattern.source, pattern.flags)
  const valueGroup = keyGroups[keyGroups.length - 1] + 1 // DQ, SQ, UQ follow key groups
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const key = keyGroups.map(g => m![g]).find(k => k !== undefined) ?? ''
    const dq = m[valueGroup]
    const sq = m[valueGroup + 1]
    const uq = m[valueGroup + 2]
    const matchEnd = m.index + m[0].length

    let value: string
    let valueStart: number
    let quoted = false
    if (dq !== undefined || sq !== undefined) {
      value = (dq ?? sq)!
      // value sits just before the closing quote
      valueStart = matchEnd - 1 - value.length
      quoted = true
    } else {
      const raw = uq ?? ''
      const rawStart = matchEnd - raw.length
      if (/^[|>][-+]?\d?$/.test(raw)) {
        const span = blockScalarSpan(text, matchEnd, m.index)
        if (span) {
          out.push({
            key,
            value: text.slice(span[0], span[1]),
            valueStart: span[0],
            valueEnd: span[1],
            quoted: true,
          })
        }
        continue
      }
      value = trimUnquoted(raw)
      valueStart = rawStart
    }

    out.push({ key, value, valueStart, valueEnd: valueStart + value.length, quoted })

    // Resume inside the value rather than after the whole match, so nested
    // pairs are still found: `{"a":{"password":…}}`, `"note":"token: …"`, and
    // `user=bob&password=…` (the unquoted value was trimmed at `&`).
    const resume = quoted ? valueStart : valueStart + value.length
    re.lastIndex = Math.max(m.index + 1, Math.min(resume, matchEnd))
  }
}

/** Scan text for every key/value pair (all supported syntaxes). */
export function scanKeyValues(text: string): KeyValueMatch[] {
  const out: KeyValueMatch[] = []
  collect(KV_PATTERN, [1, 2, 3], text, out)
  collect(NAME_VALUE_PATTERN, [1], text, out)
  collect(DOCKER_ENV_PATTERN, [1], text, out)
  return out
}

// ── value filters ─────────────────────────────────────────────────────────────

const MIN_VALUE_LENGTH = 3

// Values to skip even if matched (common non-secret placeholders / type names)
const IGNORED_VALUES = new Set([
  'true',
  'false',
  'null',
  'none',
  'nil',
  'undefined',
  'yes',
  'no',
  'on',
  'off',
  '0',
  '1',
  '',
  'n/a',
  'na',
  '-',
  'default',
  'localhost',
  '127.0.0.1',
  '::1',
  'string',
  'str',
  'number',
  'int',
  'integer',
  'boolean',
  'bool',
  'any',
  'object',
  'text',
  'varchar',
  'optional',
  'required',
  'secret',
  'password',
  'redacted',
  'changeme',
  'example',
  'placeholder',
  'xxx',
  'xxxx',
  'xxxxx',
  'todo',
  'tbd',
])

/** True for values that are references or masks, not literal secrets. */
export function isNonSecretValue(value: string, quoted = true): boolean {
  const v = value.trim()
  if (v.length < MIN_VALUE_LENGTH) return true
  if (IGNORED_VALUES.has(v.toLowerCase())) return true
  // ${VAR}, $VAR, {{ template }}, %VAR%, <placeholder>, process.env.X, os.environ[...]
  if (/^\$\{?[\w.:-]+\}?$/.test(v)) return true
  if (/^\{\{.*\}\}$/.test(v)) return true
  if (/^%[\w]+%$/.test(v)) return true
  if (/^<[^<>]+>$/.test(v)) return true
  if (
    /^(?:process\.env\.|process\.env\[|import\.meta\.env\.|os\.environ[.[]|os\.getenv\(|System\.getenv\(|ENV\[|env\.|env\()/.test(
      v,
    )
  )
    return true
  // Already masked: ****, [PASSWORD_1], sk-****1234
  if (/\*{4,}/.test(v) || /^\[[A-Z_]+_\d+\]$/.test(v)) return true
  // Unquoted function call in code: `password = getPassword()`, `os.getenv(`
  if (!quoted && /^[A-Za-z_$][\w$.]*\(/.test(v)) return true
  return false
}

// ── entropy fallback ──────────────────────────────────────────────────────────

const ENTROPY_SKIP_KEY =
  /(?:^|[^a-z])(?:id|uuid|guid|hash|sha\d*|md5|checksum|digest|integrity|etag|commit|revision|rev|version|path|url|uri|href|src|file|dir|host|region|image|name|type|class|style|color|font|lang|locale)$/

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>()
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1)
  let h = 0
  for (const n of freq.values()) {
    const p = n / s.length
    h -= p * Math.log2(p)
  }
  return h
}

/** Heuristic: does this value look like a random machine-generated credential? */
export function looksLikeRandomSecret(value: string): boolean {
  if (value.length < 20 || value.length > 512) return false
  if (/\s/.test(value)) return false
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) return false // URL
  if (/^[./~\\]|[\\/].*[\\/]/.test(value) && !/^[A-Za-z0-9+/]+=*$/.test(value)) return false // path
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return false // UUID
  if (/^(?:sha\d+|md5)-/i.test(value)) return false // lockfile integrity
  if (/^\d+(?:\.\d+)*$/.test(value)) return false
  if (/@/.test(value) && /\.[a-z]{2,}$/i.test(value)) return false // email
  const classes =
    Number(/[a-z]/.test(value)) +
    Number(/[A-Z]/.test(value)) +
    Number(/\d/.test(value)) +
    Number(/[^A-Za-z0-9]/.test(value))
  if (/^[0-9a-f]+$/i.test(value)) return value.length >= 32 && shannonEntropy(value) >= 3.5
  return classes >= 3 && shannonEntropy(value) >= 4.0
}

// ── detector ──────────────────────────────────────────────────────────────────

export class KeyBasedDetector implements Detector {
  readonly id = 'key-based'
  enabled = true
  /** Report high-entropy values under unknown keys (LOW confidence). */
  entropyFallback = true

  /** Additional keywords added at runtime, keyed by normalised form. */
  private extraKeywords: Map<string, { keyword: string; entry: KeywordEntry }> = new Map()

  addKeyword(keyword: string, entry: Omit<KeywordEntry, 'keywords'>) {
    this.extraKeywords.set(normaliseKey(keyword), { keyword, entry: { ...entry, keywords: [keyword] } })
  }

  /** Resolve a key name to its most specific keyword entry, if any. */
  lookup(key: string): { keyword: string; entry: KeywordEntry } | undefined {
    for (const suffix of keySuffixes(key)) {
      const hit = this.extraKeywords.get(suffix) ?? BUILTIN_KEYWORDS.get(suffix)
      if (hit) return hit
    }
    return undefined
  }

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []
    if (!text) return results

    for (const kv of scanKeyValues(text)) {
      if (isNonSecretValue(kv.value, kv.quoted)) continue
      const hit = this.lookup(kv.key)

      if (hit) {
        results.push({
          start: kv.valueStart,
          end: kv.valueEnd,
          category: hit.entry.category,
          ruleId: `key-based:${hit.keyword}`,
          ruleName: `Key: ${hit.keyword}`,
          confidence: hit.entry.confidence,
          line: offsetToLine(text, kv.valueStart),
        })
      } else if (
        this.entropyFallback &&
        !ENTROPY_SKIP_KEY.test(splitKeyWords(kv.key).join(' ')) &&
        looksLikeRandomSecret(kv.value)
      ) {
        results.push({
          start: kv.valueStart,
          end: kv.valueEnd,
          category: 'GENERIC_SECRET',
          ruleId: 'entropy:key-value',
          ruleName: 'High-entropy value',
          confidence: 'LOW',
          line: offsetToLine(text, kv.valueStart),
        })
      }
    }

    return results
  }
}

// Export a singleton for use by the orchestrator
export const keyBasedDetector = new KeyBasedDetector()
