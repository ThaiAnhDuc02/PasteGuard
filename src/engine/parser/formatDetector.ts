/**
 * Heuristic format detector.
 * Returns the most likely InputFormat for a text sample.
 * Never throws — always returns a usable format.
 */
import type { InputFormat } from '../../types/detection'

interface FormatScore {
  format: InputFormat
  score: number
}

/** Sniff the first `limit` characters for performance on huge inputs. */
const SNIFF_LIMIT = 4096

export function detectFormat(text: string): InputFormat {
  const sample = text.slice(0, SNIFF_LIMIT).trimStart()
  if (!sample) return 'PLAIN_TEXT'

  const scores: FormatScore[] = [
    { format: 'JSON', score: scoreJson(sample) },
    { format: 'YAML', score: scoreYaml(sample) },
    { format: 'XML', score: scoreXml(sample) },
    { format: 'SQL', score: scoreSql(sample) },
    { format: 'ENV', score: scoreEnv(sample) },
    { format: 'SHELL', score: scoreShell(sample) },
    { format: 'DOCKER', score: scoreDocker(sample) },
    { format: 'KUBERNETES', score: scoreKubernetes(sample) },
    { format: 'LOG', score: scoreLog(sample) },
    { format: 'HTTP_HEADERS', score: scoreHttpHeaders(sample) },
    { format: 'SOURCE_CODE', score: scoreSourceCode(sample) },
  ]

  const best = scores.reduce((a, b) => (b.score > a.score ? b : a))
  return best.score >= 2 ? best.format : 'PLAIN_TEXT'
}

/** Map InputFormat to Monaco language identifier. */
export function formatToMonacoLanguage(format: InputFormat): string {
  const map: Partial<Record<InputFormat, string>> = {
    JSON: 'json',
    YAML: 'yaml',
    XML: 'xml',
    SQL: 'sql',
    ENV: 'ini',
    SHELL: 'shell',
    DOCKER: 'dockerfile',
    KUBERNETES: 'yaml',
    LOG: 'plaintext',
    HTTP_HEADERS: 'plaintext',
    SOURCE_CODE: 'typescript',
    PLAIN_TEXT: 'plaintext',
    AUTO: 'plaintext',
  }
  return map[format] ?? 'plaintext'
}

// ── scorers ──────────────────────────────────────────────────────────────────

function scoreJson(s: string): number {
  let score = 0
  if (/^\s*[\[{]/.test(s)) score += 3
  if (/"[^"]+"\s*:/.test(s)) score += 3
  if (/:\s*(?:"[^"]*"|true|false|null|\d+)/.test(s)) score += 2
  try {
    JSON.parse(s.length < SNIFF_LIMIT ? s : s + '...') // just see if it parses
  } catch {
    // partial parse failure is expected for snipped text
  }
  return score
}

function scoreYaml(s: string): number {
  let score = 0
  if (/^---/.test(s)) score += 4
  if (/^[a-zA-Z_][\w-]*\s*:/m.test(s)) score += 3
  if (/^\s+-\s+\S/m.test(s)) score += 2
  if (/:\s*\|/.test(s)) score += 1 // block scalar
  // JSON also has colons — penalise if it looks like JSON
  if (/^\s*[\[{]/.test(s)) score -= 3
  return score
}

function scoreXml(s: string): number {
  let score = 0
  if (/^<\?xml/.test(s)) score += 5
  if (/<[a-zA-Z][\w:-]*[\s>]/.test(s)) score += 3
  if (/<\/[a-zA-Z][\w:-]*>/.test(s)) score += 3
  if (/<!--/.test(s)) score += 1
  return score
}

function scoreSql(s: string): number {
  let score = 0
  const upper = s.toUpperCase()
  for (const kw of [
    'SELECT',
    'INSERT',
    'UPDATE',
    'DELETE',
    'CREATE TABLE',
    'DROP',
    'ALTER',
    'FROM',
    'WHERE',
    'JOIN',
  ]) {
    if (upper.includes(kw)) score += 2
  }
  if (/;\s*$/.test(s.trimEnd())) score += 1
  return score
}

function scoreEnv(s: string): number {
  let score = 0
  const lines = s.split('\n').slice(0, 20)
  let envLines = 0
  for (const line of lines) {
    if (/^[A-Z][A-Z0-9_]*=/.test(line.trim())) envLines++
    if (/^#/.test(line.trim())) score += 0.5
  }
  score += envLines * 2
  return score
}

function scoreShell(s: string): number {
  let score = 0
  if (/^#!/.test(s)) score += 4
  if (/\b(export|source|echo|curl|wget|chmod|chown|mkdir|rm|ls|cd|grep|awk|sed)\b/.test(s)) score += 3
  if (/\$\{?\w+\}?/.test(s)) score += 2
  if (/&&|\|\|/.test(s)) score += 1
  return score
}

function scoreDocker(s: string): number {
  let score = 0
  if (/^FROM\s+\S/m.test(s)) score += 5
  if (/^(RUN|CMD|ENTRYPOINT|COPY|ADD|ENV|EXPOSE|WORKDIR|ARG|LABEL|USER|VOLUME|HEALTHCHECK|SHELL)\s/m.test(s))
    score += 3
  if (/docker[\s-]?compose/i.test(s)) score += 2
  return score
}

function scoreKubernetes(s: string): number {
  let score = 0
  if (/^apiVersion:/m.test(s)) score += 5
  if (/^kind:\s*(Deployment|Service|Pod|ConfigMap|Secret|Ingress|StatefulSet|DaemonSet|Job|CronJob)/m.test(s))
    score += 5
  if (/^metadata:/m.test(s)) score += 2
  if (/^spec:/m.test(s)) score += 2
  return score
}

function scoreLog(s: string): number {
  let score = 0
  // ISO timestamps
  if (/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}/.test(s)) score += 3
  // Log levels
  if (/\b(ERROR|WARN|INFO|DEBUG|TRACE|FATAL)\b/.test(s)) score += 3
  // Common log prefixes
  if (/^\[?\d{4}-\d{2}-\d{2}/m.test(s)) score += 2
  return score
}

function scoreHttpHeaders(s: string): number {
  let score = 0
  if (/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\//.test(s)) score += 4
  if (/^HTTP\/[12]/.test(s)) score += 4
  if (/^(Authorization|Content-Type|Accept|Host|User-Agent|X-[A-Za-z-]+):/m.test(s)) score += 3
  if (/^[A-Za-z][\w-]+:\s+\S/m.test(s)) score += 1
  return score
}

function scoreSourceCode(s: string): number {
  let score = 0
  if (/^(import|export|const|let|var|function|class|interface|type|enum)\s/m.test(s)) score += 3
  if (/^(def|class|import|from|if __name__)/m.test(s)) score += 3 // Python
  if (/^(public|private|protected|static|void|int|string)\s/m.test(s)) score += 2 // Java/C#
  if (/\/\/|\/\*|\*\//.test(s)) score += 1
  if (/\{|\}|\(|\)/.test(s)) score += 1
  return score
}
