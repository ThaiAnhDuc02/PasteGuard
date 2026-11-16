/**
 * Connection String Detector
 *
 * Detects database/service connection strings and redacts only the credential
 * portions (username and password), preserving host, port, dbname, and
 * non-sensitive query parameters.
 *
 * Supported protocols:
 *   postgres / postgresql, mysql, mariadb, mongodb, mongodb+srv,
 *   redis, rediss, sqlserver / mssql, oracle, jdbc:*
 *
 * Also detects query-parameter credentials:
 *   ?password=secret&ssl=true
 *   ?user=admin&password=secret
 */

import type { DetectionResult, Detector } from '../../types/detection'
import { offsetToLine } from '../../types/detection'

// ── URL-style connection strings ──────────────────────────────────────────────
//
// Generic form:  scheme://[user[:password]@]host[:port][/db][?params]
//
// We build one regex that covers all supported schemes.
// Groups:
//   1 – username (may be empty for redis ":password@host")
//   2 – password
//
// We use named groups so we can find offsets cleanly.

const URL_SCHEMES = [
  'postgres(?:ql)?',
  'mysql(?:x)?',
  'mariadb',
  'mongodb(?:\\+srv)?',
  'redis[s]?',
  'sqlserver',
  'mssql',
  'oracle',
  'cockroachdb',
  'clickhouse',
  'cassandra',
  'neo4j(?:\\+s)?',
  'couchdb',
  'amqps?',
  'mqtts?',
  'nats',
  'kafka',
  'ldaps?',
  'smtps?',
  'imaps?',
  'ftps?',
  'sftp',
  'ssh',
  'https?',
  'git\\+https?',
]

// Per RFC 3986 userinfo cannot contain unescaped / ? # — excluding them keeps
// `https://host:8080/path?email=a@b.c` from being misread as user:password.
const URL_CONN_PATTERN = new RegExp(
  `(?<![\\w+.-])(?:${URL_SCHEMES.join('|')}):\\/\\/` + `(?:([^:@/?#\\s]{0,256})?:([^@/?#\\s]{1,2048})@)`,
  'gi',
)

// ── JDBC connection strings ───────────────────────────────────────────────────
//
// jdbc:mysql://host/db?user=u&password=p
// jdbc:postgresql://host/db?password=p
// jdbc:sqlserver://host;user=u;password=p

const JDBC_PATTERN = /jdbc:[a-zA-Z0-9+:-]+:\/\/[^\s;?#]*(?:[?;])([^\s]{1,2048})/gi

// ── Query-parameter credentials ───────────────────────────────────────────────
//
// Matches ?password=value or &password=value (and other sensitive param names).
// Also matches ;password=value (JDBC style).

const SENSITIVE_PARAMS = [
  'password',
  'passwd',
  'pwd',
  'secret',
  'client_secret',
  'token',
  'auth',
  'api_key',
  'apikey',
  'api-key',
  'key',
  'access_token',
  'refresh_token',
  'id_token',
  'session_token',
  'private_token',
  'sig',
  'signature',
  'x-amz-signature',
  'x-amz-security-token',
  'x-goog-signature',
]

const QUERY_PARAM_PATTERN = new RegExp(`[?&;](?:${SENSITIVE_PARAMS.join('|')})=([^&\\s;#"'<>]{1,2048})`, 'gi')

// ── detector ──────────────────────────────────────────────────────────────────

export class ConnectionStringDetector implements Detector {
  readonly id = 'connection-string'
  enabled = true

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []

    this._detectUrlCredentials(text, results)
    this._detectJdbcCredentials(text, results)
    this._detectQueryParams(text, results)

    return results
  }

  private _detectUrlCredentials(text: string, out: DetectionResult[]): void {
    const pattern = new RegExp(URL_CONN_PATTERN.source, URL_CONN_PATTERN.flags)
    let match: RegExpExecArray | null

    while ((match = pattern.exec(text)) !== null) {
      const fullMatch = match[0]
      const username = match[1] // may be undefined for redis :pass@
      const password = match[2]

      if (!password || password.length < 1) continue

      const matchStart = match.index

      // Locate password offset
      const passwordOffset = matchStart + fullMatch.lastIndexOf(':' + password) + 1
      out.push({
        start: passwordOffset,
        end: passwordOffset + password.length,
        category: 'CONNECTION_STRING',
        ruleId: 'conn-str:url-password',
        ruleName: 'Connection String Password',
        confidence: 'HIGH',
        line: offsetToLine(text, passwordOffset),
      })

      // Locate username offset (only if non-empty and not a typical host/port)
      if (username && username.length >= 1 && !/^\d+$/.test(username)) {
        // The username appears right after "://"
        const afterScheme = fullMatch.indexOf('://') + 3
        const usernameOffset = matchStart + afterScheme
        out.push({
          start: usernameOffset,
          end: usernameOffset + username.length,
          category: 'USERNAME',
          ruleId: 'conn-str:url-username',
          ruleName: 'Connection String Username',
          confidence: 'HIGH',
          line: offsetToLine(text, usernameOffset),
        })
      }

      if (fullMatch.length === 0) pattern.lastIndex++
    }
  }

  private _detectJdbcCredentials(text: string, out: DetectionResult[]): void {
    const pattern = new RegExp(JDBC_PATTERN.source, JDBC_PATTERN.flags)
    let match: RegExpExecArray | null

    while ((match = pattern.exec(text)) !== null) {
      const params = match[1]
      if (!params) continue

      // Now scan the params string for sensitive param=value pairs
      const paramPattern = new RegExp(QUERY_PARAM_PATTERN.source, 'gi')
      const paramsStart = match.index + match[0].indexOf(params)
      let paramMatch: RegExpExecArray | null

      while ((paramMatch = paramPattern.exec(params)) !== null) {
        const value = paramMatch[1]
        if (!value || value.length < 1) continue

        const valueOffset = paramsStart + paramMatch.index + paramMatch[0].lastIndexOf(value)
        out.push({
          start: valueOffset,
          end: valueOffset + value.length,
          category: 'CONNECTION_STRING',
          ruleId: 'conn-str:jdbc-param',
          ruleName: 'JDBC Connection Credential',
          confidence: 'HIGH',
          line: offsetToLine(text, valueOffset),
        })
        if (paramMatch[0].length === 0) paramPattern.lastIndex++
      }

      if (match[0].length === 0) pattern.lastIndex++
    }
  }

  private _detectQueryParams(text: string, out: DetectionResult[]): void {
    // Skip lines that already look like JDBC (avoid double-counting)
    const pattern = new RegExp(QUERY_PARAM_PATTERN.source, QUERY_PARAM_PATTERN.flags)
    let match: RegExpExecArray | null

    while ((match = pattern.exec(text)) !== null) {
      const value = match[1]
      if (!value || value.length < 1) continue

      const valueOffset = match.index + match[0].lastIndexOf(value)
      out.push({
        start: valueOffset,
        end: valueOffset + value.length,
        category: 'CONNECTION_STRING',
        ruleId: 'conn-str:query-param',
        ruleName: 'Query Parameter Credential',
        confidence: 'MEDIUM',
        line: offsetToLine(text, valueOffset),
      })

      if (match[0].length === 0) pattern.lastIndex++
    }
  }
}

export const connectionStringDetector = new ConnectionStringDetector()
