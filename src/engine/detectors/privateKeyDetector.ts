/**
 * Private Key Detector
 *
 * Detects PEM-encoded private key blocks and similar credential blocks that
 * appear verbatim in text.
 *
 * Supported block types:
 *   Any "… PRIVATE KEY" label (RSA, EC, DSA, OPENSSH, ENCRYPTED, PKCS#8, …)
 *   PGP PRIVATE KEY BLOCK
 *   CERTIFICATE  (not secret per se, but often pasted alongside keys)
 *   PuTTY .ppk private key files
 *
 * The entire block from -----BEGIN … to -----END … is captured as one result.
 * This prevents the redaction engine from leaving key fragments visible.
 *
 * Fail-closed: a BEGIN header without its END footer (a truncated paste) is
 * still redacted — from the header through every following line that looks
 * like key material (base64, PEM headers such as `Proc-Type:`), so the body
 * never leaks. PEM embedded in JSON with literal `\n` escapes is handled too.
 */

import type { DetectionResult, Detector } from '../../types/detection'
import { offsetToLine } from '../../types/detection'

const LABEL = String.raw`((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?|CERTIFICATE)`

// BEGIN header; the matching END is located with indexOf (see detect()).
const BEGIN_HEADER = new RegExp(String.raw`-----BEGIN ${LABEL}-----`, 'g')

// Unterminated private block: header + following lines that are entirely key
// material — a base64 run, a PEM header (`Proc-Type: 4,ENCRYPTED`,
// `DEK-Info: …`) or blank. Line breaks may be real or literal `\n` escapes.
const NL = String.raw`(?:\r?\n|\\[nr])`
const OPEN_BLOCK = new RegExp(
  String.raw`-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----` +
    String.raw`(?:${NL}[ \t]*(?:[A-Za-z0-9+/=]{4,}|[A-Za-z-]+: [^\r\n\\]*)?(?=[ \t]*(?:${NL}|$)))*`,
  'g',
)

// PuTTY private key file (.ppk): from the header to the Private-MAC line
const PUTTY_KEY = /PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC:\s*[0-9a-fA-F]+/g

export class PrivateKeyDetector implements Detector {
  readonly id = 'private-key'
  enabled = true

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []
    if (!text.includes('-----BEGIN') && !text.includes('PuTTY-User-Key-File')) return results

    const covered: Array<[number, number]> = []
    const push = (start: number, end: number, label: string, ruleSuffix = '') => {
      covered.push([start, end])
      results.push({
        start,
        end,
        category: 'PRIVATE_KEY',
        ruleId: `private-key:${label.toLowerCase().replace(/\s+/g, '-')}${ruleSuffix}`,
        ruleName: `PEM Block: ${label}${ruleSuffix ? ' (unterminated)' : ''}`,
        confidence: 'HIGH',
        line: offsetToLine(text, start),
      })
    }

    // 1. Complete blocks — linear scan: for each BEGIN find the next matching
    //    END with indexOf, remembering the last END position per label so many
    //    headers without a footer cannot make this quadratic.
    const header = new RegExp(BEGIN_HEADER.source, BEGIN_HEADER.flags)
    const nextEnd = new Map<string, number>() // label → END index (-1 = none)
    let m: RegExpExecArray | null
    while ((m = header.exec(text)) !== null) {
      const start = m.index
      if (covered.some(([s, e]) => start >= s && start < e)) continue
      const label = m[1]
      const endMarker = `-----END ${label}-----`
      let endIdx = nextEnd.get(label)
      if (endIdx === undefined || (endIdx !== -1 && endIdx < start)) {
        endIdx = text.indexOf(endMarker, header.lastIndex)
        nextEnd.set(label, endIdx)
      }
      if (endIdx === -1) continue
      const end = endIdx + endMarker.length
      if (end - start < 64) continue // must have some body
      push(start, end, label)
      header.lastIndex = end
    }

    // 2. Unterminated private-key headers not inside a complete block
    const open = new RegExp(OPEN_BLOCK.source, OPEN_BLOCK.flags)
    while ((m = open.exec(text)) !== null) {
      const start = m.index
      if (covered.some(([s, e]) => start >= s && start < e)) continue
      const end = start + m[0].trimEnd().length
      push(start, end, m[1], ':unterminated')
    }

    // 3. PuTTY keys
    const putty = new RegExp(PUTTY_KEY.source, PUTTY_KEY.flags)
    while ((m = putty.exec(text)) !== null) {
      push(m.index, m.index + m[0].length, 'PUTTY PRIVATE KEY')
    }

    return results
  }
}

export const privateKeyDetector = new PrivateKeyDetector()
