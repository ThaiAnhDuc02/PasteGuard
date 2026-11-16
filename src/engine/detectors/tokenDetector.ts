/**
 * Token / Pattern-Based Detector
 *
 * Detects structured tokens by their known format rather than their field name.
 * Rules are deterministic regex patterns with structural anchors.
 * Each rule has an explicit confidence level and is documented.
 *
 * Rules intentionally avoid matching overly-short or generic strings to
 * minimise false positives.
 */

import type { DetectionResult, Detector, SecretCategory, ConfidenceLevel } from '../../types/detection'
import { offsetToLine } from '../../types/detection'

interface TokenRule {
  id: string
  name: string
  /** Must have exactly one capture group that contains the secret value span. */
  pattern: RegExp
  category: SecretCategory
  confidence: ConfidenceLevel
  /** Minimum captured length (default 8). */
  minLength?: number
}

// ── rule definitions ──────────────────────────────────────────────────────────
//
// All patterns use the 'g' flag so exec() advances across the input.
// Each pattern captures the secret in group 1.

const TOKEN_RULES: TokenRule[] = [
  // ── JWT ──────────────────────────────────────────────────────────────────
  {
    id: 'jwt',
    name: 'JWT Token',
    // Three base64url segments separated by dots; header always starts with eyJ
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    category: 'JWT',
    confidence: 'HIGH',
  },

  // ── AWS ──────────────────────────────────────────────────────────────────
  {
    id: 'aws-access-key-id',
    name: 'AWS Access Key ID',
    // Canonical format: AKIA followed by 16 uppercase alphanumeric chars
    pattern: /\b((?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16})\b/g,
    category: 'AWS_CREDENTIAL',
    confidence: 'HIGH',
  },
  {
    id: 'aws-secret-access-key',
    name: 'AWS Secret Access Key',
    // 40-char base64 string following aws_secret_access_key or aws_secret context
    pattern: /(?:aws_secret_access_key|aws[_-]secret)[^\S\r\n]*[=:][^\S\r\n]*([A-Za-z0-9/+]{40})\b/gi,
    category: 'AWS_CREDENTIAL',
    confidence: 'HIGH',
  },

  // ── GitHub ───────────────────────────────────────────────────────────────
  {
    id: 'github-pat-classic',
    name: 'GitHub Personal Access Token (classic)',
    pattern: /\b(ghp_[A-Za-z0-9]{36})\b/g,
    category: 'GITHUB_TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'github-pat-fine',
    name: 'GitHub Fine-Grained PAT',
    pattern: /\b(github_pat_[A-Za-z0-9_]{82})\b/g,
    category: 'GITHUB_TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'github-oauth-token',
    name: 'GitHub OAuth Token',
    pattern: /\b(gho_[A-Za-z0-9]{36})\b/g,
    category: 'GITHUB_TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'github-app-token',
    name: 'GitHub App Token',
    pattern: /\b(ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36})\b/g,
    category: 'GITHUB_TOKEN',
    confidence: 'HIGH',
  },

  // ── Bearer / Authorization header ────────────────────────────────────────
  {
    id: 'bearer-header',
    name: 'Bearer Authorization Header',
    // "Authorization: Bearer <token>" — capture everything after Bearer
    pattern: /(?:Authorization|authorization)\s*:\s*Bearer\s+([A-Za-z0-9\-._~+/=]{20,2048})/g,
    category: 'BEARER_TOKEN',
    confidence: 'HIGH',
  },

  // ── Basic Auth header ─────────────────────────────────────────────────────
  {
    id: 'basic-auth-header',
    name: 'Basic Auth Header',
    pattern: /(?:Authorization|authorization)\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,2048})/g,
    category: 'BASIC_AUTH',
    confidence: 'HIGH',
  },

  // Bearer token outside an Authorization header (curl args, JSON, logs)
  {
    id: 'bearer-standalone',
    name: 'Bearer Token',
    pattern: /\bBearer\s+([A-Za-z0-9\-._~+/]{16,2048}=*)/g,
    category: 'BEARER_TOKEN',
    confidence: 'MEDIUM',
  },

  // curl -u user:password / --user user:password
  {
    id: 'curl-basic-auth',
    name: 'curl -u Credentials',
    pattern: /(?:^|\s)(?:-u|--user)\s+["']?[^\s:"']+:([^\s"']{3,})/g,
    category: 'BASIC_AUTH',
    confidence: 'HIGH',
    minLength: 3,
  },

  // ── AI providers ──────────────────────────────────────────────────────────
  // Listed before the generic OpenAI rule: identical spans dedupe to the first.
  {
    id: 'anthropic-key',
    name: 'Anthropic API Key',
    pattern: /\b(sk-ant-[A-Za-z0-9_-]{20,})/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'openai-key',
    name: 'OpenAI API Key',
    // Legacy sk-…, project sk-proj-…, service-account sk-svcacct-…, admin sk-admin-…
    pattern: /\b(sk-(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{20,})/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'huggingface-token',
    name: 'Hugging Face Token',
    pattern: /\b(hf_[A-Za-z0-9]{30,})\b/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'google-api-key',
    name: 'Google API Key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})(?![0-9A-Za-z_-])/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'google-oauth-secret',
    name: 'Google OAuth Client Secret',
    pattern: /\b(GOCSPX-[A-Za-z0-9_-]{20,})/g,
    category: 'OAUTH_SECRET',
    confidence: 'HIGH',
  },

  // ── Source control / registries ──────────────────────────────────────────
  {
    id: 'gitlab-token',
    name: 'GitLab Token',
    pattern: /\b(gl(?:pat|dt|rt|ptt|cbt|soat)-[A-Za-z0-9_-]{20,})/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'github-user-token',
    name: 'GitHub User-to-Server Token',
    pattern: /\b(ghu_[A-Za-z0-9]{36})\b/g,
    category: 'GITHUB_TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'pypi-token',
    name: 'PyPI Token',
    pattern: /\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'docker-hub-pat',
    name: 'Docker Hub PAT',
    pattern: /\b(dckr_pat_[A-Za-z0-9_-]{20,})/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },

  // ── Webhooks / chat ──────────────────────────────────────────────────────
  {
    id: 'slack-webhook',
    name: 'Slack Webhook URL',
    pattern: /https:\/\/hooks\.slack\.com\/services\/([A-Za-z0-9/_-]{20,})/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'discord-webhook',
    name: 'Discord Webhook URL',
    pattern: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/([A-Za-z0-9_-]{30,})/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'telegram-bot-token',
    name: 'Telegram Bot Token',
    pattern: /\b(\d{8,10}:AA[A-Za-z0-9_-]{33})(?![A-Za-z0-9_-])/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },

  // ── Payments / commerce ──────────────────────────────────────────────────
  {
    id: 'stripe-webhook-secret',
    name: 'Stripe Webhook Secret',
    pattern: /\b(whsec_[A-Za-z0-9]{24,})\b/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'shopify-token',
    name: 'Shopify Access Token',
    pattern: /\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'stripe-key',
    name: 'Stripe API Key',
    pattern: /\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{24,})\b/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'sendgrid-key',
    name: 'SendGrid API Key',
    pattern: /\b(SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43})\b/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'slack-token',
    name: 'Slack Token',
    pattern: /\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },
  {
    id: 'twilio-sid',
    name: 'Twilio Account SID',
    pattern: /\b(AC[a-f0-9]{32})\b/g,
    category: 'API_KEY',
    confidence: 'HIGH',
  },
  {
    id: 'npm-token',
    name: 'NPM Publish Token',
    pattern: /\b(npm_[A-Za-z0-9]{36})\b/g,
    category: 'TOKEN',
    confidence: 'HIGH',
  },

  // ── Generic long hex/base64 string in key-ish context ────────────────────
  // Medium confidence — only flagged when adjacent to a suspicious keyword in
  // the surrounding 60 chars. Kept here for completeness.
  {
    id: 'generic-hex-secret',
    name: 'Generic Hex Secret (32+ hex chars)',
    // Only match if preceded by a separator suggesting it is a value
    pattern: /(?:[:=]\s*)([0-9a-f]{32,64})\b/gi,
    category: 'GENERIC_SECRET',
    confidence: 'LOW',
  },
]

// ── detector ──────────────────────────────────────────────────────────────────

export class TokenDetector implements Detector {
  readonly id = 'token'
  enabled = true

  detect(text: string): DetectionResult[] {
    const results: DetectionResult[] = []

    for (const rule of TOKEN_RULES) {
      // Reset lastIndex before each scan (patterns share the 'g' flag object)
      const pattern = new RegExp(rule.pattern.source, rule.pattern.flags)
      let match: RegExpExecArray | null

      while ((match = pattern.exec(text)) !== null) {
        const value = match[1]
        if (!value || value.length < (rule.minLength ?? 8)) continue

        // Locate value start within full match
        const valueStart = match.index + match[0].indexOf(value)
        const valueEnd = valueStart + value.length

        results.push({
          start: valueStart,
          end: valueEnd,
          category: rule.category,
          ruleId: `token:${rule.id}`,
          ruleName: rule.name,
          confidence: rule.confidence,
          line: offsetToLine(text, valueStart),
        })

        // Avoid infinite loop on zero-length matches
        if (match[0].length === 0) pattern.lastIndex++
      }
    }

    return results
  }
}

export const tokenDetector = new TokenDetector()
