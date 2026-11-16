import type { FC } from 'react'
import type { DetectionSummary as DSummary, SecretCategory } from '../../types/detection'

interface DetectionSummaryProps {
  summary: DSummary
  hasRun: boolean
}

const CATEGORY_META: Record<SecretCategory, { label: string; color: string; icon: string }> = {
  PASSWORD: { label: 'Passwords', color: 'badge-red', icon: '🔑' },
  USERNAME: { label: 'Usernames', color: 'badge-yellow', icon: '👤' },
  API_KEY: { label: 'API Keys', color: 'badge-red', icon: '🗝️' },
  TOKEN: { label: 'Tokens', color: 'badge-red', icon: '🎟️' },
  CONNECTION_STRING: { label: 'Conn. Strings', color: 'badge-red', icon: '🔗' },
  PRIVATE_KEY: { label: 'Private Keys', color: 'badge-red', icon: '🔐' },
  BEARER_TOKEN: { label: 'Bearer Tokens', color: 'badge-red', icon: '🔑' },
  BASIC_AUTH: { label: 'Basic Auth', color: 'badge-yellow', icon: '🔒' },
  AWS_CREDENTIAL: { label: 'AWS Credentials', color: 'badge-red', icon: '☁️' },
  GITHUB_TOKEN: { label: 'GitHub Tokens', color: 'badge-blue', icon: '🐙' },
  JWT: { label: 'JWTs', color: 'badge-yellow', icon: '📛' },
  OAUTH_SECRET: { label: 'OAuth Secrets', color: 'badge-red', icon: '🔓' },
  GENERIC_SECRET: { label: 'Generic Secrets', color: 'badge-yellow', icon: '⚠️' },
  CUSTOM: { label: 'Custom Rules', color: 'badge-blue', icon: '🔧' },
}

const DetectionSummary: FC<DetectionSummaryProps> = ({ summary, hasRun }) => {
  if (!hasRun) return null

  const categories = Object.entries(summary.byCategory) as [SecretCategory, number][]
  categories.sort((a, b) => b[1] - a[1])

  return (
    <div className="bg-gray-800/60 border-b border-gray-700/60 px-4 py-3">
      {/* Total count row */}
      <div className="flex items-center gap-3 mb-2">
        {summary.total === 0 ? (
          <div className="flex items-center gap-2 text-green-400">
            <span>✅</span>
            <span className="text-sm font-medium">No secrets detected</span>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-red-400">
            <span>⚠️</span>
            <span className="text-sm font-semibold">
              {summary.total} secret{summary.total !== 1 ? 's' : ''} detected and masked
            </span>
          </div>
        )}

        {summary.hasLowConfidence && (
          <span className="badge badge-yellow text-xs">⚠ Low-confidence matches — review output</span>
        )}
      </div>

      {/* Category breakdown */}
      {categories.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {categories.map(([cat, count]) => {
            const meta = CATEGORY_META[cat]
            return (
              <span key={cat} className={`${meta.color} flex items-center gap-1`}>
                <span aria-hidden>{meta.icon}</span>
                {count} {meta.label}
              </span>
            )
          })}
        </div>
      )}

      {/* Disclaimer */}
      <p className="mt-2 text-xs text-gray-500 italic">
        PasteGuard uses deterministic detection rules. Some sensitive values may not be detected. Review
        sanitized output before sharing.
      </p>
    </div>
  )
}

export default DetectionSummary
