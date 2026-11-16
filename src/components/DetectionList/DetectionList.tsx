import { type FC, useState } from 'react'
import type { DetectionResult, SecretCategory, ConfidenceLevel } from '../../types/detection'

interface DetectionListProps {
  detections: DetectionResult[]
  hasRun: boolean
}

const CONFIDENCE_BADGE: Record<ConfidenceLevel, string> = {
  HIGH: 'badge-red',
  MEDIUM: 'badge-yellow',
  LOW: 'badge-gray',
}

const CATEGORY_ICON: Partial<Record<SecretCategory, string>> = {
  PASSWORD: '🔑',
  USERNAME: '👤',
  API_KEY: '🗝️',
  TOKEN: '🎟️',
  CONNECTION_STRING: '🔗',
  PRIVATE_KEY: '🔐',
  BEARER_TOKEN: '🔑',
  BASIC_AUTH: '🔒',
  AWS_CREDENTIAL: '☁️',
  GITHUB_TOKEN: '🐙',
  JWT: '📛',
  OAUTH_SECRET: '🔓',
  GENERIC_SECRET: '⚠️',
  CUSTOM: '🔧',
}

const PAGE_SIZE = 50

const DetectionList: FC<DetectionListProps> = ({ detections, hasRun }) => {
  const [page, setPage] = useState(0)

  if (!hasRun || detections.length === 0) return null

  const totalPages = Math.ceil(detections.length / PAGE_SIZE)
  const pageItems = detections.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div className="bg-gray-900/60 border-t border-gray-700/60">
      <div className="px-4 py-2 flex items-center justify-between border-b border-gray-700/40">
        <span className="text-xs font-medium text-gray-400 uppercase tracking-wider">
          Detection Details
          <span className="ml-1.5 text-gray-500 normal-case font-normal">
            ({detections.length} {detections.length === 1 ? 'finding' : 'findings'})
          </span>
        </span>
        {totalPages > 1 && (
          <div className="flex items-center gap-1 text-xs text-gray-500">
            <button
              onClick={() => setPage(p => Math.max(0, p - 1))}
              disabled={page === 0}
              className="px-1.5 py-0.5 rounded hover:bg-gray-700 disabled:opacity-30 transition-colors"
            >
              ‹
            </button>
            <span>
              {page + 1} / {totalPages}
            </span>
            <button
              onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
              disabled={page === totalPages - 1}
              className="px-1.5 py-0.5 rounded hover:bg-gray-700 disabled:opacity-30 transition-colors"
            >
              ›
            </button>
          </div>
        )}
      </div>

      <div className="overflow-x-auto max-h-48 overflow-y-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900">
            <tr className="text-gray-500 uppercase tracking-wide">
              <th className="text-left px-4 py-1.5 font-medium">Category</th>
              <th className="text-left px-4 py-1.5 font-medium">Line</th>
              <th className="text-left px-4 py-1.5 font-medium">Rule</th>
              <th className="text-left px-4 py-1.5 font-medium">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/60">
            {pageItems.map((d, idx) => (
              <tr key={`${d.start}-${d.end}-${idx}`} className="hover:bg-gray-800/40 transition-colors">
                <td className="px-4 py-1.5">
                  <span className="flex items-center gap-1.5 text-gray-300">
                    <span aria-hidden>{CATEGORY_ICON[d.category] ?? '•'}</span>
                    {d.category.replace(/_/g, ' ')}
                    {d.isCustom && <span className="badge badge-blue text-xs py-0">custom</span>}
                  </span>
                </td>
                <td className="px-4 py-1.5 font-mono text-gray-400 tabular-nums">{d.line}</td>
                <td className="px-4 py-1.5 text-gray-400 max-w-xs truncate" title={d.ruleName}>
                  {d.ruleName}
                </td>
                <td className="px-4 py-1.5">
                  <span className={`${CONFIDENCE_BADGE[d.confidence]}`}>{d.confidence}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default DetectionList
