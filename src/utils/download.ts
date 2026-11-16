/**
 * Download utilities
 * Triggers a browser file-save without any server round-trip.
 */

export function downloadText(content: string, filename: string, mimeType = 'text/plain'): void {
  const blob = new Blob([content], { type: `${mimeType};charset=utf-8` })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  // Revoke after a short delay to allow the download to start
  setTimeout(() => {
    URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }, 100)
}

export function getDownloadFilename(format: string): string {
  const ext: Record<string, string> = {
    JSON: 'json',
    YAML: 'yaml',
    XML: 'xml',
    SQL: 'sql',
    ENV: 'env',
    SHELL: 'sh',
    DOCKER: 'dockerfile',
    KUBERNETES: 'yaml',
    LOG: 'log',
    HTTP_HEADERS: 'txt',
    SOURCE_CODE: 'txt',
    PLAIN_TEXT: 'txt',
    AUTO: 'txt',
  }
  const extension = ext[format] ?? 'txt'
  const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)
  return `masked-${ts}.${extension}`
}
