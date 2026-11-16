/**
 * Text utilities
 */

/** Truncate a string for display (never expose full secrets in the UI). */
export function truncate(s: string, maxLen = 60): string {
  if (s.length <= maxLen) return s
  return s.slice(0, maxLen - 1) + '…'
}

/** Format a byte count as a human-readable string. */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

/** Count lines in a string. */
export function countLines(text: string): number {
  if (!text) return 0
  let count = 1
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') count++
  }
  return count
}

/** Pluralise a word. */
export function plural(count: number, word: string, plural = `${word}s`): string {
  return count === 1 ? word : plural
}
