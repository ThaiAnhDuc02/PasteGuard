/**
 * Clipboard utilities
 * Uses the modern Clipboard API with a textarea fallback for older browsers.
 */

export async function copyToClipboard(text: string): Promise<void> {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  // Fallback: create an off-screen textarea
  const el = document.createElement('textarea')
  el.value = text
  el.style.cssText = 'position:fixed;left:-9999px;top:-9999px'
  document.body.appendChild(el)
  el.focus()
  el.select()
  try {
    document.execCommand('copy')
  } finally {
    document.body.removeChild(el)
  }
}
