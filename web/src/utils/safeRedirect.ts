/**
 * Validates a redirect path to prevent open redirect attacks.
 * Only allows relative paths on the same origin.
 */
export function safeRedirect(path: string | null | undefined, defaultPath = '/'): string {
  if (!path || typeof path !== 'string') return defaultPath
  // Only allow relative paths — prevent open redirect via protocol-relative URLs or encoded schemes
  if (!path.startsWith('/') || path.startsWith('//') || path.includes('://')) return defaultPath
  try { if (new URL(path, 'http://x').origin !== 'http://x') return defaultPath } catch { return defaultPath }
  return path
}
