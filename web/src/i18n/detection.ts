export function detectLocale(available: string[], fallback: string): string {
  // 1. Check localStorage override
  const stored = localStorage.getItem('vault42-locale')
  if (stored && available.includes(stored)) return stored

  // 2. Check navigator.languages
  for (const lang of navigator.languages ?? [navigator.language]) {
    const exact = available.find(a => a === lang)
    if (exact) return exact
    const prefix = lang.split('-')[0]
    const partial = available.find(a => a === prefix || a.startsWith(prefix + '-'))
    if (partial) return partial
  }

  return fallback
}
