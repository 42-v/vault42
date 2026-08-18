/**
 * Language subtags whose scripts run right to left.
 *
 * Only `ar` and `he` ship a catalogue today; the rest are here so adding one of
 * them is a locale file and nothing else. Matching is on the primary subtag, so
 * `ar-EG` and `zh-Hans` both resolve correctly.
 */
const RTL_LANGUAGES = new Set(['ar', 'fa', 'he', 'ps', 'ur', 'yi'])

/** Whether a BCP-47 tag names a right-to-left language. */
export function isRTL(locale: string): boolean {
  return RTL_LANGUAGES.has(locale.split('-')[0].toLowerCase())
}

/**
 * Publishes the active locale on `<html>`.
 *
 * `web/index.html` hardcodes `lang="en"` and nothing ever changed it, across 39
 * locales including two right-to-left ones. That is two separate failures:
 * screen readers applied English pronunciation to every translated string
 * (WCAG 3.1.1 and 3.1.2), and Arabic and Hebrew rendered left to right, which
 * mis-orders any string mixing script and digits — one-time codes, quota
 * figures and dates, all of which this dashboard shows.
 *
 * Called at startup and again on every switch, so the attribute tracks the
 * locale rather than the page load.
 *
 * @param locale - The BCP-47 tag now active.
 * @param root - The element to stamp. Defaults to `document.documentElement`.
 */
export function applyDocumentLocale(locale: string, root: HTMLElement = document.documentElement): void {
  root.lang = locale
  root.dir = isRTL(locale) ? 'rtl' : 'ltr'
}
