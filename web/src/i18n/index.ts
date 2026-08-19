import type { LocaleMessages } from '@vault42/vue'

/**
 * The shipped locale catalogues, one lazily loaded chunk each.
 *
 * They used to be 38 static imports. `src/locales` is 844 KB, so every visitor
 * downloaded every language to render one, and because the login view is this
 * app's cold start that cost sat on the critical path before a password could be
 * typed. It was the bulk of an 895 kB entry chunk.
 *
 * `import.meta.glob` gives Rollup one dynamic import per file, so it emits one
 * chunk per locale and the entry carries none of them.
 */
const loaders = import.meta.glob<{ default: LocaleMessages }>('../locales/*.json')

function localeOf(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1, -'.json'.length)
}

/** Every locale that has a catalogue, whether or not it has been fetched yet. */
export const availableLocales: string[] = Object.keys(loaders).map(localeOf).sort()

/**
 * The catalogues handed to `createI18nPlugin`.
 *
 * Every locale is present from the start, initially empty. That is load-bearing
 * twice over: `createI18n` snapshots `Object.keys(messages)` into its own
 * `availableLocales` at construction, so a locale absent here could never appear
 * in the switcher, and its `setLocale` refuses any locale with no entry. An
 * empty catalogue resolves through the `en` fallback, and `t()` re-reads
 * `messages[locale]` on every call, so replacing an entry before that locale
 * becomes active is enough — {@link loadLocale} does exactly that.
 */
export const messages: Record<string, LocaleMessages> = Object.fromEntries(
  availableLocales.map(locale => [locale, {} as LocaleMessages]),
)

const loaded = new Set<string>()

/**
 * Fetches a locale's catalogue and installs it into {@link messages}.
 *
 * Idempotent, and safe to call for a locale that does not exist: it resolves
 * `false` rather than throwing, so a stale `vault42-locale` in localStorage or a
 * hand-typed tag cannot break startup.
 *
 * Await it *before* switching the active locale. Installing a catalogue is a
 * plain property write on a non-reactive object and re-renders nothing by
 * itself; the render is driven by the locale ref changing afterwards.
 *
 * @param locale - A tag from {@link availableLocales}.
 * @returns Whether a catalogue is now installed for that locale.
 */
export async function loadLocale(locale: string): Promise<boolean> {
  if (loaded.has(locale)) return true

  const load = loaders[`../locales/${locale}.json`]
  if (!load) return false

  messages[locale] = (await load()).default
  loaded.add(locale)
  return true
}

export { detectLocale } from './detection'
export { applyDocumentLocale, isRTL } from './documentLocale'
