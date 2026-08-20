/**
 * Validates a redirect target that came from untrusted input — a query string, a
 * URL fragment, a postMessage — before it is handed to the router.
 *
 * The validator is allowlist-shaped and fails closed: a value is returned only
 * when it is provably a same-origin, relative, ASCII, dot-segment-free path.
 * Everything else collapses to `defaultPath`. Callers may pass the return value
 * straight to `router.push` / `router.replace` without further checks.
 *
 * Deliberate decisions:
 *
 *   Fragments survive. `/2fa#webauthn` is a real in-app deep link and a fragment
 *   cannot change the origin of a relative path.
 *
 *   Queries survive, but `://` is rejected everywhere in the string, including
 *   inside the query and the fragment. `/x?next=https://evil.com` is a redirect
 *   chain waiting for some downstream consumer to follow it, and no route in
 *   this app takes an absolute URL as a parameter. The rule costs nothing and
 *   removes a class of second-order open redirects.
 *
 *   Percent-encoding is decoded (bounded rounds) and re-checked. A consumer that
 *   decodes once before navigating would otherwise turn `/%2f%2fevil.com` into
 *   the protocol-relative `//evil.com`.
 *
 *   Dot segments are rejected rather than normalised. vue-router does not
 *   collapse them — it resolves `/..//evil.com` verbatim — while `new URL()`
 *   does collapse them, to `//evil.com`. A validator whose idea of the final
 *   path disagrees with the router's is a validator that can be talked around,
 *   so neither interpretation is accepted.
 *
 *   Backslashes, control characters and non-ASCII are rejected by character
 *   allowlist rather than by asking a URL parser. Parsers disagree: `/\evil.com`
 *   begins an authority to the WHATWG parser and is a plain path to others, and
 *   browsers strip tab/CR/LF before parsing while `decodeURIComponent` does not.
 *   Structural rules that hold regardless of parser come first; the parser is
 *   consulted afterwards only as a second opinion.
 */

/** Longer than any route this app generates; keeps hostile input out of history and logs. */
const MAX_REDIRECT_LENGTH = 2048

/** Enough to unwrap double and triple encoding without spinning on crafted input. */
const MAX_DECODE_ROUNDS = 4

/**
 * RFC 3986 unreserved + sub-delims + the separators a router legitimately emits.
 * Excludes backslash, every whitespace and control character, and all non-ASCII.
 */
const ALLOWED_CHARS = /^[A-Za-z0-9\-._~!$&'()*+,;=:@/?#%[\]]+$/

/** Throwaway origin used only to get a second opinion from the URL parser. */
const PROBE_ORIGIN = 'http://safe-redirect.invalid'

/**
 * C0 and C1 control characters plus the Unicode line separators. Browsers strip
 * tab, CR and LF before resolving a URL, which is how `/<tab>/evil.com` becomes
 * protocol-relative, so no decoded form may contain any of them.
 */
function hasControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f) return true
    if (code >= 0x7f && code <= 0x9f) return true
    if (code === 0x2028 || code === 0x2029) return true
  }
  return false
}

/** True when any path segment is a dot segment, i.e. the path can climb or collapse. */
function hasDotSegment(value: string): boolean {
  const pathOnly = value.split(/[?#]/, 1)[0]
  return pathOnly.split('/').some((segment) => segment === '.' || segment === '..')
}

/** Full structural allowlist, applied to the raw candidate. */
function isStructurallySafe(value: string): boolean {
  if (value.length === 0 || value.length > MAX_REDIRECT_LENGTH) return false
  if (value[0] !== '/') return false
  // A second slash or a backslash in position 1 starts an authority in at least
  // one real browser, which would make the target cross-origin.
  if (value[1] === '/' || value[1] === '\\') return false
  if (!ALLOWED_CHARS.test(value)) return false
  if (value.includes('://')) return false
  if (hasDotSegment(value)) return false
  return true
}

/**
 * Shape rules re-applied to each percent-decoded form. The full character
 * allowlist cannot be reused here — decoding legitimately produces spaces and
 * other characters inside a query value — so only the dangerous shapes are
 * checked.
 */
function isDecodedShapeSafe(value: string): boolean {
  // The first two are unreachable from isProvablySafe and are kept anyway.
  // Nothing gets here without passing isStructurallySafe, which requires a
  // literal leading '/', and no percent-decoding can delete a literal character
  // or empty a non-empty string -- every escape decodes to at least one
  // character. They are the two statements the frontend coverage report has
  // never covered, and this comment is the reason rather than an oversight.
  //
  // Defence in depth in the strict sense: this function's contract is "these
  // shapes are unsafe", and it holds whether or not the caller checked first. A
  // future caller that decodes from somewhere else gets a function that is
  // correct on its own, not one that assumes it was called in the right order.
  if (value.length === 0) return false
  if (value[0] !== '/') return false
  if (value[1] === '/' || value[1] === '\\') return false
  if (value.includes('\\')) return false
  if (hasControlChar(value)) return false
  if (value.includes('://')) return false
  if (hasDotSegment(value)) return false
  return true
}

/**
 * The whole validator, applied to one candidate. Both the untrusted `path` and
 * the caller's `defaultPath` go through this, so neither position is held to a
 * weaker standard than the other: a value rejected as a redirect target is also
 * rejected as a fallback.
 *
 * Duplicated query parameters (`?redirect=a&redirect=b`) arrive as an array, not
 * a string. Everything non-string fails closed here.
 */
function isProvablySafe(value: unknown): value is string {
  if (typeof value !== 'string') return false
  if (!isStructurallySafe(value)) return false

  let decoded = value
  for (let round = 0; round < MAX_DECODE_ROUNDS; round++) {
    let next: string
    try {
      next = decodeURIComponent(decoded)
    } catch {
      // Malformed percent-escape. Different consumers recover from it differently.
      return false
    }
    if (next === decoded) break
    if (!isDecodedShapeSafe(next)) return false
    decoded = next
  }

  // Second opinion from the URL parser, resolved against an origin we control.
  // The canonical form must match byte for byte: if the parser and the rules
  // above disagree about what this string means, the value is not returned.
  try {
    const url = new URL(value, PROBE_ORIGIN)
    // Also unreachable, for the same reason: a value that begins with a single
    // '/' and no backslash resolves against the probe base to the probe origin,
    // and the parser does not throw on the ASCII, control-free, decodable
    // strings that reach here. The check that does the work is the next one,
    // which is where the parser gets to disagree.
    if (url.origin !== PROBE_ORIGIN) return false
    if (url.pathname + url.search + url.hash !== value) return false
  } catch {
    return false
  }

  return true
}

/**
 * @param path        Untrusted redirect target, or null/undefined/anything else.
 * @param defaultPath Fallback used whenever `path` is not provably safe. It is
 *                    itself validated, so a call site that mistakenly forwards
 *                    user input as the default still cannot open-redirect.
 */
export function safeRedirect(path: string | null | undefined, defaultPath = '/'): string {
  const fallback = isProvablySafe(defaultPath) ? defaultPath : '/'
  return isProvablySafe(path) ? path : fallback
}
