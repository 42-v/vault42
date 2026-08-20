import { describe, it, expect } from 'vitest'
import { safeRedirect } from '../utils/safeRedirect'

// Control characters are built from char codes rather than escapes so that the
// vectors below stay readable and cannot be mangled by an editor or a linter.
const NUL = String.fromCharCode(0x00)
const TAB = String.fromCharCode(0x09)
const LF = String.fromCharCode(0x0a)
const CR = String.fromCharCode(0x0d)
const DEL = String.fromCharCode(0x7f)
const NEL = String.fromCharCode(0x85)
const LINE_SEP = String.fromCharCode(0x2028)

/**
 * The hostile table. A new attack vector is one line here.
 * Every entry must collapse to the default path.
 */
const HOSTILE: Array<[string, unknown]> = [
  // Absolute and protocol-relative
  ['a protocol-relative URL', '//evil.com'],
  ['a triple-slash URL', '///evil.com'],
  ['an absolute http URL', 'http://evil.com'],
  ['an absolute https URL with a path', 'https://evil.com/profile'],
  ['a scheme-relative URL with credentials', '//user:pass@evil.com'],
  ['a javascript: URL', 'javascript:alert(1)'],
  ['a data: URL', 'data:text/html,<h1>hi</h1>'],
  ['a mailto: URL', 'mailto:a@b.c'],

  // Backslash variants — browsers and routers disagree on these
  ['a backslash authority', '/\\evil.com'],
  ['a leading backslash', '\\/evil.com'],
  ['a double backslash authority', '/\\\\evil.com'],
  ['a mixed slash and backslash authority', '/\\/evil.com'],
  ['a backslash after a double slash', '//\\evil.com'],
  ['a backslash later in the path', '/profile\\@evil.com'],
  ['an encoded backslash authority', '/%5cevil.com'],
  ['a double encoded backslash authority', '/%5c%5cevil.com'],

  // Whitespace and control characters — stripped by browsers before parsing
  ['a tab in the path', '/' + TAB + 'evil.com'],
  ['a tab-separated authority', '/' + TAB + '/evil.com'],
  ['a newline-separated authority', '/' + LF + '/evil.com'],
  ['a CRLF-separated authority', '/' + CR + LF + '/evil.com'],
  ['a NUL byte', '/' + NUL + '/evil.com'],
  ['a DEL character', '/' + DEL + '/evil.com'],
  ['a C1 next-line character', '/' + NEL + '/evil.com'],
  ['a Unicode line separator', '/' + LINE_SEP + '/evil.com'],
  ['a leading space', ' /evil.com'],
  ['an embedded space', '/ /evil.com'],
  ['a trailing newline', '/profile' + LF],
  ['a tab inside the query', '/profile?q=' + TAB],

  // Percent-encoded and double-encoded separators
  ['an encoded tab authority', '/%09/evil.com'],
  ['an encoded CRLF header injection', '/%0d%0aSet-Cookie:x'],
  ['an encoded double slash', '/%2f%2fevil.com'],
  ['an uppercase encoded double slash', '/%2F%2Fevil.com'],
  ['a double-encoded double slash', '/%252f%252fevil.com'],
  ['an encoded backslash and slash', '/%5c/evil.com'],
  ['an encoded backslash deeper in the path', '/profile%5cevil.com'],
  ['an encoded DEL character', '/%7f/evil.com'],
  ['an encoded C1 next-line character', '/%c2%85/evil.com'],
  ['an encoded Unicode line separator', '/%e2%80%a8/evil.com'],
  ['an encoded scheme separator', '/a%3a%2f%2fevil.com'],
  ['a malformed percent escape', '/%zz'],
  ['a truncated percent escape', '/profile%'],
  ['a form the URL parser rewrites (bare question mark)', '/profile?'],
  ['a form the URL parser rewrites (bare hash)', '/profile#'],

  // Dot segments — vue-router keeps them, new URL() collapses them
  ['a dot-segment climb into a protocol-relative URL', '/..//evil.com'],
  ['a dot-segment climb', '/../../evil.com'],
  ['a current-dir segment before a climb', '/./..//evil.com'],
  ['encoded dot segments', '/%2e%2e//evil.com'],
  ['a trailing dot segment', '/profile/..'],
  ['a bare current-dir segment', '/./profile'],

  // Second-order redirect chains
  ['an absolute URL in the query', '/login?next=https://evil.com'],
  ['an absolute URL in the fragment', '/login#https://evil.com'],
  ['a nested redirect parameter carrying a scheme', '/login?redirect=http://evil.com'],

  // Unicode confusables and raw non-ASCII
  ['a fullwidth solidus authority', '/／／evil.com'],
  ['a fraction slash', '/⁄evil.com'],
  ['a right-to-left override', '/profile‮evil.com'],
  ['raw non-ASCII (the router emits it percent-encoded)', '/café'],

  // Shape
  ['the empty string', ''],
  ['a path with no leading slash', 'profile'],
  ['a query-only string', '?redirect=/profile'],
  ['a fragment-only string', '#/profile'],
  ['an unencoded pipe', '/a|b'],
  ['an unencoded angle bracket', '/a<b>'],
  ['an unencoded double quote', '/a"b'],
  ['an unencoded brace', '/a{b}'],
  ['an over-long path', '/' + 'a'.repeat(4096)],

  // Wrong types — `route.query.redirect` is not always a string
  ['null', null],
  ['undefined', undefined],
  ['a duplicated query parameter (array)', ['/profile', '//evil.com']],
  ['a number', 42],
  ['an object that stringifies to a URL', { toString: () => '//evil.com' }],
  ['a boolean', true],
]

/**
 * Values that must survive untouched. If a hardening change starts rejecting
 * one of these, in-app navigation silently breaks.
 */
const SAFE: string[] = [
  '/',
  '/profile',
  '/storage',
  '/2fa#webauthn',
  '/login?reason=password_changed',
  '/verify-email?token=abc.def-ghi_jkl~mno',
  '/identity?a=b&c=d',
  '/a%20b',
  '/storage?q=x+y',
  '/x?next=%2Ffoo',
  '/deep/nested/path/segments',
  '/@handle',
  '/path;matrix=1',
  "/a!$&'()*,;=:@",
  // Decoding stops after a bounded number of rounds; the raw value is what the
  // router receives, and it is still a plain same-origin path.
  '/profile%252525252fx',
]

describe('safeRedirect', () => {
  describe('hostile inputs', () => {
    it.each(HOSTILE)('rejects %s', (_name, input) => {
      expect(safeRedirect(input as string)).toBe('/')
    })

    it.each(HOSTILE)('falls back to the caller default for %s', (_name, input) => {
      expect(safeRedirect(input as string, '/login')).toBe('/login')
    })
  })

  describe('legitimate inputs', () => {
    it.each(SAFE)('returns %s unchanged', (input) => {
      expect(safeRedirect(input)).toBe(input)
    })

    it.each(SAFE)('ignores the default when %s is valid', (input) => {
      expect(safeRedirect(input, '/login')).toBe(input)
    })
  })

  describe('the default path itself', () => {
    it('uses the caller default when input is absent', () => {
      expect(safeRedirect(null, '/login')).toBe('/login')
    })

    it('refuses an unsafe default rather than trusting the caller', () => {
      expect(safeRedirect(null, '//evil.com')).toBe('/')
      expect(safeRedirect('//evil.com', 'https://evil.com')).toBe('/')
    })

    it('holds the default to the same standard as the path, vector for vector', () => {
      // The two positions used to disagree: `defaultPath` was checked by the raw
      // structural rules only, so `/%2e%2e//evil.com` and `/%5cevil.com` were
      // rejected as a target yet handed straight back as a fallback.
      const asymmetric: string[] = []
      for (const [name, input] of HOSTILE) {
        if (typeof input !== 'string') continue
        if (safeRedirect(null, input) !== '/') asymmetric.push(`${name}: ${input}`)
      }
      expect(asymmetric).toEqual([])
    })

    it('refuses a non-string default', () => {
      expect(safeRedirect(null, undefined as unknown as string)).toBe('/')
      expect(safeRedirect(null, 7 as unknown as string)).toBe('/')
    })
  })

  describe('documented policy decisions', () => {
    it('preserves a fragment, because /2fa#webauthn is a real in-app deep link', () => {
      expect(safeRedirect('/2fa#webauthn')).toBe('/2fa#webauthn')
    })

    it('preserves a query string', () => {
      expect(safeRedirect('/login?reason=password_changed')).toBe('/login?reason=password_changed')
    })

    it('rejects :// even inside a query or fragment, to stop second-order redirects', () => {
      expect(safeRedirect('/login?next=https://evil.com')).toBe('/')
      expect(safeRedirect('/login#https://evil.com')).toBe('/')
    })

    it('accepts a same-origin path that merely looks like a host', () => {
      expect(safeRedirect('/evil.com')).toBe('/evil.com')
    })

    it('rejects dot segments in the path but keeps them inside a query or fragment', () => {
      // The climb rule deliberately inspects the path only. A dot segment in a
      // query value cannot move the target, and tightening the check to the whole
      // string would silently break links that pass a relative path as a parameter.
      expect(safeRedirect('/profile/..')).toBe('/')
      expect(safeRedirect('/./profile')).toBe('/')
      expect(safeRedirect('/x?a=../b')).toBe('/x?a=../b')
      expect(safeRedirect('/x?next=/a/../b')).toBe('/x?next=/a/../b')
      expect(safeRedirect('/x#../y')).toBe('/x#../y')
    })

    it('caps input length instead of forwarding unbounded attacker data', () => {
      const justUnder = '/' + 'a'.repeat(2047)
      const justOver = '/' + 'a'.repeat(2048)
      expect(safeRedirect(justUnder)).toBe(justUnder)
      expect(safeRedirect(justOver)).toBe('/')
    })
  })

  describe('agreement with the URL parser', () => {
    it('never returns a value that the URL parser resolves off-origin', () => {
      for (const [, input] of HOSTILE) {
        const result = safeRedirect(input as string)
        const resolved = new URL(result, 'http://vault42.test')
        expect(resolved.origin).toBe('http://vault42.test')
      }
    })

    it('always returns a value it would itself accept', () => {
      // Call sites chain the result: the guard writes ?redirect=, a view reads it
      // back and sanitizes again. If the validator ever normalised its output into
      // a form it then rejected, the second pass would silently drop the user on /.
      for (const [, input] of [...HOSTILE, ...SAFE.map((s) => ['', s] as const)]) {
        const once = safeRedirect(input as string, '/login')
        expect(safeRedirect(once, '/login'), `not a fixed point: ${once}`).toBe(once)
      }
    })

    it('never returns a value whose canonical form differs from itself', () => {
      for (const input of SAFE) {
        const result = safeRedirect(input)
        const url = new URL(result, 'http://vault42.test')
        expect(url.pathname + url.search + url.hash).toBe(result)
      }
    })
  })
})

/**
 * Everything above is a table: a vector somebody thought of, and the outcome it
 * must have. A table is only as good as the imagination behind it, and this
 * validator's whole job is to survive inputs nobody imagined.
 *
 * So this last block stops asserting outcomes for named inputs and starts
 * asserting a property over generated ones: whatever `safeRedirect` returns is
 * re-derived as safe from the returned string alone, without consulting the
 * implementation. The checks below are written from the threat -- can this
 * string leave the origin -- rather than from the code, so an input that talks
 * the validator around fails here even though the validator thought it was fine.
 *
 * The generator is deterministic. A fuzz test that finds a failure once a month
 * and cannot reproduce it is worse than no fuzz test: it teaches the reader to
 * re-run CI.
 */

/** Fragments chosen because each one has, somewhere, been an open redirect. */
const FRAGMENTS = [
  '/', '//', '\\', '/\\', '.', '..', '/..', '/.', 'evil.com', 'profile', '2fa',
  '?', '#', '&', '=', ':', '@', '%2f', '%2F', '%5c', '%252f', '%00', '%09', '%0a',
  '%25', '%', 'http:', 'https:', '://', 'javascript:', 'data:', ' ', TAB, LF, CR,
  NUL, DEL, NEL, LINE_SEP, 'a', '1', '-', '_', '~', ';', ',', '+', '!', '$', "'",
  '(', ')', '*', '[', ']', 'localhost', '127.0.0.1', 'İ', '／',
]

/** xorshift32. Constant seed, so a failure reported here reproduces exactly. */
function makeRandom(seed: number): () => number {
  let state = seed
  return () => {
    state ^= state << 13
    state ^= state >>> 17
    state ^= state << 5
    return (state >>> 0) / 0x100000000
  }
}

const PROBE = 'http://safe-redirect.invalid'

/**
 * Re-derives safety from a returned value. Deliberately not a copy of the
 * validator: it asks the questions an attacker asks, and a validator that
 * satisfies its own rules while failing these has a bug the rules did not cover.
 */
function escapesTheOrigin(value: string): string | null {
  if (!value.startsWith('/')) return 'does not start with a slash'
  if (value.startsWith('//') || value.startsWith('/\\')) return 'starts an authority'
  if (value.includes('\\')) return 'contains a backslash'
  if (value.includes('://')) return 'contains a scheme separator'

  for (let i = 0; i < value.length; i++) {
    const code = value.charCodeAt(i)
    if (code <= 0x1f || (code >= 0x7f && code <= 0x9f) || code === 0x2028 || code === 0x2029) {
      return `contains control character 0x${code.toString(16)}`
    }
  }

  // A consumer that decodes before navigating must not be handed something that
  // becomes an authority on the way.
  let decoded = value
  for (let round = 0; round < 4; round++) {
    let next: string
    try {
      next = decodeURIComponent(decoded)
    } catch {
      break
    }
    if (next === decoded) break
    if (next.startsWith('//') || next.startsWith('/\\') || next.includes('://')) {
      return `decodes in ${round + 1} round(s) to something that leaves the origin: ${next}`
    }
    decoded = next
  }

  try {
    const url = new URL(value, PROBE)
    if (url.origin !== PROBE) return `resolves to ${url.origin}`
  } catch {
    return 'is not a URL the parser accepts'
  }

  return null
}

describe('generated inputs', () => {
  it('never returns a value that can leave the origin', () => {
    const random = makeRandom(0x5afe_9ed1)
    const failures: string[] = []
    let accepted = 0

    for (let i = 0; i < 20_000; i++) {
      const parts = 1 + Math.floor(random() * 6)
      let candidate = ''
      for (let p = 0; p < parts; p++) {
        candidate += FRAGMENTS[Math.floor(random() * FRAGMENTS.length)]
      }

      const result = safeRedirect(candidate)
      if (result === candidate) accepted++

      const why = escapesTheOrigin(result)
      if (why !== null) {
        failures.push(`safeRedirect(${JSON.stringify(candidate)}) = ${JSON.stringify(result)} ${why}`)
      }
      if (failures.length >= 5) break
    }

    expect(failures).toEqual([])

    // A corpus that is rejected in full passes this test without exercising the
    // accepting path at all, and would go on passing if the validator were
    // replaced by `() => '/'`. The generator currently accepts 261 of the 20000,
    // things like `/.;` and `/..*`, whose first segment only looks like a dot
    // segment. The floor is well under that: it is here to catch a generator
    // that stops producing valid paths, not to pin the exact figure.
    expect(accepted).toBeGreaterThan(50)
  })

  it('returns either the input unchanged or the fallback, never a repaired value', () => {
    // A validator that normalises is a validator whose output the caller has to
    // re-check. This one is allowlist-shaped: a value is accepted as it stands
    // or replaced wholesale.
    const random = makeRandom(0x0bad_f00d)
    for (let i = 0; i < 5_000; i++) {
      const parts = 1 + Math.floor(random() * 4)
      let candidate = ''
      for (let p = 0; p < parts; p++) {
        candidate += FRAGMENTS[Math.floor(random() * FRAGMENTS.length)]
      }
      const result = safeRedirect(candidate, '/home')
      expect(result === candidate || result === '/home').toBe(true)
    }
  })
})
