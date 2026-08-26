import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * Re-derives WCAG contrast from the palette itself, so a "just a shade" edit
 * fails here rather than months later in an audit.
 *
 * The palette this replaced failed AA in four places at once: `muted` carried
 * body copy at 4.15:1, `primary` was link and active-nav text at 4.42:1,
 * `border` drew form-field boundaries at 1.20:1 against a 3:1 requirement, and
 * the primary button put white on `primary` at 4.47:1 and then *lightened* on
 * hover to 2.98:1.
 */

const stylesheetPath = resolvePath(dirname(fileURLToPath(import.meta.url)), '../style.css')

/**
 * Reads the tokens out of the `@theme` block in `src/style.css` as text.
 *
 * They lived in `tailwind.config.js` until Tailwind 4, which takes its theme
 * from CSS. Reading the stylesheet keeps this a test of the file Tailwind
 * actually compiles rather than of a copy that could drift from it, which is
 * the same reason the old version parsed the config instead of importing it.
 */
function readPalette(): Record<string, string> {
  const source = readFileSync(stylesheetPath, 'utf8')
  const block = /@theme\s*\{([^}]*)\}/.exec(source)
  if (!block) throw new Error(`no @theme block in ${stylesheetPath}`)

  const tokens: Record<string, string> = {}
  for (const [, name, hex] of block[1].matchAll(/--color-vault42-([\w-]+):\s*(#[0-9a-fA-F]{6});/g)) {
    tokens[name] = hex
  }
  return tokens
}

const palette = readPalette()

function channel(value: number): number {
  const c = value / 255
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

function parseHex(hex: string): number[] {
  const h = hex.replace('#', '')
  return [0, 2, 4].map(i => parseInt(h.slice(i, i + 2), 16))
}

function luminance(hex: string): number {
  const [r, g, b] = parseHex(hex)
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (hi + 0.05) / (lo + 0.05)
}

/** Flattens a `bg-<token>/<pct>` tint onto an opaque backdrop. */
function tint(fg: string, alpha: number, bg: string): string {
  const [f, b] = [parseHex(fg), parseHex(bg)]
  return '#' + f
    .map((c, i) => Math.round(c * alpha + b[i] * (1 - alpha)).toString(16).padStart(2, '0'))
    .join('')
}

const { bg, surface, border, control, primary, accent, text, muted, success, warning, error } = palette
const primaryHover = palette['primary-hover']
const BACKDROPS: Array<[string, string]> = [['bg', bg], ['surface', surface]]

describe('the palette this suite reads', () => {
  it('parsed every token out of the @theme block', () => {
    // A parse that silently found nothing would make every assertion below pass
    // against `undefined`.
    expect(Object.keys(palette).sort()).toEqual([
      'accent', 'bg', 'border', 'control', 'error', 'muted',
      'primary', 'primary-hover', 'success', 'surface', 'text', 'warning',
    ])
  })
})

describe('the contrast maths itself', () => {
  it('agrees with the WCAG reference values', () => {
    expect(contrast('#ffffff', '#000000')).toBeCloseTo(21, 5)
    expect(contrast('#ffffff', '#ffffff')).toBeCloseTo(1, 5)
  })
})

describe('text meets WCAG AA (4.5:1)', () => {
  it.each(BACKDROPS)('renders `text` on %s', (_name, backdrop) => {
    expect(contrast(text, backdrop)).toBeGreaterThanOrEqual(4.5)
  })

  it.each(BACKDROPS)('renders `muted` body copy on %s', (_name, backdrop) => {
    // 97 sites: the login subtitle, every form label and hint, the signed-in
    // email, the whole footer.
    expect(contrast(muted, backdrop)).toBeGreaterThanOrEqual(4.5)
  })

  it.each(BACKDROPS)('renders `accent` links and active nav on %s', (_name, backdrop) => {
    expect(contrast(accent, backdrop)).toBeGreaterThanOrEqual(4.5)
  })

  it.each(BACKDROPS)('renders `error`, `success` and `warning` on %s', (_name, backdrop) => {
    expect(contrast(error, backdrop)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(success, backdrop)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(warning, backdrop)).toBeGreaterThanOrEqual(4.5)
  })

  it('keeps `muted` readable on the badge and hover fills built from `border`', () => {
    expect(contrast(muted, border)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(muted, tint(border, 0.5, bg))).toBeGreaterThanOrEqual(4.5)
  })
})

describe('tinted banners keep their own text readable', () => {
  // Every alert and badge renders its colour on a 10-20% wash of itself, which
  // is where the previous `error` fell to 4.00:1.
  it.each([0.1, 0.15, 0.2])('holds `error` on an error/%s wash', (alpha) => {
    expect(contrast(error, tint(error, alpha, surface))).toBeGreaterThanOrEqual(4.5)
  })

  it.each([0.1, 0.15])('holds `success` on a success/%s wash', (alpha) => {
    expect(contrast(success, tint(success, alpha, surface))).toBeGreaterThanOrEqual(4.5)
  })

  // The backup-code banner in TwoFactorView is warning text on a warning/10
  // fill inside a warning/30 border, which is the shape `error` was measured
  // against when it moved off #ef4444.
  it.each([0.1, 0.15, 0.3])('holds `warning` on a warning/%s wash', (alpha) => {
    expect(contrast(warning, tint(warning, alpha, surface))).toBeGreaterThanOrEqual(4.5)
  })

  it.each([0.1, 0.15])('holds `accent` on a primary/%s wash', (alpha) => {
    for (const backdrop of [bg, surface]) {
      expect(contrast(accent, tint(primary, alpha, backdrop))).toBeGreaterThanOrEqual(4.5)
    }
  })
})

describe('primary is a surface, not ink', () => {
  it('carries white button text in both its resting and hover states', () => {
    expect(contrast('#ffffff', primary)).toBeGreaterThanOrEqual(4.5)
    expect(contrast('#ffffff', primaryHover)).toBeGreaterThanOrEqual(4.5)
  })

  it('changes on hover instead of staying put', () => {
    expect(primaryHover).not.toBe(primary)
  })
})

describe('control boundaries meet WCAG 1.4.11 (3:1)', () => {
  it.each(BACKDROPS)('draws `control` against %s', (_name, backdrop) => {
    // Input, checkbox and outline-button edges. `border` was 1.20:1 here.
    expect(contrast(control, backdrop)).toBeGreaterThanOrEqual(3)
  })

  it.each(BACKDROPS)('draws the focus indicator against %s', (_name, backdrop) => {
    expect(contrast(accent, backdrop)).toBeGreaterThanOrEqual(3)
  })

  it('draws both quota-bar fills against their track', () => {
    expect(contrast(accent, surface)).toBeGreaterThanOrEqual(3)
    expect(contrast(error, surface)).toBeGreaterThanOrEqual(3)
  })
})

describe('the source tree paints only from the palette', () => {
  const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

  // `.ts` is in scope, and it was not. The walker read `.vue` and `.css` only,
  // so `usePasswordStrength.ts` -- which returns Tailwind class names as data,
  // two of them stock-palette yellows -- was outside every colour gate in this
  // file. A composable that hands a class string to a template is styling.
  //
  // `__tests__` is out, for the reason paletteEscapes.test.ts gives: a test
  // asserting on a colour name has to be able to write it down.
  function sources(dir: string): string[] {
    const out: string[] = []
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== '__tests__') {
          out.push(...sources(full))
        }
      } else if (/\.(vue|css|ts)$/.test(entry.name)) {
        out.push(full)
      }
    }
    return out
  }

  it('reads the templates it is meant to be checking', () => {
    expect(sources(srcDir).length).toBeGreaterThanOrEqual(18)
  })

  it('has no `text-vault42-primary` left anywhere', () => {
    // The rule the split rests on: `primary` is now too dark to be read as text
    // (that is what makes white sit on it), so any reappearance is a regression.
    const offenders: string[] = []
    for (const file of sources(srcDir)) {
      const source = readFileSync(file, 'utf8')
      for (const match of source.matchAll(/[\w:-]*text-vault42-primary(?![\w-])/g)) {
        offenders.push(`${relative(srcDir, file)}: ${match[0]}`)
      }
    }
    expect(offenders).toEqual([])
  })

  /**
   * Tailwind ships a stock palette -- `text-green-400`, `bg-yellow-500` -- and
   * every one of those names resolves to a colour this file has never audited.
   *
   * Eleven had accumulated, in four files, and they were invisible to
   * everything: the essay at the top of style.css governs the tokens, the gate
   * in it reads CSS literals, and paletteEscapes.test.ts reads hex and rgb() in
   * templates. A class name is none of those.
   *
   * The shape they took is worth naming, because it is the one that looks
   * harmless. Nine of the eleven were hover states written beside a correct
   * token -- `text-vault42-error hover:text-red-300` -- so the resting colour
   * was audited and the interactive one was not. That is the same defect the
   * palette rework was done for: the old primary button carried white at
   * 4.47:1 and *lightened* on hover to 2.98:1. Here the tree is dark, so
   * lightening happened to help; on any backdrop that changes, it would not,
   * and nothing would have said so.
   *
   * The remaining two were a caution colour with no token behind it, which is
   * what `warning` now is.
   */
  it('uses no colour from Tailwind\'s stock palette', () => {
    const STOCK = new RegExp(
      String.raw`(?<![\w-])(?:[a-z-]+:)*(?:text|bg|border|ring|from|to|via|fill|stroke|` +
        String.raw`decoration|outline|shadow|accent|caret|divide|placeholder)-` +
        `(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|` +
        `cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\\d{2,3}(?![\\w-])`,
      'g',
    )
    const offenders: string[] = []
    for (const file of sources(srcDir)) {
      const source = readFileSync(file, 'utf8')
      for (const match of source.matchAll(STOCK)) {
        offenders.push(`${relative(srcDir, file)}: ${match[0]}`)
      }
    }
    expect(offenders).toEqual([])
  })

  it('would notice a stock colour if one came back', () => {
    // The regex above is the whole gate, so it is worth proving it matches the
    // things it is written for rather than trusting it to.
    const STOCK = /(?<![\w-])(?:[a-z-]+:)*(?:text|bg|border)-(?:red|green|yellow)-\d{2,3}(?![\w-])/g
    for (const sample of ['text-red-300', 'hover:text-green-400', 'bg-yellow-500', 'md:hover:bg-red-500']) {
      expect(sample.match(STOCK), sample).not.toBeNull()
    }
    // And not the tokens, which share the prefix.
    for (const ok of ['text-vault42-error', 'hover:text-vault42-text', 'bg-vault42-warning/10']) {
      expect(ok.match(STOCK), ok).toBeNull()
    }
  })
})
