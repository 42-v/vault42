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

const { bg, surface, border, control, primary, accent, text, muted, success, error } = palette
const primaryHover = palette['primary-hover']
const BACKDROPS: Array<[string, string]> = [['bg', bg], ['surface', surface]]

describe('the palette this suite reads', () => {
  it('parsed every token out of the @theme block', () => {
    // A parse that silently found nothing would make every assertion below pass
    // against `undefined`.
    expect(Object.keys(palette).sort()).toEqual([
      'accent', 'bg', 'border', 'control', 'error', 'muted',
      'primary', 'primary-hover', 'success', 'surface', 'text',
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

  it.each(BACKDROPS)('renders `error` and `success` on %s', (_name, backdrop) => {
    expect(contrast(error, backdrop)).toBeGreaterThanOrEqual(4.5)
    expect(contrast(success, backdrop)).toBeGreaterThanOrEqual(4.5)
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

describe('the source tree keeps `primary` off text', () => {
  const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

  function sources(dir: string): string[] {
    const out: string[] = []
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules') out.push(...sources(full))
      } else if (/\.(vue|css)$/.test(entry.name)) {
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
})
