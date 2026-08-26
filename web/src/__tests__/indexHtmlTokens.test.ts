import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve as resolvePath } from 'node:path'

/**
 * `index.html` is the one template Tailwind's own tooling cannot vouch for.
 *
 * Every other palette class in this app lives in a `.vue` file that
 * `palette.test.ts` and the build both read. `index.html` is copied through by
 * Vite, so a class that stops existing there produces no error, no warning and
 * no visual difference on any screen that paints its own background.
 *
 * That is exactly what happened. The theme was renamed `vault-*` to
 * `vault42-*` when `tailwind.config.js` was deleted for Tailwind 4's CSS-first
 * `@theme`, and `<body class="bg-vault-bg text-vault-text ...">` was left
 * behind. Neither class was generated into the emitted CSS afterwards -- the
 * shipped bundle contains no `bg-vault-bg` rule at all -- so the body element
 * had no background and no colour of its own for the whole of that period.
 *
 * It was invisible because every view paints its own container over the top.
 * The failure only shows through a gap: over-scroll bounce, a page shorter
 * than the viewport, the edges around a teleported overlay. There the browser
 * default shows through, which on a dark-only app means white.
 *
 * So this reads the classes out of `index.html` and requires each palette one
 * to name a token that `@theme` actually declares.
 */

const here = dirname(fileURLToPath(import.meta.url))
const indexHtmlPath = resolvePath(here, '../../index.html')
const stylesheetPath = resolvePath(here, '../style.css')

/** Palette utilities are `<prefix>-<token>`; these are the prefixes in use. */
const PALETTE_PREFIXES = ['bg', 'text', 'border', 'ring', 'fill', 'stroke', 'from', 'via', 'to', 'divide', 'outline', 'accent', 'caret', 'shadow', 'decoration']

/** Declared `--color-<name>` tokens from the `@theme` block. */
function declaredColorTokens(): Set<string> {
  const css = readFileSync(stylesheetPath, 'utf8')
  const tokens = new Set<string>()
  for (const match of css.matchAll(/--color-([a-z0-9-]+)\s*:/g)) {
    tokens.add(match[1])
  }
  return tokens
}

/** Every class named by a `class="..."` attribute in index.html. */
function classesInIndexHtml(): string[] {
  const html = readFileSync(indexHtmlPath, 'utf8')
  const classes: string[] = []
  for (const match of html.matchAll(/class="([^"]*)"/g)) {
    classes.push(...match[1].split(/\s+/).filter(Boolean))
  }
  return classes
}

/**
 * Splits a utility into prefix and token when it looks like a palette class
 * naming one of this project's own tokens, and returns null otherwise. Only
 * `vault*` tokens are claimed: `min-h-screen` and `antialiased` are Tailwind's
 * and are not ours to check.
 */
function paletteToken(cls: string): { prefix: string; token: string } | null {
  const bare = cls.replace(/^[a-z-]+:/, '').replace(/\/\d+$/, '')
  for (const prefix of PALETTE_PREFIXES) {
    if (!bare.startsWith(`${prefix}-`)) continue
    const token = bare.slice(prefix.length + 1)
    if (!token.startsWith('vault')) continue
    return { prefix, token }
  }
  return null
}

describe('index.html palette classes', () => {
  it('names only tokens that @theme declares', () => {
    const declared = declaredColorTokens()
    const stale = classesInIndexHtml()
      .map((cls) => ({ cls, parsed: paletteToken(cls) }))
      .filter(({ parsed }) => parsed !== null && !declared.has(parsed.token))
      .map(({ cls, parsed }) => `${cls} (no --color-${parsed!.token} in @theme)`)

    expect(
      stale,
      'index.html carries a palette class that generates no CSS. Tailwind emits ' +
        'nothing for an undeclared token and reports nothing, so the element ' +
        'silently loses that property. Rename the class to a declared token.',
    ).toEqual([])
  })

  it('gives the body an explicit background and text colour', () => {
    // The dark background is the app's ground. Without it here, the browser
    // default shows through wherever a view does not paint: over-scroll, a
    // short page, the edges of a teleported overlay.
    const classes = classesInIndexHtml()
    const declared = declaredColorTokens()

    const background = classes.find((c) => paletteToken(c)?.prefix === 'bg')
    const foreground = classes.find((c) => paletteToken(c)?.prefix === 'text')

    expect(background, 'index.html body has no vault palette background class').toBeDefined()
    expect(foreground, 'index.html body has no vault palette text class').toBeDefined()
    expect(declared.has(paletteToken(background!)!.token)).toBe(true)
    expect(declared.has(paletteToken(foreground!)!.token)).toBe(true)
  })
})
