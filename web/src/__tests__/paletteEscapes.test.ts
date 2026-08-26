import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * Colour comes from the design tokens, except where it provably cannot.
 *
 * The UI plan asked for a lint forbidding "colour outside the palette" and put
 * the count at thirteen raw escapes across five files. Measured, it is six in
 * two non-test files -- and every one of them has to stay literal. A gate
 * written to the plan's wording would have flagged six pieces of correct markup,
 * which is worse than no gate at all.
 *
 * So this holds the useful half instead: no NEW raw colour. The six that exist
 * are listed with the reason each is exempt, and the listing is checked in both
 * directions -- an entry that stops matching has to be removed, or the list
 * stops describing the tree and starts hiding it.
 *
 * Test files are out of scope. A test asserting an exact rendered colour is
 * supposed to name that colour; palette.test.ts and TwoFactorView.test.ts do
 * exactly that, and pinning them here would fight the assertions.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

/** Hex, rgb()/rgba(), hsl()/hsla(). */
const RAW_COLOUR = /#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)/g

/**
 * The literals that are allowed, and why. Keyed "file:literal".
 *
 * Both groups fail for the same underlying reason: the value is consumed by
 * something that is not the stylesheet, so a token never reaches it.
 */
const ALLOWED = new Map<string, string>([
  ['src/views/LoginView.vue:#4285F4', "Google's own mark; re-hueing a trademark is not a theming decision"],
  ['src/views/LoginView.vue:#34A853', "Google's own mark"],
  ['src/views/LoginView.vue:#FBBC05', "Google's own mark"],
  ['src/views/LoginView.vue:#EA4335', "Google's own mark"],
  ['src/views/TwoFactorView.vue:#0a0a0f', 'QR modules: the encoder takes concrete colours and the code must decode off any background, which is the defect that put them there'],
  ['src/views/TwoFactorView.vue:#ffffff', 'QR quiet zone: must be opaque white for a scanner, not the surface behind it'],
])

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'node_modules') continue
      out.push(...sourceFiles(full))
    } else if (/\.(vue|ts)$/.test(entry.name) && !/\.test\.ts$/.test(entry.name)) {
      out.push(full)
    }
  }
  return out.sort()
}

const files = sourceFiles(srcDir)

describe('palette escapes', () => {
  it('scans a non-empty set of sources', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  it('introduces no raw colour outside the palette', () => {
    const problems: string[] = []
    const matched = new Set<string>()

    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      const where = relative(srcDir, file)
      for (const m of source.matchAll(RAW_COLOUR)) {
        const key = `src/${where}:${m[0]}`
        if (ALLOWED.has(key)) {
          matched.add(key)
          continue
        }
        problems.push(
          `${key} is a raw colour. Use a design token, or add it to ALLOWED with the ` +
          `reason it cannot be one -- the existing entries are values consumed by ` +
          `something that is not the stylesheet.`,
        )
      }
    }

    expect(problems.join('\n')).toBe('')

    // The other direction. An exemption that outlives the literal it excused is
    // how a list like this quietly becomes permission to add anything.
    for (const [key, reason] of ALLOWED) {
      expect(
        matched.has(key),
        `${key} is listed as allowed (${reason}) but no longer appears. Remove the entry.`,
      ).toBe(true)
    }
  })
})
