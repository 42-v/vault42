import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * Buttons go through the shared utilities, and the retired aliases stay retired.
 *
 * Two things drifted here, in opposite directions.
 *
 * `vault42-btn-primary` and `vault42-btn-secondary` were pure `@apply` forwards
 * onto `vault42-btn` and `vault42-btn-outline` -- two names for one button, so a
 * reader could not tell whether the difference was meaningful. Five call sites
 * used them. They are gone from the templates; the definitions leave style.css
 * with the rest of that file's cleanup, and this gate is what makes that removal
 * safe rather than a gamble on nobody having typed the old name.
 *
 * MFAOnboardingView went the other way and hand-rolled the palette inline --
 * `bg-vault42-primary text-white ... hover:bg-vault42-primary-hover` -- which is
 * `vault42-btn` written out longhand, minus the `disabled:` states it carries.
 * A button styled that way looks right until the day the utility changes and it
 * silently does not follow.
 *
 * Reading the templates catches both, including in the view somebody adds next.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

/** Alias names that were retired. Typing one again should fail here. */
const RETIRED = ['vault42-btn-primary', 'vault42-btn-secondary']

/**
 * Palette utilities that mean "this element is painting a button by hand".
 * A control carrying these without a vault42-btn* class has forked the style.
 *
 * The negative lookahead excludes an opacity modifier. `bg-vault42-primary/15`
 * is a selection highlight, not a button fill -- LanguageSwitcher's dropdown
 * rows use it to mark the active locale, and an earlier version of this pattern
 * called that a hand-rolled button because \b terminates at the slash.
 */
const HAND_ROLLED = /\bbg-vault42-primary(?![/\w-])|\bhover:bg-vault42-primary-hover\b/

function vueFiles(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name === '__tests__' || entry.name === 'node_modules') continue
      out.push(...vueFiles(full))
    } else if (entry.name.endsWith('.vue')) {
      out.push(full)
    }
  }
  return out.sort()
}

const files = vueFiles(srcDir)

describe('button utilities', () => {
  it('scans a non-empty set of templates', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  it('uses no retired alias class', () => {
    const problems: string[] = []
    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      const where = relative(resolvePath(srcDir, '../..'), file)
      for (const alias of RETIRED) {
        // Word boundary on both sides: vault42-btn-primary must not match
        // inside a longer name, and vault42-btn must not match it either.
        if (new RegExp(`\\b${alias}\\b`).test(source)) {
          problems.push(
            `${where}: uses the retired alias ${alias}. It forwarded to ` +
            `${alias === 'vault42-btn-primary' ? 'vault42-btn' : 'vault42-btn-outline'}; ` +
            `use that directly.`,
          )
        }
      }
    }
    expect(problems.join('\n')).toBe('')
  })

  it('paints no button by hand', () => {
    const problems: string[] = []
    let buttonsSeen = 0

    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      const where = relative(resolvePath(srcDir, '../..'), file)
      for (const tag of source.matchAll(/<button\b[^>]*>/g)) {
        buttonsSeen++
        const cls = tag[0].match(/\bclass="([^"]*)"/)
        if (!cls) continue
        if (HAND_ROLLED.test(cls[1]) && !/\bvault42-btn/.test(cls[1])) {
          problems.push(
            `${where}: a <button> paints the button palette inline instead of ` +
            `using vault42-btn. It will not follow the utility when that changes.\n    ` +
            `class="${cls[1]}"`,
          )
        }
      }
    }

    // A gate that finds no buttons proves nothing.
    expect(buttonsSeen).toBeGreaterThan(0)
    expect(problems.join('\n')).toBe('')
  })
})
