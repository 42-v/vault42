import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * An `<svg>` is either hidden from assistive technology or it has a name.
 *
 * There is no third option, and the default is the worst one. An `<svg>` with
 * neither is announced as an unlabelled graphic: a screen reader interrupts the
 * sentence the icon decorates to say "graphic" and nothing else.
 *
 * Twenty-two of the twenty-six in this tree were in that state. Every one sits
 * beside real text -- the provider buttons on the login screen carry
 * `{{ t('login.github') }}` next to the mark, the security cards on the home
 * screen carry a heading and a description, the status icons carry both -- so
 * the icon adds nothing a reader needs and costs an interruption per icon. Ten
 * of them are on one screen.
 *
 * The verify-email pair was the sharpest. Both live inside a `role="status"`
 * region, which a screen reader announces in full when the state changes, so
 * the announcement for a successful verification led with an unlabelled graphic
 * before reaching the words that say it worked.
 *
 * The rule is expressed as a choice rather than as "always hide", because an
 * icon that IS the accessible content of its control -- an icon-only button --
 * must be named instead, and a gate that said "always hide" would push someone
 * to hide the only thing announcing that button. None exist here today; the
 * rule is written so that adding one has a correct answer.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

/** Opening `<svg` tags, with everything up to the closing bracket. */
const SVG_OPEN = /<svg\b[^>]*>/g

function templates(dir: string): string[] {
  const out: string[] = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      if (entry.name !== '__tests__' && entry.name !== 'node_modules') out.push(...templates(full))
    } else if (entry.name.endsWith('.vue')) {
      out.push(full)
    }
  }
  return out.sort()
}

describe('every svg is hidden or named', () => {
  const files = templates(srcDir)

  it('reads the templates it is meant to be checking', () => {
    // A walker that found nothing would make the assertion below vacuous.
    expect(files.length).toBeGreaterThanOrEqual(8)
    expect(files.some((f) => readFileSync(f, 'utf8').includes('<svg'))).toBe(true)
  })

  it('leaves no svg for a screen reader to announce as an unlabelled graphic', () => {
    const offenders: string[] = []
    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      let index = 0
      for (const match of source.matchAll(SVG_OPEN)) {
        index += 1
        const tag = match[0]
        const hidden = /\baria-hidden\s*=\s*"(true|'?true'?)"/.test(tag) || /\baria-hidden\b/.test(tag)
        const named = /\baria-label\s*=/.test(tag) || /\baria-labelledby\s*=/.test(tag)
        if (!hidden && !named) {
          offenders.push(`${relative(srcDir, file)}: svg #${index}`)
        }
      }
    }
    expect(offenders).toEqual([])
  })

  it('would catch an svg that is neither', () => {
    // The regex is the gate, so it is worth demonstrating rather than trusting.
    const hidden = '<svg aria-hidden="true" class="w-4 h-4">'
    const named = '<svg aria-label="Vault logo" class="w-4">'
    const bare = '<svg class="w-4 h-4" viewBox="0 0 24 24">'
    const test = (tag: string) =>
      /\baria-hidden\b/.test(tag) || /\baria-label(ledby)?\s*=/.test(tag)
    expect(test(hidden)).toBe(true)
    expect(test(named)).toBe(true)
    expect(test(bare)).toBe(false)
  })
})
