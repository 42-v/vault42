import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * A label a screen reader cannot connect to its field is not a label.
 *
 * ResetPasswordView had two: `<label class="vault42-label">` with no `for`, and
 * password inputs with no `id`. Sighted users saw "New password" above a box;
 * a screen reader announced an unlabelled secure edit field, twice, on the one
 * screen a user reaches from a password-reset email with no way to go back and
 * work out what the second box wanted. WCAG 1.3.1, 3.3.2 and 4.1.2.
 *
 * Eighteen of the twenty labels in the app were already associated, which is
 * exactly why this went unseen: the pattern was right nearly everywhere, so
 * nobody was looking. A component test for those two fields would have proved
 * this once and said nothing about the twenty-first label. This reads the
 * templates, so the next unassociated one fails here instead of shipping mute.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')
const sdkDir = resolvePath(srcDir, '../../packages/vue/src')

/**
 * Controls that need a name. `hidden` carries no user-visible affordance, and
 * submit/button/reset take their name from their own value or content.
 */
const NAMELESS_INPUT_TYPES = new Set(['hidden', 'submit', 'button', 'reset', 'image'])

/** Attributes that give a control an accessible name without a <label>. */
const SELF_NAMING = /\baria-label=|\baria-labelledby=|\b:aria-label=/

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

/** A tag may span several lines, so a line-based scan misses its attributes. */
function openingTags(source: string, name: string): string[] {
  return [...source.matchAll(new RegExp(`<${name}\\b[^>]*>`, 'g'))].map(m => m[0])
}

/**
 * Whole `<label>...</label>` blocks, so a control nested inside one can be
 * recognised. A label that wraps its control needs no `for` -- that is implicit
 * labelling, it is valid HTML, and the SDK's "remember me" checkbox uses it.
 * Treating it as a defect would be a gate that flags correct markup.
 */
function labelBlocks(source: string): string[] {
  return [...source.matchAll(/<label\b[^>]*>[\s\S]*?<\/label>/g)].map(m => m[0])
}

function attr(tag: string, name: string): string | null {
  const m = tag.match(new RegExp(`\\b${name}="([^"]*)"`))
  return m ? m[1] : null
}

/**
 * The one control this gate knowingly does not hold, with the reason and the
 * condition that retires it.
 *
 * LanguageSwitcher's filter box has no accessible name, and unlike the others it
 * cannot borrow one: the component uses no i18n at all -- it has no useI18n, no
 * t(), and its placeholder is a hardcoded English "Search...". There is no
 * search key in any of the 38 locale files. Giving it a name therefore means
 * adding the first new string in the UI plan and translating it 38 times, which
 * is an owner decision (#297) and not an engineer's to make inside an
 * accessibility fix.
 *
 * It is listed rather than skipped so the cost stays visible, and the assertion
 * below fails if it is ever fixed without being removed from here -- an
 * exception that outlives its defect is how an exclusion list becomes a
 * blindfold.
 */
const KNOWN_UNNAMED = new Map<string, string>([
  ['web/src/components/LanguageSwitcher.vue', 'no i18n in the component; naming it needs a new string x38 locales (#297, plan item C5)'],
])

const files = [...vueFiles(srcDir), ...vueFiles(sdkDir)]

describe('label association', () => {
  it('scans a non-empty set of templates', () => {
    // A gate that finds nothing passes for the wrong reason.
    expect(files.length).toBeGreaterThan(0)
  })

  it('gives every label a control, and every control a name', () => {
    const problems: string[] = []
    let labelsSeen = 0
    let controlsSeen = 0

    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      const where = relative(resolvePath(srcDir, '../..'), file)

      const ids = new Set<string>()
      for (const name of ['input', 'select', 'textarea']) {
        for (const tag of openingTags(source, name)) {
          const id = attr(tag, 'id')
          if (id) ids.add(id)
        }
      }

      // Controls sitting inside a <label>...</label> are named by it, with no
      // `for` needed.
      const wrapped = new Set<string>()
      for (const block of labelBlocks(source)) {
        for (const name of ['input', 'select', 'textarea']) {
          for (const tag of openingTags(block, name)) wrapped.add(tag)
        }
      }

      const labelTargets = new Set<string>()
      for (const tag of openingTags(source, 'label')) {
        labelsSeen++
        const target = attr(tag, 'for')
        if (!target) {
          const wraps = labelBlocks(source).some(
            b => b.startsWith(tag) && /<(input|select|textarea)\b/.test(b),
          )
          if (!wraps) {
            problems.push(
              `${where}: <label> with no for= and no control inside it. A sighted ` +
              `user reads it; a screen reader does not connect it to anything.\n    ${tag}`,
            )
          }
          continue
        }
        labelTargets.add(target)
        if (!ids.has(target)) {
          problems.push(
            `${where}: <label for="${target}"> points at an id no control in this ` +
            `file carries, so the association is written down but does not exist.`,
          )
        }
      }

      for (const name of ['input', 'select', 'textarea']) {
        for (const tag of openingTags(source, name)) {
          const type = attr(tag, 'type') ?? ''
          if (name === 'input' && NAMELESS_INPUT_TYPES.has(type)) continue
          if (SELF_NAMING.test(tag)) continue
          if (wrapped.has(tag)) continue
          controlsSeen++
          const id = attr(tag, 'id')
          if (!id || !labelTargets.has(id)) {
            problems.push(
              `${where}: <${name}${type ? ` type="${type}"` : ''}> has no label and no ` +
              `aria-label, so it is announced as an unnamed field.\n    ${tag}`,
            )
          }
        }
      }
    }

    // Both counters, because the two halves fail independently: a template with
    // no labels at all would satisfy the first loop vacuously.
    expect(labelsSeen).toBeGreaterThan(0)
    expect(controlsSeen).toBeGreaterThan(0)

    const excused: string[] = []
    const real: string[] = []
    for (const p of problems) {
      const file = p.split(':')[0]
      if (KNOWN_UNNAMED.has(file)) excused.push(file)
      else real.push(p)
    }
    expect(real.join('\n')).toBe('')

    // Every listed exception must still be earning its place. A file that no
    // longer has the defect has to leave this map, or the map stops describing
    // the tree and starts hiding it.
    for (const file of KNOWN_UNNAMED.keys()) {
      expect(
        excused.includes(file),
        `${file} is listed in KNOWN_UNNAMED (${KNOWN_UNNAMED.get(file)}) but no ` +
        `longer has an unnamed control. Remove the entry.`,
      ).toBe(true)
    }
  })
})
