import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve as resolvePath } from 'node:path'
import { compile } from 'tailwindcss'

/**
 * A size modifier has to actually beat the class it modifies, in the output.
 *
 * Declaring both the same way is necessary and not sufficient, which is the
 * whole reason this gate compiles instead of reading. Tailwind orders rules
 * inside @layer utilities by a property-set sort, not by source order, so two
 * utilities written adjacently can still emit in the wrong order -- measured:
 * adding w-full, h-4, block, inline-flex or z-10 to vault42-btn-sm moves it
 * ahead of vault42-btn and makes it inert at every one of its call sites, while
 * adding rounded-md or leading-none does not. Nothing about the source says
 * which of those you just did.
 *
 * The defect this was written for: vault42-spinner-sm set w-4 h-4 as an
 * @utility, which lands in @layer utilities, while .vault42-spinner was a plain
 * unlayered rule setting w-5 h-5. Unlayered beats layered whatever the
 * specificity, so every "small" spinner rendered at the default size. The class
 * was in the markup, the rule was in the stylesheet, the build emitted both.
 * Only the layer differed.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')
const repoRoot = resolvePath(srcDir, '../..')

/** Modifier/base pairs whose relative order in the output is load-bearing. */
const PAIRS: Array<[string, string]> = [
  ['vault42-spinner-sm', 'vault42-spinner'],
  ['vault42-spinner-lg', 'vault42-spinner'],
  ['vault42-btn-sm', 'vault42-btn'],
]

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === 'dist' || e.name === '.git') continue
    const p = join(dir, e.name)
    if (e.isDirectory()) sourceFiles(p, out)
    else if (/\.(vue|ts|js|html)$/.test(e.name)) out.push(p)
  }
  return out
}

async function buildCSS(): Promise<string> {
  const files = [
    ...sourceFiles(srcDir),
    ...sourceFiles(resolvePath(repoRoot, 'packages/vue/src')),
    resolvePath(repoRoot, 'web/index.html'),
  ]
  const candidates = new Set<string>()
  for (const f of files) {
    for (const m of readFileSync(f, 'utf8').matchAll(/[^\s"'`<>=(){};,]+/g)) candidates.add(m[0])
  }

  const twBase = resolvePath(repoRoot, 'web/node_modules/tailwindcss')
  const compiler = await compile(readFileSync(join(srcDir, 'style.css'), 'utf8'), {
    base: srcDir,
    loadStylesheet: async (id: string, base: string) => {
      const file = id === 'tailwindcss'
        ? join(twBase, 'index.css')
        : id.startsWith('tailwindcss/')
          ? join(twBase, id.slice('tailwindcss/'.length))
          : resolvePath(base, id)
      return { path: file, base: dirname(file), content: readFileSync(file, 'utf8') }
    },
    loadModule: async () => {
      throw new Error('no modules')
    },
  })
  return compiler.build([...candidates])
}

/**
 * Offset of a class's own rule in the emitted CSS, or -1.
 *
 * Plain string scanning rather than a regex built from the class name. The
 * first version escaped the name with cls.replace(/[-]/g, ...), which handles
 * exactly one metacharacter and is the shape CodeQL calls incomplete
 * sanitization -- correctly, even though every name here is a literal from the
 * table above. Not building a pattern from a value is simpler than escaping one.
 *
 * The delimiter check is what stops `.vault42-spinner` matching inside
 * `.vault42-spinner-sm`: a class name ends where the selector does.
 */
function ruleOffset(css: string, cls: string): number {
  const needle = `.${cls}`
  for (let i = css.indexOf(needle); i !== -1; i = css.indexOf(needle, i + 1)) {
    const after = css[i + needle.length]
    if (after === undefined) continue
    if (after === '{' || after === ',' || after === ' ' || after === '\n' || after === ':') {
      return i
    }
  }
  return -1
}

describe('utility cascade', () => {
  it('emits every size modifier after the class it modifies', async () => {
    const css = await buildCSS()

    for (const [modifier, base] of PAIRS) {
      const mOff = ruleOffset(css, modifier)
      const bOff = ruleOffset(css, base)

      expect(mOff, `${modifier} is not in the built CSS at all`).toBeGreaterThan(-1)
      expect(bOff, `${base} is not in the built CSS at all`).toBeGreaterThan(-1)

      expect(
        mOff > bOff,
        `${modifier} is emitted at ${mOff}, before ${base} at ${bOff}, so ${base} wins and ` +
        `${modifier} does nothing. Order inside @layer utilities is Tailwind's property-set ` +
        `sort, not source order -- adding a property to the modifier can move it ahead of its ` +
        `base without anything in the source looking different.`,
      ).toBe(true)
    }
  })
})
