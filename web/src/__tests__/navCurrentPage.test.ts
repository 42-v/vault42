import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * A link marked as current has to say so to something other than an eye.
 *
 * The nav already knew which entry was active -- isActive(link.to) picks the
 * highlight -- and expressed it only as a background colour and a text shade.
 * A screen-reader user tabbing the navigation heard the same thing on every
 * entry and could not tell which page they were on. WCAG 1.3.1: information
 * conveyed through presentation has to be available programmatically.
 *
 * The gate reads templates rather than mounting the component, because the
 * property is about every link the nav grows later, not the three that exist
 * now. It works by pairing: any element whose class binding consults isActive
 * must also bind aria-current from the same call. Two expressions of one fact,
 * and they have to agree.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')

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

/** Whole opening tags, which may span lines and carry multi-line bindings. */
function openingTags(source: string): string[] {
  return [...source.matchAll(/<[a-zA-Z][^>]*>/g)].map(m => m[0])
}

describe('current page indication', () => {
  const files = vueFiles(srcDir)

  it('scans a non-empty set of templates', () => {
    expect(files.length).toBeGreaterThan(0)
  })

  it('pairs every isActive highlight with aria-current', () => {
    const problems: string[] = []
    let paired = 0

    for (const file of files) {
      const source = readFileSync(file, 'utf8')
      const where = relative(resolvePath(srcDir, '../..'), file)
      for (const tag of openingTags(source)) {
        if (!tag.includes('isActive(')) continue
        if (tag.includes('aria-current')) {
          paired++
          continue
        }
        problems.push(
          `${where}: an element decides its appearance from isActive() but binds no ` +
          `aria-current, so the current page is signalled by colour alone.\n    ` +
          tag.replace(/\s+/g, ' ').slice(0, 160),
        )
      }
    }

    // A gate that pairs nothing proves nothing.
    expect(paired).toBeGreaterThan(0)
    expect(problems.join('\n')).toBe('')
  })
})
