import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join, relative, resolve as resolvePath } from 'node:path'

/**
 * Every rendered failure has to reach a screen reader.
 *
 * Before this gate the app contained not one `role="alert"`, `role="status"` or
 * `aria-live` anywhere: a screen-reader user who mistyped a password, failed a
 * TOTP challenge, was refused a WebAuthn assertion or followed a dead reset link
 * heard nothing at all, because the error banner is inserted into a plain `div`
 * with no live region. The page simply appeared not to have responded.
 *
 * A component test per view would prove the same thing thirteen times over and
 * would still say nothing about the fourteenth view somebody adds. This reads
 * the templates instead, so a new error banner without a live region fails here
 * rather than shipping silent.
 */

const srcDir = resolvePath(dirname(fileURLToPath(import.meta.url)), '..')
const sdkDir = resolvePath(srcDir, '../../packages/vue/src')

/** Class fragments that mark an element as a rendered failure message. */
const ERROR_MARKERS = ['vault42-alert-error', 'vault42-login-form__error', 'vault42-register-form__error']

/** Anything that satisfies WCAG 4.1.3 for a message inserted after page load. */
const LIVE_REGION = /\brole="(alert|status)"|\baria-live="/

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

/**
 * Splits a template into opening tags. A tag may span several lines, so a
 * line-based scan would miss the attribute it is looking for.
 */
function openingTags(source: string): string[] {
  return [...source.matchAll(/<[a-zA-Z][^>]*>/g)].map(m => m[0])
}

const allFiles = [...vueFiles(join(srcDir, 'views')), join(srcDir, 'App.vue'), ...vueFiles(sdkDir)]

describe('error surfaces are announced', () => {
  it('finds the templates it is meant to be reading', () => {
    // A path typo would make every assertion below vacuously true.
    expect(allFiles.length).toBeGreaterThanOrEqual(18)
  })

  it('gives every rendered error message a live region', () => {
    const silent: string[] = []

    for (const file of allFiles) {
      const source = readFileSync(file, 'utf8')
      for (const tag of openingTags(source)) {
        if (!ERROR_MARKERS.some(marker => tag.includes(marker))) continue
        if (LIVE_REGION.test(tag)) continue
        silent.push(`${relative(srcDir, file)}: ${tag.replace(/\s+/g, ' ')}`)
      }
    }

    expect(silent).toEqual([])
  })

  it('announces the login and 2FA failures the SDK renders', () => {
    // The single highest-traffic failure path in the product, pinned by name so
    // a refactor of VaultLoginForm cannot quietly drop it.
    const source = readFileSync(join(sdkDir, 'components/VaultLoginForm.vue'), 'utf8')
    const alerts = openingTags(source).filter(tag => tag.includes('role="alert"'))

    expect(alerts.length).toBe(2)
    expect(source).toContain('aria-describedby')
    expect(source).toContain('aria-invalid')
  })
})
