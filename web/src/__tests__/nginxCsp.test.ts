import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, resolve as resolvePath } from 'node:path'

/**
 * Keeps `web/nginx.conf` from drifting back into being the weakest policy in the
 * repository.
 *
 * The nginx image is not how a shipped vault serves this dashboard — the Go
 * binary does, from `go:embed`, under `internal/middleware/security_headers`.
 * That is exactly why the file was dangerous: nobody exercised it, so nobody
 * noticed it allowed `connect-src 'self' http://localhost:* https://*`, and it
 * is the first hit anyone grepping the repo for `connect-src` finds and copies.
 *
 * A wildcard there is not academic here. The access token lives in JavaScript
 * memory by design (`packages/vue/src/client.ts`), with no localStorage, no
 * cookie the page can read and no other XSS-reachable store. `connect-src` is
 * the control that closes the one remaining exfiltration route.
 */
const nginxConf = readFileSync(
  resolvePath(dirname(fileURLToPath(import.meta.url)), '../../nginx.conf'),
  'utf8',
)

const csp = /add_header Content-Security-Policy "([^"]+)"/.exec(nginxConf)?.[1] ?? ''

/** Directive -> the value it must have, and why anything looser is a hole. */
const REQUIRED_DIRECTIVES: Record<string, string> = {
  'default-src': "'self'",
  'script-src': "'self'",
  'style-src': "'self'",
  'connect-src': "'self'",
  'object-src': "'none'",
  'frame-ancestors': "'none'",
  'base-uri': "'self'",
  'form-action': "'self'",
}

function directive(name: string): string {
  const found = csp.split(';').map(part => part.trim()).find(part => part.startsWith(`${name} `))
  return found ? found.slice(name.length + 1).trim() : ''
}

describe('web/nginx.conf content security policy', () => {
  it('declares a policy at all', () => {
    expect(csp).not.toBe('')
  })

  it.each(Object.entries(REQUIRED_DIRECTIVES))('pins %s to %s', (name, value) => {
    expect(directive(name)).toBe(value)
  })

  it('permits no wildcard or plaintext source anywhere', () => {
    // `https://*` is a token-exfiltration channel; `http://localhost:*` is a dev
    // convenience that has no business in an image definition.
    expect(csp).not.toContain('*')
    expect(csp).not.toContain('http://')
    expect(csp).not.toContain("'unsafe-inline'")
    expect(csp).not.toContain("'unsafe-eval'")
  })

  it('keeps the headers that the Go path also sets', () => {
    for (const header of [
      'Strict-Transport-Security',
      'X-Content-Type-Options',
      'X-Frame-Options',
      'Referrer-Policy',
      'Cross-Origin-Opener-Policy',
      'Cross-Origin-Resource-Policy',
    ]) {
      expect(nginxConf, `${header} is missing`).toContain(`add_header ${header} `)
    }
  })

  it('still refuses to serve source maps', () => {
    expect(nginxConf).toContain('\\.map$')
    expect(nginxConf).toContain('return 404')
  })
})
