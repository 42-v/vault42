import { describe, it, expect, vi, afterEach } from 'vitest'
import { resolveVaultURL } from '../config'

const ORIGIN = 'https://vault.example.com'

afterEach(() => {
  vi.restoreAllMocks()
})

describe('resolveVaultURL', () => {
  it('uses the page origin when no override is set', () => {
    expect(resolveVaultURL({}, ORIGIN)).toBe(ORIGIN)
  })

  it('treats an empty or whitespace override as absent', () => {
    expect(resolveVaultURL({ VITE_VAULT_URL: '' }, ORIGIN)).toBe(ORIGIN)
    expect(resolveVaultURL({ VITE_VAULT_URL: '   ' }, ORIGIN)).toBe(ORIGIN)
  })

  it('honours the override in a development build', () => {
    expect(resolveVaultURL({ VITE_VAULT_URL: 'https://vault.localhost' }, ORIGIN))
      .toBe('https://vault.localhost')
  })

  it('honours the override when PROD is explicitly false', () => {
    expect(resolveVaultURL({ PROD: false, VITE_VAULT_URL: 'https://dev.test' }, ORIGIN))
      .toBe('https://dev.test')
  })

  it('trims surrounding whitespace off an accepted override', () => {
    expect(resolveVaultURL({ VITE_VAULT_URL: '  https://dev.test  ' }, ORIGIN))
      .toBe('https://dev.test')
  })

  it('discards a production override that was not opted into', () => {
    // The regression this exists for: a developer's web/.env used to survive
    // `vite build`, get copied into internal/frontend/dist, and ship inside the
    // Go binary pointing every API call at https://vault.localhost.
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    expect(resolveVaultURL({ PROD: true, VITE_VAULT_URL: 'https://vault.localhost' }, ORIGIN))
      .toBe(ORIGIN)
    expect(warn).toHaveBeenCalledOnce()
  })

  it('discards a production override when the opt-in is not exactly "true"', () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})

    for (const optIn of ['1', 'yes', 'TRUE', 'false', '']) {
      expect(
        resolveVaultURL(
          { PROD: true, VITE_VAULT_URL: 'https://vault.localhost', VITE_VAULT_URL_ALLOW_PRODUCTION: optIn },
          ORIGIN,
        ),
      ).toBe(ORIGIN)
    }
    expect(warn).toHaveBeenCalledTimes(5)
  })

  it('honours a production override that explicitly opted in', () => {
    // A gateway deployment that genuinely serves the SPA off a different origin
    // is still possible; it just has to say so.
    expect(
      resolveVaultURL(
        {
          PROD: true,
          VITE_VAULT_URL: 'https://api.example.com',
          VITE_VAULT_URL_ALLOW_PRODUCTION: 'true',
        },
        ORIGIN,
      ),
    ).toBe('https://api.example.com')
  })
})
