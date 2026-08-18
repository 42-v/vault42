import { describe, it, expect, vi } from 'vitest'
import { friendlyError } from '../errorMessages'
import en from '../locales/en.json'

const copy = en as Record<string, string>

// House-style i18n shim: resolves against the real English copy so assertions are
// made against the strings a user actually sees, and returns the key itself when a
// translation is missing (exactly what the real createI18n does).
vi.mock('@vault42/vue', () => ({
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = copy[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => (params[name] != null ? String(params[name]) : `{${name}}`))
    },
  }),
}))

// Every code the API can return, mirrored from errorMessages.ts. Kept as a literal
// list on purpose: if someone deletes a mapping, this test notices.
const MAPPED_CODES = [
  'invalid_credentials',
  'invalid_client_credentials',
  'unauthorized',
  'missing_authorization',
  'invalid_authorization',
  'unable_to_identify_user',
  'session_expired',
  'token_expired',
  'invalid_token',
  'invalid_token_type',
  'missing_refresh_token',
  'challenge_consumed',
  'account_locked',
  'account_banned',
  'account_disabled',
  'account_unavailable',
  'too_many_attempts',
  'too_many_sessions',
  'server_busy',
  'rate_limiter_unavailable',
  'dpop_replay_check_unavailable',
  'registration_disabled',
  'email_already_registered',
  'email_not_verified',
  'password_too_short',
  'password_breached',
  'password_recently_used',
  'invalid_email',
  'invalid_password',
  'invalid_current_password',
  'password_same_as_current',
  'invalid_or_expired_token',
  'invalid_or_expired_code',
  'invalid_code',
  'invalid_totp_code',
  'totp_already_enabled',
  'totp_already_setup',
  'totp_not_enabled',
  'totp_not_setup',
  'totp_code_already_used',
  'backup_code_already_used',
  'invalid_backup_code',
  'webauthn_not_supported',
  'webauthn_not_configured',
  'webauthn_registration_failed',
  'webauthn_authentication_failed',
  'webauthn_verification_failed',
  'webauthn_error',
  'cloned_authenticator_detected',
  'credential_already_registered',
  'user_verification_required',
  'no_webauthn_credentials',
  'oauth_failed',
  'provider_denied',
  'provider_error',
  'provider_not_configured',
  'unknown_provider',
  'invalid_state',
  'invalid_or_reused_state',
  'missing_state',
  'state_expired',
  'replay_detected',
  'concurrent_update',
  'no_pending_registration',
  'no_pending_verification',
  'dpop_proof_reused',
  'blob_too_large',
  'blob_too_small',
  'quota_exceeded',
  'blob_not_found',
  'empty_blob',
  'missing_name',
  'name_too_long',
  'identity_not_found',
  'not_found',
  'device_not_found',
  'session_not_found',
  'credential_not_found',
  'forbidden',
  'access_denied',
  'insufficient_scope',
  'rate_limited',
  'rate_limit_exceeded',
  'invalid_request',
  'invalid_input',
  'invalid_profile',
  'invalid_label',
  'invalid_scope',
  'invalid_country',
  'invalid_billing_country',
  'invalid_date_of_birth',
  'name_required',
  'name_invalid_chars',
  'password_required',
  'code_required',
  'missing_code',
  'missing_id',
  'missing_file',
  'missing_credential_id',
  'missing_device_id',
  'missing_session_id',
  'unwrap_failed',
  'dpop_proof_required',
  'invalid_dpop_proof',
  'dpop_thumbprint_mismatch',
  'dpop_scheme_required',
  'internal_error',
  'internal_server_error',
  'import_claim_failed',
  'verification_failed',
  'missing_token',
]

// Mirrored from the Go side: every string the public API puts in the `error`
// field of a JSON error body. Sources are `WriteError(w, ..., "<code>")` calls
// under internal/handler, internal/server and internal/middleware, plus the
// three validateIdentity() messages that internal/handler/identity.go forwards
// verbatim via err.Error() and the two package-level constants.
//
// Regenerate with:
//   grep -rhoE 'WriteError\(w, [^,]+, "[a-z0-9_]+"' internal/handler internal/server internal/middleware
const SERVER_CODES = [
  'access_denied',
  'account_banned',
  'account_disabled',
  'account_locked',
  'account_unavailable',
  'backup_code_already_used',
  'blob_not_found',
  'blob_too_large',
  'blob_too_small',
  'challenge_consumed',
  'cloned_authenticator_detected',
  'code_required',
  'concurrent_update',
  'credential_already_registered',
  'credential_not_found',
  'device_not_found',
  'dpop_proof_required',
  'dpop_proof_reused',
  'dpop_replay_check_unavailable',
  'dpop_scheme_required',
  'dpop_thumbprint_mismatch',
  'email_already_registered',
  'empty_blob',
  'forbidden',
  'identity_not_found',
  'import_claim_failed',
  'insufficient_scope',
  'internal_error',
  'internal_server_error',
  'invalid_authorization',
  'invalid_backup_code',
  'invalid_billing_country',
  'invalid_client_credentials',
  'invalid_code',
  'invalid_country',
  'invalid_credentials',
  'invalid_current_password',
  'invalid_date_of_birth',
  'invalid_dpop_proof',
  'invalid_input',
  'invalid_label',
  'invalid_or_expired_code',
  'invalid_or_expired_token',
  'invalid_or_reused_state',
  'invalid_password',
  'invalid_profile',
  'invalid_request',
  'invalid_scope',
  'invalid_state',
  'invalid_token',
  'invalid_token_type',
  'missing_authorization',
  'missing_code',
  'missing_credential_id',
  'missing_device_id',
  'missing_file',
  'missing_id',
  'missing_name',
  'missing_refresh_token',
  'missing_session_id',
  'missing_state',
  'missing_token',
  'name_invalid_chars',
  'name_required',
  'name_too_long',
  'no_pending_registration',
  'no_pending_verification',
  'no_webauthn_credentials',
  'not_found',
  'password_breached',
  'password_recently_used',
  'password_required',
  'password_too_short',
  'provider_denied',
  'provider_error',
  'quota_exceeded',
  'rate_limit_exceeded',
  'rate_limiter_unavailable',
  'registration_disabled',
  'replay_detected',
  'server_busy',
  'session_not_found',
  'state_expired',
  'token_expired',
  'too_many_attempts',
  'too_many_sessions',
  'totp_already_setup',
  'totp_code_already_used',
  'totp_not_setup',
  'unable_to_identify_user',
  'unauthorized',
  'unknown_provider',
  'unwrap_failed',
  'user_verification_required',
  'webauthn_error',
  'webauthn_not_configured',
  'webauthn_verification_failed',
]

// requires_confirmation (middleware.Confirmed) is deliberately not mapped: it is
// not an error to show, it is the signal that opens the re-authentication prompt.
// Anything else added here without copy is a bug, not an exemption.
const UNMAPPED_BY_DESIGN = ['requires_confirmation']

describe('friendlyError', () => {
  it('renders a human sentence for every mapped server error code', () => {
    // Codes that mean the same thing to a user share one translation key, so the
    // key is not always `error.<code>`. What must hold for all of them: the copy
    // exists in en.json, and it is a sentence rather than a leaked key.
    const errorCopy = new Set(
      Object.entries(copy).filter(([key]) => key.startsWith('error.')).map(([, value]) => value),
    )

    for (const code of MAPPED_CODES) {
      const message = friendlyError(code)

      // A missing translation surfaces as the raw key, which is the silent failure
      // this guards against: the user would see "error.blob_too_large" in a banner.
      expect(message, `no en.json copy for ${code}`).not.toBe(`error.${code}`)
      expect(message, `${code} resolves to copy that is not in en.json`).toBeOneOf([...errorCopy])
      expect(message).not.toMatch(/^[a-z0-9_]+\.[a-z0-9_]+$/i)
      expect(message.trim().length).toBeGreaterThan(0)
    }
  })

  it('never lets a mapped code silently render the generic fallback', () => {
    // Mapping a code to a key that has no copy would resolve to the key string;
    // mapping it to error.fallback would be indistinguishable from not mapping
    // it at all. Both are ways for this table to look complete while being empty.
    for (const code of MAPPED_CODES) {
      expect(friendlyError(code), `${code} renders the fallback despite being mapped`).not.toBe(copy['error.fallback'])
    }
  })

  it('has copy for every error code the server can emit', () => {
    // The whole point of this module is that a raw wire code never reaches the
    // user. A code the server sends but we never mapped renders the generic
    // fallback, which is safe but useless: the account_banned 403 would read
    // "Something went wrong. Please try again."
    const uncovered = SERVER_CODES.filter(
      code => !MAPPED_CODES.includes(code) && !UNMAPPED_BY_DESIGN.includes(code),
    )

    expect(uncovered).toEqual([])
  })

  it('gives the toggle and capacity errors their own copy instead of a shrug', () => {
    expect(friendlyError('server_busy')).toBe('The server is busy right now. Please try again in a moment.')
    expect(friendlyError('account_banned')).toBe('This account has been banned. Contact support if you think this is a mistake.')
    expect(friendlyError('account_disabled')).toBe('This account has been disabled. Contact support for help.')
    expect(friendlyError('too_many_sessions')).toBe('You have too many active sessions. Sign out on another device and try again.')
    expect(friendlyError('registration_disabled')).toBe('New account registration is currently disabled.')

    for (const code of ['server_busy', 'account_banned', 'account_disabled', 'too_many_sessions', 'registration_disabled']) {
      expect(friendlyError(code), `${code} fell through to the fallback`).not.toBe(copy['error.fallback'])
    }
  })

  it('does not tell a banned user their account is only temporarily locked', () => {
    // account_banned and account_disabled are permanent; account_locked is the
    // rate-limit lockout that clears itself. Collapsing them would be worse copy
    // than the generic fallback, because it is confidently wrong.
    expect(friendlyError('account_banned')).not.toBe(copy['error.account_locked'])
    expect(friendlyError('account_disabled')).not.toBe(copy['error.account_locked'])
    expect(friendlyError('account_banned')).not.toBe(friendlyError('account_disabled'))
  })

  it('maps codes to their own distinct copy rather than collapsing to the fallback', () => {
    expect(friendlyError('invalid_credentials')).toBe('Invalid email or password.')
    expect(friendlyError('quota_exceeded')).toBe('Storage quota exceeded.')
    expect(friendlyError('rate_limited')).toBe('Too many requests. Please wait a moment.')
    expect(friendlyError('quota_exceeded')).not.toBe(copy['error.fallback'])
  })

  it('uses the unknown-error copy when no code is supplied', () => {
    expect(friendlyError(undefined)).toBe('An unexpected error occurred.')
  })

  it('treats an empty-string code as no code at all', () => {
    // '' is falsy, so it must take the same branch as undefined rather than
    // looking up errorKeys[''] and rendering nothing.
    expect(friendlyError('')).toBe('An unexpected error occurred.')
    expect(friendlyError('').trim().length).toBeGreaterThan(0)
  })

  it('falls back to safe generic copy for an unrecognised code', () => {
    const message = friendlyError('some_code_we_have_never_seen')
    expect(message).toBe('Something went wrong. Please try again.')
    expect(message).not.toBe(copy['error.unknown'])
  })

  it('never echoes attacker-controlled server text back into the DOM', () => {
    // The code string comes straight off the wire. It must never reach the
    // rendered string — this is an injection surface, not just a cosmetic issue.
    const payloads = [
      '<script>alert(1)</script>',
      '"><img src=x onerror=alert(1)>',
      'javascript:alert(document.cookie)',
      '{{constructor.constructor("alert(1)")()}}',
      'error.fallback',
      'common.save',
      '../../locales/en.json',
    ]

    for (const payload of payloads) {
      const message = friendlyError(payload)
      expect(message, `friendlyError leaked ${payload}`).toBe('Something went wrong. Please try again.')
      expect(message).not.toContain(payload)
      expect(message).not.toMatch(/[<>]/)
    }
  })

  it('does not resolve inherited Object.prototype members as if they were mappings', () => {
    // A bare errorKeys[code] lookup hands back Object.prototype.toString for the
    // code "toString". That is truthy, so it reaches t(), which calls .split on
    // it and throws — a server-chosen string that crashes the error banner and
    // takes the surrounding render with it.
    const inherited = [
      'toString',
      'valueOf',
      'constructor',
      'hasOwnProperty',
      'isPrototypeOf',
      'propertyIsEnumerable',
      'toLocaleString',
      '__proto__',
      '__defineGetter__',
    ]

    for (const code of inherited) {
      expect(() => friendlyError(code), `friendlyError threw on ${code}`).not.toThrow()
      expect(friendlyError(code), `${code} resolved to something other than the fallback`).toBe('Something went wrong. Please try again.')
    }
  })

  it('does not let a raw i18n key sent by the server resolve to arbitrary copy', () => {
    // A server (or MITM) sending "common.delete" must not be able to pick any
    // string out of the locale bundle — only the curated error.* set is reachable.
    expect(friendlyError('common.delete')).not.toBe(copy['common.delete'])
    expect(friendlyError('login.title')).not.toBe(copy['login.title'])
  })

  it('always returns a non-empty string, whatever it is handed', () => {
    const inputs = [undefined, '', 'unauthorized', 'nope', 'UPPERCASE', '  spaced  ', '42']
    for (const input of inputs) {
      const message = friendlyError(input)
      expect(typeof message).toBe('string')
      expect(message.length).toBeGreaterThan(0)
    }
  })

  it('is case-sensitive and does not accidentally match a differently-cased code', () => {
    expect(friendlyError('UNAUTHORIZED')).toBe('Something went wrong. Please try again.')
    expect(friendlyError('unauthorized')).toBe(copy['error.unauthorized'])
  })

  it('does not reach outside the curated error set for ordinary unknown codes', () => {
    // Guards the shape of the lookup for every realistic code: only error.* copy is
    // reachable, everything else lands on the single fallback sentence.
    const unknown = ['blob_exploded', 'teapot', 'error', 'unknown', 'fallback', 'errorKeys', 'default']
    for (const code of unknown) {
      expect(friendlyError(code), `unexpected copy for ${code}`).toBe('Something went wrong. Please try again.')
    }
  })
})
