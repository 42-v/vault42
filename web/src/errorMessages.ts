import { useT } from '@vault42/vue'

/** Maps API error codes to i18n translation keys. */
const errorKeys: Record<string, string> = {
  invalid_credentials: 'error.invalid_credentials',
  unauthorized: 'error.unauthorized',
  session_expired: 'error.session_expired',
  token_expired: 'error.token_expired',
  account_locked: 'error.account_locked',
  too_many_attempts: 'error.too_many_attempts',
  email_already_registered: 'error.email_already_registered',
  password_too_short: 'error.password_too_short',
  password_breached: 'error.password_breached',
  invalid_email: 'error.invalid_email',
  invalid_password: 'error.invalid_password',
  password_same_as_current: 'error.password_same_as_current',
  invalid_or_expired_token: 'error.invalid_or_expired_token',
  invalid_totp_code: 'error.invalid_totp_code',
  totp_already_enabled: 'error.totp_already_enabled',
  totp_not_enabled: 'error.totp_not_enabled',
  invalid_backup_code: 'error.invalid_backup_code',
  webauthn_not_supported: 'error.webauthn_not_supported',
  webauthn_registration_failed: 'error.webauthn_registration_failed',
  webauthn_authentication_failed: 'error.webauthn_authentication_failed',
  oauth_failed: 'error.oauth_failed',
  provider_not_configured: 'error.provider_not_configured',
  blob_too_large: 'error.blob_too_large',
  blob_too_small: 'error.blob_too_small',
  quota_exceeded: 'error.quota_exceeded',
  blob_not_found: 'error.blob_not_found',
  empty_blob: 'error.empty_blob',
  missing_name: 'error.missing_name',
  name_too_long: 'error.name_too_long',
  identity_not_found: 'error.identity_not_found',
  rate_limited: 'error.rate_limited',
  internal_error: 'error.internal_error',
  verification_failed: 'error.verification_failed',
  missing_token: 'error.missing_token',
}

export function friendlyError(code: string | undefined): string {
  const { t } = useT()
  if (!code) return t('error.unknown')
  const key = errorKeys[code]
  if (key) return t(key)
  return t('error.fallback')
}
