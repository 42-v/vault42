// Client
export { VaultClient, VaultAPIError } from './client'

// Plugin
export { createVaultPlugin, useVaultClient } from './plugin'
export type { VaultPluginOptions } from './plugin'

// Composables
export { useAuth, getAuthState } from './composables/useAuth'
export { useProfile } from './composables/useProfile'
export { useSessions } from './composables/useSessions'
export { use2FA } from './composables/use2FA'
export { usePasswordReset } from './composables/usePasswordReset'
export { useWebAuthn } from './composables/useWebAuthn'
export { useOAuth } from './composables/useOAuth'
export { useConfirm } from './composables/useConfirm'
export { useIdentity } from './composables/useIdentity'
export { useBlobs } from './composables/useBlobs'

// I18n
export { createI18n, createI18nPlugin, useT, I18N_KEY } from './i18n'
export type { LocaleMessages, MessageResolver, I18nOptions, I18nInstance } from './i18n'

// Components
export { default as VaultLoginForm } from './components/VaultLoginForm.vue'
export { default as VaultRegisterForm } from './components/VaultRegisterForm.vue'
export { default as VaultAuthGuard } from './components/VaultAuthGuard.vue'
export { default as VaultTokenDebug } from './components/VaultTokenDebug.vue'

// Types
export type {
  VaultClientOptions,
  VaultError,
  RegisterResult,
  LoginResult,
  RefreshResult,
  UserProfile,
  Session,
  Device,
  TOTPSetupResult,
  DecodedJWT,
  JWK,
  JWKS,
  OIDCConfig,
  WebAuthnCreationOptions,
  WebAuthnAssertionOptions,
  OAuthProvider,
  MFAStatus,
  WebAuthnCredential,
  ConfirmResult,
  IdentityData,
  BillingInfo,
  BlobMeta,
  BlobUploadResult,
  BlobListResult,
  BlobQuota,
  Capabilities,
} from './types'
