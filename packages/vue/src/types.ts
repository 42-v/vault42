export interface VaultClientOptions {
  /** Called on every request to add headers (e.g. fingerprint consistency) */
  onRequest?: (init: RequestInit) => RequestInit
}

export interface VaultError {
  code: string
  status: number
  message?: string
}

export interface RegisterResult {
  user_id: string
  email: string
}

export interface LoginResult {
  access_token: string
  token_type: string
  expires_in: number
  requires_2fa?: boolean
  challenge_token?: string
  available_methods?: string[]
}

export interface RefreshResult {
  access_token: string
  token_type: string
  expires_in: number
}

export interface UserProfile {
  id: string
  email: string
  email_verified: boolean
  display_name: string
  avatar_url: string
  locale: string
  mfa_required: boolean
  mfa_enabled: boolean
  mfa_methods: string[]
  created_at: string
  updated_at: string
}

export interface Session {
  id: string
  friendly_name?: string
  ip: string
  user_agent: string
  trusted: boolean
  last_seen_at?: string
  first_seen_at: string
}

export interface Device {
  id: string
  friendly_name: string
  trusted: boolean
  trusted_until?: string
  ip: string
  user_agent: string
  last_seen_at?: string
  first_seen_at: string
  created_at: string
}

export interface TOTPSetupResult {
  secret: string
  otp_url: string
}

export interface DecodedJWT {
  header: { alg: string; kid: string; typ: string }
  payload: Record<string, unknown>
}

export interface JWK {
  kty: string
  use: string
  kid: string
  alg: string
  n: string
  e: string
}

export interface JWKS {
  keys: JWK[]
}

export interface OIDCConfig {
  issuer: string
  authorization_endpoint: string
  token_endpoint: string
  jwks_uri: string
  [key: string]: unknown
}

export interface PasswordResetRequestResult {
  status: string
}

export interface PasswordResetConfirmResult {
  status: string
}

export interface PasswordChangeResult {
  status: string
}

// --- MFA Status ---

export interface MFAStatus {
  totp_enabled: boolean
  webauthn_enabled: boolean
  backup_codes_remaining: number
  available_methods: string[]
  mfa_required: boolean
}

// --- WebAuthn ---

/** Server response for webauthn register/begin — maps to PublicKeyCredentialCreationOptions. */
export interface WebAuthnCreationOptions {
  publicKey: {
    challenge: string
    rp: { name: string; id: string }
    user: { id: string; name: string; displayName: string }
    pubKeyCredParams: Array<{ type: string; alg: number }>
    timeout?: number
    excludeCredentials?: Array<{ type: string; id: string; transports?: string[] }>
    authenticatorSelection?: {
      authenticatorAttachment?: string
      residentKey?: string
      requireResidentKey?: boolean
      userVerification?: string
    }
    attestation?: string
  }
}

/** Server response for webauthn verify/begin — maps to PublicKeyCredentialRequestOptions. */
export interface WebAuthnAssertionOptions {
  publicKey: {
    challenge: string
    timeout?: number
    rpId?: string
    allowCredentials?: Array<{ type: string; id: string; transports?: string[] }>
    userVerification?: string
  }
}

/** A registered WebAuthn credential (from GET /auth/2fa/webauthn/credentials). */
export interface WebAuthnCredential {
  id: string
  sign_count: number
  created_at: string
}

/** Result from POST /auth/confirm. */
export interface ConfirmResult {
  confirmed: boolean
  expires_in: number
}

// --- Identity ---

export interface IdentityData {
  given_name?: string
  family_name?: string
  country?: string
  date_of_birth?: string
  sex?: string
  billing?: BillingInfo
  updated_at?: string
}

export interface BillingInfo {
  address_line_1?: string
  address_line_2?: string
  city?: string
  postal_code?: string
  country?: string
  vat_id?: string
}

// --- Blobs ---

export interface BlobMeta {
  id: string
  label?: string
  named: boolean
  size_bytes: number
  stored_bytes: number
  checksum: string
  created_at: string
}

export interface BlobUploadResult {
  id: string
  label: string
  size_bytes: number
  stored_bytes: number
  checksum: string
  created_at: string
}

export interface BlobListResult {
  blobs: BlobMeta[]
  count: number
  quota: BlobQuota
}

export interface BlobQuota {
  used_bytes: number
  max_bytes: number
  used_count: number
  max_count: number
}

// --- Capabilities ---

export interface Capabilities {
  registration_enabled: boolean
  mfa_required: boolean
  oauth_providers: string[]
}

// --- OAuth ---

export type OAuthProvider = 'github' | 'google' | 'facebook'
