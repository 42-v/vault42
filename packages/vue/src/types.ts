/** Optional behaviour hooks for {@link VaultClient}. */
export interface VaultClientOptions {
  /** Called on every request to add headers (e.g. fingerprint consistency) */
  onRequest?: (init: RequestInit) => RequestInit
}

/**
 * The shape every failed call rejects with. `VaultAPIError` implements it, and
 * the composables store it in their `error` refs.
 */
export interface VaultError {
  /** Machine-readable failure code. Branch on this, never on `message`. */
  code: string
  /** HTTP status, or `0` when the error was raised before the request was sent. */
  status: number
  /** Diagnostic detail. Not UI copy and not part of the contract. */
  message?: string
}

/** Result of `POST /auth/register`. */
export interface RegisterResult {
  /** The new account's identifier. */
  user_id: string
  /** The registered address. Not yet verified at this point. */
  email: string
}

/**
 * Result of a sign-in attempt, and of each second-factor verification.
 *
 * A response with `requires_2fa` set is **not** a completed login: it carries no
 * usable `access_token`, only a `challenge_token` authorising the second-factor
 * call.
 */
export interface LoginResult {
  /** The bearer token. Empty or absent when `requires_2fa` is set. */
  access_token: string
  /** Always `Bearer` for a completed login. */
  token_type: string
  /** Access-token lifetime in seconds. */
  expires_in: number
  /** True when the password step succeeded but a second factor is outstanding. */
  requires_2fa?: boolean
  /** Short-lived token authorising only the second-factor verification call. */
  challenge_token?: string
  /** Factors the server will accept, e.g. `totp`, `webauthn`, `backup_code`, `email_otp`. */
  available_methods?: string[]
}

/**
 * Result of `POST /auth/refresh`. The new refresh token, when one is issued,
 * travels as an HttpOnly cookie and never appears here.
 */
export interface RefreshResult {
  /** The new bearer token. */
  access_token: string
  /** Always `Bearer`. */
  token_type: string
  /** Access-token lifetime in seconds. */
  expires_in: number
}

/** The signed-in user's profile, from `GET /user/profile`. */
export interface UserProfile {
  /** Stable account identifier, matching the token's `sub` claim. */
  id: string
  /** Current address. Changing it re-triggers verification. */
  email: string
  /** Whether the address has been confirmed. */
  email_verified: boolean
  /** User-chosen display name. May be empty. */
  display_name: string
  /** Avatar URL. May be empty. */
  avatar_url: string
  /** Preferred locale tag, for example `en` or `sk`. */
  locale: string
  /** Whether policy obliges this user to hold a second factor. */
  mfa_required: boolean
  /** Whether the user currently has one enrolled. */
  mfa_enabled: boolean
  /** The enrolled factors. */
  mfa_methods: string[]
  /** RFC 3339 timestamp. */
  created_at: string
  /** RFC 3339 timestamp. */
  updated_at: string
}

/**
 * One active session, from `GET /user/sessions`.
 *
 * A session is a live credential; a {@link Device} is the recognised machine it
 * belongs to. Revoking either revokes the other's tokens.
 */
export interface Session {
  /** Session identifier, for `revokeSession`. */
  id: string
  /** Device label, when the session is tied to a named device. */
  friendly_name?: string
  /** Client IP recorded for the session. */
  ip: string
  /** User agent recorded for the session. */
  user_agent: string
  /** Whether the session's device has been marked trusted, which can relax MFA prompts. */
  trusted: boolean
  /** RFC 3339 timestamp. Absent until the session is used a second time. */
  last_seen_at?: string
  /** RFC 3339 timestamp of first use. */
  first_seen_at: string
}

/** A recognised device, from `GET /user/devices`. */
export interface Device {
  /** Device identifier, for `renameDevice` and `removeDevice`. */
  id: string
  /** User-editable label. */
  friendly_name: string
  /** Whether the device is trusted. */
  trusted: boolean
  /** RFC 3339 timestamp at which trust lapses. Absent when trust does not expire. */
  trusted_until?: string
  /** Most recent IP seen for the device. */
  ip: string
  /** Most recent user agent seen for the device. */
  user_agent: string
  /** RFC 3339 timestamp. Absent until the device is used a second time. */
  last_seen_at?: string
  /** RFC 3339 timestamp of first use. */
  first_seen_at: string
  /** RFC 3339 timestamp of enrolment. */
  created_at: string
}

/**
 * Result of `POST /auth/2fa/totp/setup`. Returned once and never again, so the
 * app must render it before the user can navigate away.
 */
export interface TOTPSetupResult {
  /** Base32 shared secret, for manual entry. */
  secret: string
  /** The `otpauth://` URL to render as a QR code. */
  otp_url: string
}

/**
 * A JWT decoded **without** signature verification, for display only. Never
 * make an authorization decision from this; the server validates the token
 * properly on every request.
 */
export interface DecodedJWT {
  /** The JOSE header. */
  header: { alg: string; kid: string; typ: string }
  /** The raw claim set. */
  payload: Record<string, unknown>
}

/** One RSA public key from the server's JWKS. */
export interface JWK {
  /** Key type. Always `RSA`. */
  kty: string
  /** Intended use. `sig` for the signing keys. */
  use: string
  /** Key identifier, matching a token's `kid` header. */
  kid: string
  /** Algorithm. Always `RS256`. */
  alg: string
  /** base64url RSA modulus. */
  n: string
  /** base64url RSA public exponent. */
  e: string
}

/** The key set from `GET /.well-known/jwks.json`. */
export interface JWKS {
  /** The published signing keys. More than one appears during rotation. */
  keys: JWK[]
}

/**
 * The discovery document from `GET /.well-known/openid-configuration`. Indexed
 * so any field the spec defines is reachable, not only the four named here.
 */
export interface OIDCConfig {
  /** Token issuer identifier. */
  issuer: string
  /** Authorization endpoint URL. */
  authorization_endpoint: string
  /** Token endpoint URL. */
  token_endpoint: string
  /** JWKS URL. */
  jwks_uri: string
  /** Any other advertised metadata. */
  [key: string]: unknown
}

/**
 * Acknowledgement of a password-reset request. Identical whether or not the
 * address exists, so it cannot be used to enumerate accounts.
 */
export interface PasswordResetRequestResult {
  /** Server-supplied status string. */
  status: string
}

/** Acknowledgement of a completed password reset. */
export interface PasswordResetConfirmResult {
  /** Server-supplied status string. */
  status: string
}

/** Acknowledgement of a completed password change. */
export interface PasswordChangeResult {
  /** Server-supplied status string. */
  status: string
}

// --- MFA Status ---

/** The user's second-factor configuration, from `GET /auth/2fa/status`. */
export interface MFAStatus {
  /** Whether an authenticator app is enrolled. */
  totp_enabled: boolean
  /** Whether at least one security key is enrolled. */
  webauthn_enabled: boolean
  /** Unused backup codes left. Regenerating replaces the whole set. */
  backup_codes_remaining: number
  /** Factors accepted at sign-in for this user. */
  available_methods: string[]
  /** Whether policy obliges this user to hold a second factor. */
  mfa_required: boolean
}

// --- WebAuthn ---

/**
 * Server response for webauthn register/begin. Maps to PublicKeyCredentialCreationOptions.
 *
 * Every binary field arrives base64url-encoded and must be decoded to an
 * `ArrayBuffer` before the browser will accept it. `useWebAuthn().register()`
 * does that conversion.
 */
export interface WebAuthnCreationOptions {
  /** The creation options, mirroring the WebAuthn spec's field names. */
  publicKey: {
    /** base64url challenge. */
    challenge: string
    /** Relying party identity. */
    rp: { name: string; id: string }
    /** User handle and display names. `id` is base64url. */
    user: { id: string; name: string; displayName: string }
    /** Acceptable algorithms, in order of preference. */
    pubKeyCredParams: Array<{ type: string; alg: number }>
    /** Milliseconds the browser should wait for the authenticator. */
    timeout?: number
    /** Already-enrolled credentials, so the authenticator refuses to enrol twice. */
    excludeCredentials?: Array<{ type: string; id: string; transports?: string[] }>
    /** Constraints on which authenticators qualify. */
    authenticatorSelection?: {
      authenticatorAttachment?: string
      residentKey?: string
      requireResidentKey?: boolean
      userVerification?: string
    }
    /** Attestation conveyance preference. */
    attestation?: string
  }
}

/**
 * Server response for webauthn verify/begin. Maps to PublicKeyCredentialRequestOptions.
 *
 * As with creation options, binary fields are base64url and are decoded by
 * `useWebAuthn().verify()`.
 */
export interface WebAuthnAssertionOptions {
  /** The request options, mirroring the WebAuthn spec's field names. */
  publicKey: {
    /** base64url challenge. */
    challenge: string
    /** Milliseconds the browser should wait for the authenticator. */
    timeout?: number
    /** Relying party identifier the credential is scoped to. */
    rpId?: string
    /** Credentials the user may assert with. Empty allows any discoverable credential. */
    allowCredentials?: Array<{ type: string; id: string; transports?: string[] }>
    /** Whether the authenticator must verify the user, e.g. by PIN or biometric. */
    userVerification?: string
  }
}

/** A registered WebAuthn credential (from GET /auth/2fa/webauthn/credentials). */
export interface WebAuthnCredential {
  /** base64url credential identifier, for `deleteCredential`. */
  id: string
  /** Authenticator signature counter, used server-side to detect cloned authenticators. */
  sign_count: number
  /** RFC 3339 timestamp of enrolment. */
  created_at: string
}

/** Result from POST /auth/confirm. */
export interface ConfirmResult {
  /** Whether the password was correct. */
  confirmed: boolean
  /** Seconds the elevation lasts. The server re-checks it independently of any local timer. */
  expires_in: number
}

// --- Identity ---

/**
 * The user's stored identity record. Every field is optional: a user may have
 * filled in none, some or all of it, and a partial object is a valid update.
 */
export interface IdentityData {
  /** Given name. */
  given_name?: string
  /** Family name. */
  family_name?: string
  /** ISO 3166-1 alpha-2 country code. */
  country?: string
  /** Date of birth as `YYYY-MM-DD`. */
  date_of_birth?: string
  /** Self-described sex. */
  sex?: string
  /** Billing address and tax identity. */
  billing?: BillingInfo
  /** RFC 3339 timestamp. Server-maintained; ignored on write. */
  updated_at?: string
}

/** Billing address and tax identity, nested in {@link IdentityData}. */
export interface BillingInfo {
  /** Street address, first line. */
  address_line_1?: string
  /** Street address, second line. */
  address_line_2?: string
  /** City. */
  city?: string
  /** Postal code. */
  postal_code?: string
  /** ISO 3166-1 alpha-2 country code. May differ from the identity's country. */
  country?: string
  /** VAT identification number. */
  vat_id?: string
}

// --- Blobs ---

/** Metadata for one stored blob. The contents are not included. */
export interface BlobMeta {
  /** Blob identifier. For a named blob this is the name. */
  id: string
  /** Caller-supplied label. Printable ASCII only, because it travels in a header. */
  label?: string
  /** Whether the blob is addressed by name and overwrites in place. */
  named: boolean
  /** Plaintext size in bytes. */
  size_bytes: number
  /** Size actually consumed after encryption, which is what counts against the quota. */
  stored_bytes: number
  /** Integrity checksum of the contents. */
  checksum: string
  /** RFC 3339 timestamp. */
  created_at: string
}

/** Result of a blob upload. */
export interface BlobUploadResult {
  /** Identifier to read the blob back with. */
  id: string
  /** The label as stored. */
  label: string
  /** Plaintext size in bytes. */
  size_bytes: number
  /** Size consumed after encryption. */
  stored_bytes: number
  /** Integrity checksum. */
  checksum: string
  /** RFC 3339 timestamp. */
  created_at: string
}

/** Result of `GET /user/blobs`: the listing plus the quota in one response. */
export interface BlobListResult {
  /** The stored blobs' metadata. */
  blobs: BlobMeta[]
  /** Number of blobs. */
  count: number
  /** Current quota usage. */
  quota: BlobQuota
}

/** Blob storage limits and current usage. */
export interface BlobQuota {
  /** Encrypted bytes consumed, matching the sum of `stored_bytes`. */
  used_bytes: number
  /** Byte ceiling. An upload that would exceed it is rejected. */
  max_bytes: number
  /** Blobs stored. */
  used_count: number
  /** Blob-count ceiling. */
  max_count: number
}

// --- Capabilities ---

/**
 * What this server instance allows, from `GET /auth/capabilities`. Unauthenticated,
 * so it can be read before sign-in to decide which controls to render.
 */
export interface Capabilities {
  /** Whether self-service registration is open. */
  registration_enabled: boolean
  /** Whether every account must hold a second factor. */
  mfa_required: boolean
  /** Configured social providers, matching {@link OAuthProvider} values. */
  oauth_providers: string[]
}

// --- OAuth ---

/** The social identity providers this client can start a flow against. */
export type OAuthProvider = 'github' | 'google' | 'facebook'
