import type {
  VaultClientOptions,
  VaultError,
  RegisterResult,
  LoginResult,
  RefreshResult,
  UserProfile,
  Session,
  Device,
  TOTPSetupResult,
  JWKS,
  OIDCConfig,
  WebAuthnCreationOptions,
  WebAuthnAssertionOptions,
  WebAuthnCredential,
  ConfirmResult,
  OAuthProvider,
  MFAStatus,
  IdentityData,
  BlobUploadResult,
  BlobListResult,
  Capabilities,
} from './types'

class VaultAPIError extends Error implements VaultError {
  code: string
  status: number

  constructor(code: string, status: number, message?: string) {
    super(message || code)
    this.code = code
    this.status = status
    this.name = 'VaultAPIError'
  }
}

/** Status used for errors raised before a request reaches the network. */
const NO_HTTP_STATUS = 0

/** Printable ASCII only: fetch rejects header values outside latin-1 and any CR/LF. */
const PRINTABLE_ASCII = /^[\x20-\x7E]*$/

export class VaultClient {
  private baseURL: string
  private options: VaultClientOptions
  private _accessToken: string | null = null
  private _refreshing: Promise<RefreshResult> | null = null

  constructor(baseURL: string, options?: VaultClientOptions) {
    this.baseURL = baseURL.replace(/\/+$/, '')
    this.options = options || {}
  }

  get accessToken(): string | null {
    return this._accessToken
  }

  set accessToken(token: string | null) {
    this._accessToken = token
  }

  // ---- Auth ----

  async register(email: string, password: string, displayName?: string): Promise<RegisterResult> {
    return this.request<RegisterResult>('POST', '/auth/register', {
      email,
      password,
      display_name: displayName,
    })
  }

  async login(email: string, password: string, rememberMe?: boolean): Promise<LoginResult> {
    const result = await this.request<LoginResult>('POST', '/auth/login', {
      email,
      password,
      remember_me: rememberMe,
    })
    if (!result || typeof result !== 'object') {
      throw new VaultAPIError('invalid_response', 200, 'Login response carried no body')
    }
    if (result.access_token) {
      this._accessToken = result.access_token
    }
    return result
  }

  async refresh(): Promise<RefreshResult> {
    // Deduplicate concurrent refresh calls
    if (this._refreshing) return this._refreshing

    this._refreshing = this.request<RefreshResult>('POST', '/auth/refresh', undefined, false)
      .then((result) => {
        // A 200 without a usable token is not a successful refresh. Assigning it
        // would put undefined behind a `string | null` getter and break every
        // downstream `=== null` check, so fail closed instead.
        if (!result || typeof result.access_token !== 'string' || result.access_token === '') {
          this._accessToken = null
          throw new VaultAPIError('invalid_refresh_response', 200, 'Refresh response carried no access token')
        }
        this._accessToken = result.access_token
        return result
      })
      .finally(() => {
        this._refreshing = null
      })

    return this._refreshing
  }

  async logout(): Promise<void> {
    // De-authenticate locally whatever the server answered: the caller is told
    // the session is over, so the bearer must not survive in memory.
    try {
      await this.request<void>('POST', '/auth/logout')
    } finally {
      this._accessToken = null
    }
  }

  async verifyEmail(token: string): Promise<void> {
    await this.request<void>('GET', `/auth/verify-email?token=${encodeURIComponent(token)}`)
  }

  // ---- Profile ----

  async getProfile(): Promise<UserProfile> {
    return this.request<UserProfile>('GET', '/user/profile')
  }

  // ---- Sessions ----

  async getSessions(): Promise<Session[]> {
    const result = await this.request<{ sessions: Session[] }>('GET', '/user/sessions')
    return result.sessions || []
  }

  async revokeSession(id: string): Promise<void> {
    await this.request<void>('DELETE', `/user/sessions/${this.safePath(id)}`)
  }

  async revokeAllSessions(): Promise<void> {
    await this.request<void>('DELETE', '/user/sessions')
  }

  // ---- Devices ----

  async getDevices(): Promise<Device[]> {
    const result = await this.request<{ devices: Device[] }>('GET', '/user/devices')
    return result.devices || []
  }

  async renameDevice(id: string, friendlyName: string): Promise<void> {
    await this.request<void>('PATCH', `/user/devices/${this.safePath(id)}`, { friendly_name: friendlyName })
  }

  async removeDevice(id: string): Promise<void> {
    await this.request<void>('DELETE', `/user/devices/${this.safePath(id)}`)
  }

  // ---- Password ----

  async changePassword(current: string, newPassword: string): Promise<void> {
    await this.request<void>('POST', '/user/password', {
      current_password: current,
      new_password: newPassword,
    })
  }

  async requestPasswordReset(email: string): Promise<void> {
    await this.request<void>('POST', '/auth/password/reset', { email })
  }

  async confirmPasswordReset(token: string, password: string): Promise<void> {
    await this.request<void>('POST', '/auth/password/reset/confirm', { token, password })
  }

  // ---- 2FA ----

  async setupTOTP(): Promise<TOTPSetupResult> {
    return this.request<TOTPSetupResult>('POST', '/auth/2fa/totp/setup')
  }

  async verifyTOTP(code: string): Promise<LoginResult> {
    return this.request<LoginResult>('POST', '/auth/2fa/totp/verify', { code }, false)
  }

  async generateBackupCodes(): Promise<string[]> {
    const result = await this.request<{ codes: string[] }>('POST', '/auth/2fa/backup-codes')
    return result.codes
  }

  async verifyBackupCode(code: string): Promise<LoginResult> {
    return this.request<LoginResult>('POST', '/auth/2fa/backup-code/verify', { code }, false)
  }

  async verifyEmailOTP(code: string): Promise<LoginResult> {
    return this.request<LoginResult>('POST', '/auth/2fa/email-otp/verify', { code }, false)
  }

  async resendEmailOTP(): Promise<{ status: string }> {
    return this.request<{ status: string }>('POST', '/auth/2fa/email-otp/resend', undefined, false)
  }

  // ---- Confirm (re-auth) ----

  async confirmPassword(password: string): Promise<ConfirmResult> {
    return this.request<ConfirmResult>('POST', '/auth/confirm', { password })
  }

  // ---- MFA Status ----

  async getMFAStatus(): Promise<MFAStatus> {
    return this.request<MFAStatus>('GET', '/auth/2fa/status')
  }

  // ---- TOTP disable ----

  async disableTOTP(): Promise<void> {
    await this.request<void>('DELETE', '/auth/2fa/totp')
  }

  // ---- WebAuthn ----

  async webauthnRegisterBegin(): Promise<WebAuthnCreationOptions> {
    return this.request<WebAuthnCreationOptions>('POST', '/auth/2fa/webauthn/register/begin')
  }

  async webauthnRegisterFinish(body: object): Promise<void> {
    await this.request<void>('POST', '/auth/2fa/webauthn/register/finish', body)
  }

  async webauthnVerifyBegin(): Promise<WebAuthnAssertionOptions> {
    return this.request<WebAuthnAssertionOptions>('POST', '/auth/2fa/webauthn/verify/begin', undefined, false)
  }

  async webauthnVerifyFinish(body: object): Promise<LoginResult> {
    return this.request<LoginResult>('POST', '/auth/2fa/webauthn/verify/finish', body, false)
  }

  async webauthnListCredentials(): Promise<WebAuthnCredential[]> {
    const result = await this.request<{ credentials: WebAuthnCredential[] }>('GET', '/auth/2fa/webauthn/credentials')
    return result.credentials || []
  }

  async webauthnDeleteCredential(id: string): Promise<void> {
    await this.request<void>('DELETE', `/auth/2fa/webauthn/credentials/${this.safePath(id)}`)
  }

  // ---- OAuth ----

  getOAuthAuthorizeURL(provider: OAuthProvider): string {
    return `${this.baseURL}/auth/oauth2/authorize?provider=${provider}`
  }

  async exchangeOAuthCode(code: string): Promise<LoginResult> {
    return this.request<LoginResult>('POST', '/auth/oauth2/exchange', { code })
  }

  // ---- Identity ----

  async getIdentity(): Promise<IdentityData> {
    return this.request<IdentityData>('GET', '/user/identity')
  }

  async putIdentity(data: Partial<IdentityData>): Promise<{ status: string }> {
    return this.request<{ status: string }>('PUT', '/user/identity', data)
  }

  async deleteIdentity(): Promise<{ status: string }> {
    return this.request<{ status: string }>('DELETE', '/user/identity')
  }

  // ---- Blobs ----

  async listBlobs(): Promise<BlobListResult> {
    return this.request<BlobListResult>('GET', '/user/blobs')
  }

  /**
   * Uploads binary data. `label` travels in the X-Blob-Label header, so it is
   * limited to printable ASCII (0x20-0x7E) and 255 characters. A label with a
   * newline, a control character or any non-ASCII character is rejected here
   * with a VaultAPIError; callers holding such names must transliterate or
   * encode them before upload.
   */
  async uploadBlob(data: Blob | ArrayBuffer | Uint8Array, label?: string): Promise<BlobUploadResult> {
    const headers: Record<string, string> = {}
    if (label) {
      headers['X-Blob-Label'] = this.safeLabel(label)
    }
    const response = await this.binaryRequest('POST', '/user/blobs', headers, this.toBlob(data))
    return this.parseBody<BlobUploadResult>(response)
  }

  async downloadBlob(id: string): Promise<{ data: ArrayBuffer; label?: string; checksum?: string }> {
    const response = await this.binaryRequest('GET', `/user/blobs/${this.safePath(id)}`)
    return this.readBinary(response)
  }

  async deleteBlob(id: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('DELETE', `/user/blobs/${this.safePath(id)}`)
  }

  async uploadNamedBlob(name: string, data: Blob | ArrayBuffer | Uint8Array): Promise<BlobUploadResult> {
    const path = `/user/blobs/named/${this.safePath(name)}`
    const response = await this.binaryRequest('PUT', path, {}, this.toBlob(data))
    return this.parseBody<BlobUploadResult>(response)
  }

  async downloadNamedBlob(name: string): Promise<{ data: ArrayBuffer; label?: string; checksum?: string }> {
    const response = await this.binaryRequest('GET', `/user/blobs/named/${this.safePath(name)}`)
    return this.readBinary(response)
  }

  async deleteNamedBlob(name: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('DELETE', `/user/blobs/named/${this.safePath(name)}`)
  }

  // ---- Capabilities ----

  async getCapabilities(): Promise<Capabilities> {
    return this.request<Capabilities>('GET', '/auth/capabilities', undefined, false)
  }

  // ---- Well-known ----

  async getJWKS(): Promise<JWKS> {
    return this.request<JWKS>('GET', '/.well-known/jwks.json')
  }

  async getOIDCConfig(): Promise<OIDCConfig> {
    return this.request<OIDCConfig>('GET', '/.well-known/openid-configuration')
  }

  // ---- Internal ----

  private safePath(id: string): string {
    if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
      throw new VaultAPIError('invalid_resource_id', NO_HTTP_STATUS, 'Invalid resource ID')
    }
    return id
  }

  private safeLabel(label: string): string {
    if (label.length > 255) {
      throw new VaultAPIError('invalid_blob_label', NO_HTTP_STATUS, 'Blob label too long')
    }
    if (!PRINTABLE_ASCII.test(label)) {
      throw new VaultAPIError(
        'invalid_blob_label',
        NO_HTTP_STATUS,
        'Blob label must contain only printable ASCII characters',
      )
    }
    return label
  }

  private toBlob(data: Blob | ArrayBuffer | Uint8Array): Blob {
    if (data instanceof Blob) return data
    return new Blob([data instanceof ArrayBuffer ? data : new Uint8Array(data)])
  }

  private resolve(path: string): string {
    if (path.startsWith('http://') || path.startsWith('https://')) {
      const pathOrigin = new URL(path).origin
      const baseOrigin = new URL(this.baseURL).origin
      if (pathOrigin !== baseOrigin) {
        throw new VaultAPIError(
          'invalid_request_url',
          NO_HTTP_STATUS,
          'Request URL origin does not match base URL origin',
        )
      }
      return path
    }
    return `${this.baseURL}${path}`
  }

  /**
   * Single network path for every request, JSON or binary: onRequest hook,
   * auto-refresh on 401, and error mapping to VaultAPIError. Returns the raw
   * Response so the caller can read it as JSON or as bytes.
   *
   * `makeInit` is re-invoked per attempt so the retry carries the refreshed
   * bearer rather than the one the server just rejected.
   */
  private async dispatch(url: string, makeInit: () => RequestInit, retry: boolean): Promise<Response> {
    let init = makeInit()
    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)

    // Auto-refresh on 401 (only for authenticated endpoints, not login/register)
    if (response.status === 401 && retry && this._accessToken) {
      try {
        await this.refresh()
      } catch {
        this._accessToken = null
        throw new VaultAPIError('session_expired', 401)
      }
      try {
        return await this.dispatch(url, makeInit, false)
      } catch (err) {
        // The refresh succeeded and the server still rejected the bearer, so
        // the token is dead: drop it instead of retrying with it forever.
        if (err instanceof VaultAPIError && err.status === 401) {
          this._accessToken = null
        }
        throw err
      }
    }

    if (!response.ok) {
      throw await this.toError(response)
    }

    return response
  }

  private async toError(response: Response): Promise<VaultAPIError> {
    let code = 'unknown_error'
    try {
      const body = await response.json()
      if (body && typeof body === 'object') {
        code = body.error || body.code || code
      }
    } catch {
      // response body not JSON
    }
    return new VaultAPIError(code, response.status)
  }

  /** Reads a success body as JSON. An empty body (204, or 200 with no content) resolves undefined. */
  private async parseBody<T>(response: Response): Promise<T> {
    let text: string
    try {
      text = await response.text()
    } catch {
      throw new VaultAPIError('invalid_response', response.status, 'Response body could not be read')
    }
    if (!text) return undefined as T
    try {
      return JSON.parse(text) as T
    } catch {
      throw new VaultAPIError('invalid_response', response.status, 'Response body is not valid JSON')
    }
  }

  private async readBinary(response: Response): Promise<{ data: ArrayBuffer; label?: string; checksum?: string }> {
    let data: ArrayBuffer
    try {
      data = await response.arrayBuffer()
    } catch {
      throw new VaultAPIError('invalid_response', response.status, 'Response body could not be read')
    }
    return {
      data,
      label: response.headers.get('X-Blob-Label') || undefined,
      checksum: response.headers.get('X-Blob-Checksum') || undefined,
    }
  }

  private async binaryRequest(
    method: string,
    path: string,
    extraHeaders: Record<string, string> = {},
    body?: Blob,
  ): Promise<Response> {
    return this.dispatch(`${this.baseURL}${path}`, () => ({
      method,
      credentials: 'include',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
        ...extraHeaders,
      },
      ...(body ? { body } : {}),
    }), true)
  }

  private async request<T>(method: string, path: string, body?: unknown, retry = true): Promise<T> {
    const url = this.resolve(path)
    const serialized = body ? JSON.stringify(body) : undefined

    const response = await this.dispatch(url, () => ({
      method,
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
      },
      ...(serialized !== undefined ? { body: serialized } : {}),
    }), retry)

    return this.parseBody<T>(response)
  }
}

export { VaultAPIError }
