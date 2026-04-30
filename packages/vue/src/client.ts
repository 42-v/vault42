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

export class VaultClient {
  private baseURL: string
  private options: VaultClientOptions
  private _accessToken: string | null = null
  private _refreshing: Promise<RefreshResult> | null = null

  constructor(baseURL: string, options?: VaultClientOptions) {
    this.baseURL = baseURL.replace(/\/$/, '')
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
        this._accessToken = result.access_token
        return result
      })
      .finally(() => {
        this._refreshing = null
      })

    return this._refreshing
  }

  async logout(): Promise<void> {
    await this.request<void>('POST', '/auth/logout')
    this._accessToken = null
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

  async uploadBlob(data: Blob | ArrayBuffer | Uint8Array, label?: string): Promise<BlobUploadResult> {
    if (label && label.length > 255) {
      throw new Error('Blob label too long')
    }
    const url = `${this.baseURL}/user/blobs`
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
    }
    if (label) {
      headers['X-Blob-Label'] = label
    }

    let init: RequestInit = {
      method: 'POST',
      credentials: 'include',
      headers,
      body: data instanceof Blob ? data : new Blob([data instanceof ArrayBuffer ? data : new Uint8Array(data)]),
    }
    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)
    if (!response.ok) {
      let code = 'unknown_error'
      try {
        const err = await response.json()
        code = err.error || err.code || code
      } catch { /* ignore */ }
      throw new VaultAPIError(code, response.status)
    }
    return response.json()
  }

  async downloadBlob(id: string): Promise<{ data: ArrayBuffer; label?: string; checksum?: string }> {
    const url = `${this.baseURL}/user/blobs/${this.safePath(id)}`
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
    }

    let init: RequestInit = {
      method: 'GET',
      credentials: 'include',
      headers,
    }
    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)
    if (!response.ok) {
      let code = 'unknown_error'
      try {
        const err = await response.json()
        code = err.error || err.code || code
      } catch { /* ignore */ }
      throw new VaultAPIError(code, response.status)
    }
    return {
      data: await response.arrayBuffer(),
      label: response.headers.get('X-Blob-Label') || undefined,
      checksum: response.headers.get('X-Blob-Checksum') || undefined,
    }
  }

  async deleteBlob(id: string): Promise<{ status: string }> {
    return this.request<{ status: string }>('DELETE', `/user/blobs/${this.safePath(id)}`)
  }

  async uploadNamedBlob(name: string, data: Blob | ArrayBuffer | Uint8Array): Promise<BlobUploadResult> {
    const safeName = this.safePath(name)
    const url = `${this.baseURL}/user/blobs/named/${safeName}`
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
    }

    let init: RequestInit = {
      method: 'PUT',
      credentials: 'include',
      headers,
      body: data instanceof Blob ? data : new Blob([data instanceof ArrayBuffer ? data : new Uint8Array(data)]),
    }
    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)
    if (!response.ok) {
      let code = 'unknown_error'
      try {
        const err = await response.json()
        code = err.error || err.code || code
      } catch { /* ignore */ }
      throw new VaultAPIError(code, response.status)
    }
    return response.json()
  }

  async downloadNamedBlob(name: string): Promise<{ data: ArrayBuffer; label?: string; checksum?: string }> {
    const safeName = this.safePath(name)
    const url = `${this.baseURL}/user/blobs/named/${safeName}`
    const headers: Record<string, string> = {
      'X-Requested-With': 'XMLHttpRequest',
      ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
    }

    let init: RequestInit = {
      method: 'GET',
      credentials: 'include',
      headers,
    }
    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)
    if (!response.ok) {
      let code = 'unknown_error'
      try {
        const err = await response.json()
        code = err.error || err.code || code
      } catch { /* ignore */ }
      throw new VaultAPIError(code, response.status)
    }
    return {
      data: await response.arrayBuffer(),
      label: response.headers.get('X-Blob-Label') || undefined,
      checksum: response.headers.get('X-Blob-Checksum') || undefined,
    }
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
      throw new Error('Invalid resource ID')
    }
    return id
  }

  private async request<T>(method: string, path: string, body?: unknown, retry = true): Promise<T> {
    let url: string
    if (path.startsWith('http://') || path.startsWith('https://')) {
      const pathOrigin = new URL(path).origin
      const baseOrigin = new URL(this.baseURL).origin
      if (pathOrigin !== baseOrigin) {
        throw new Error('Request URL origin does not match base URL origin')
      }
      url = path
    } else {
      url = `${this.baseURL}${path}`
    }

    let init: RequestInit = {
      method,
      credentials: 'include',
      headers: {
        'Accept': 'application/json',
        'X-Requested-With': 'XMLHttpRequest',
        ...(body ? { 'Content-Type': 'application/json' } : {}),
        ...(this._accessToken ? { 'Authorization': `Bearer ${this._accessToken}` } : {}),
      },
      ...(body ? { body: JSON.stringify(body) } : {}),
    }

    if (this.options.onRequest) {
      init = this.options.onRequest(init)
    }

    const response = await fetch(url, init)

    // Auto-refresh on 401 (only for authenticated endpoints, not login/register)
    if (response.status === 401 && retry && this._accessToken) {
      try {
        await this.refresh()
        return this.request<T>(method, path, body, false)
      } catch {
        this._accessToken = null
        throw new VaultAPIError('session_expired', 401)
      }
    }

    if (!response.ok) {
      let code = 'unknown_error'
      try {
        const err = await response.json()
        code = err.error || err.code || code
      } catch {
        // response body not JSON
      }
      throw new VaultAPIError(code, response.status)
    }

    // Handle empty responses (204, or empty body)
    const text = await response.text()
    if (!text) return undefined as T
    return JSON.parse(text) as T
  }
}

export { VaultAPIError }
