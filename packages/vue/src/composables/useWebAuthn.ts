import { ref, computed, type Ref, type ComputedRef } from 'vue'
import { useVaultClient } from '../plugin'
import { base64urlToBuffer, bufferToBase64url } from '../base64url'
import type { VaultError, LoginResult, WebAuthnCredential } from '../types'

/**
 * WebAuthn / FIDO2 credential enrolment, assertion and management.
 *
 * Handles the base64url-to-`ArrayBuffer` conversion the browser credential API
 * requires in both directions, so the server's JSON options can be passed
 * straight through.
 *
 * State is created per call and is not shared between callers.
 *
 * Calls `POST /auth/2fa/webauthn/register/{begin,finish}`,
 * `POST /auth/2fa/webauthn/verify/{begin,finish}`, and
 * `GET`/`DELETE /auth/2fa/webauthn/credentials`.
 *
 * @returns
 * - `isSupported`: computed, whether the browser exposes
 *   `window.PublicKeyCredential`. Gate any WebAuthn UI on this: the API is also
 *   unavailable in non-secure contexts and in SSR, where it is false.
 * - `isLoading`: true while a call is outstanding, including the time the
 *   browser is waiting for the user to touch their authenticator.
 * - `error`: the last `VaultError`, or null. A user who dismisses the browser
 *   prompt produces code `webauthn_cancelled`, which is a normal outcome rather
 *   than a failure to report as one.
 * - `isRegistered`: true after a successful `register()` in this composable's
 *   lifetime. Local bookkeeping, not server state.
 * - `credentials`: the {@link WebAuthnCredential} list, empty until fetched.
 * - `register()`: enrols a new credential for the signed-in user.
 * - `verify(challengeToken?)`: performs an assertion and returns the
 *   {@link LoginResult}.
 * - `listCredentials()`: loads and returns the credential list. Swallows its
 *   error and returns the previous value, so an empty result does not
 *   distinguish "none enrolled" from "the call failed".
 * - `deleteCredential(id)`: removes one credential and drops it from the local
 *   list.
 *
 * `verify(challengeToken)` temporarily replaces the shared client's access
 * token with the challenge token for the duration of the call, and on success
 * leaves the **real** access token from the server in place. It restores the
 * previous token only on the error path. That mutation is global to the client,
 * so a request issued from elsewhere while an assertion is in flight travels
 * with the challenge token, which authorises nothing but the verification
 * route. During login, prefer `verify2FAWebAuthn()` on {@link useAuth}, which
 * sequences this correctly and keeps the session refs consistent.
 *
 * `register`, `verify` and `deleteCredential` set `error` and rethrow.
 *
 * @throws Error if `createVaultPlugin` was never installed.
 */
export function useWebAuthn() {
  const client = useVaultClient()
  const isLoading: Ref<boolean> = ref(false)
  const error: Ref<VaultError | null> = ref(null)
  const isRegistered: Ref<boolean> = ref(false)
  const credentials: Ref<WebAuthnCredential[]> = ref([])

  const isSupported: ComputedRef<boolean> = computed(
    () => typeof window !== 'undefined' && !!window.PublicKeyCredential,
  )

  async function register(): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      const options = await client.webauthnRegisterBegin()
      const pk = options.publicKey

      // Transform base64url → ArrayBuffer for the browser API
      const createOptions: PublicKeyCredentialCreationOptions = {
        challenge: base64urlToBuffer(pk.challenge),
        rp: pk.rp,
        user: {
          id: base64urlToBuffer(pk.user.id),
          name: pk.user.name,
          displayName: pk.user.displayName,
        },
        pubKeyCredParams: pk.pubKeyCredParams as PublicKeyCredentialParameters[],
        timeout: pk.timeout,
        excludeCredentials: pk.excludeCredentials?.map((c) => ({
          type: c.type as PublicKeyCredentialType,
          id: base64urlToBuffer(c.id),
          transports: c.transports as AuthenticatorTransport[] | undefined,
        })),
        authenticatorSelection: pk.authenticatorSelection as AuthenticatorSelectionCriteria | undefined,
        attestation: pk.attestation as AttestationConveyancePreference | undefined,
      }

      const credential = (await navigator.credentials.create({
        publicKey: createOptions,
      })) as PublicKeyCredential | null
      if (!credential) throw { code: 'webauthn_cancelled', status: 0 }

      const response = credential.response as AuthenticatorAttestationResponse
      const body = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: bufferToBase64url(response.attestationObject),
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
        },
      }

      await client.webauthnRegisterFinish(body)
      isRegistered.value = true
    } catch (e: unknown) {
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error.value = { code: 'webauthn_cancelled', status: 0 } as VaultError
      } else {
        error.value = e as VaultError
      }
      throw e
    } finally {
      isLoading.value = false
    }
  }

  async function verify(challengeToken?: string): Promise<LoginResult> {
    isLoading.value = true
    error.value = null
    const prevToken = client.accessToken
    try {
      if (challengeToken) {
        client.accessToken = challengeToken
      }
      const options = await client.webauthnVerifyBegin()
      const pk = options.publicKey

      const getOptions: PublicKeyCredentialRequestOptions = {
        challenge: base64urlToBuffer(pk.challenge),
        timeout: pk.timeout,
        rpId: pk.rpId,
        allowCredentials: pk.allowCredentials?.map((c) => ({
          type: c.type as PublicKeyCredentialType,
          id: base64urlToBuffer(c.id),
          transports: c.transports as AuthenticatorTransport[] | undefined,
        })),
        userVerification: pk.userVerification as UserVerificationRequirement | undefined,
      }

      const credential = (await navigator.credentials.get({
        publicKey: getOptions,
      })) as PublicKeyCredential | null
      if (!credential) throw { code: 'webauthn_cancelled', status: 0 }

      const response = credential.response as AuthenticatorAssertionResponse
      const body = {
        id: credential.id,
        rawId: bufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          authenticatorData: bufferToBase64url(response.authenticatorData),
          clientDataJSON: bufferToBase64url(response.clientDataJSON),
          signature: bufferToBase64url(response.signature),
          userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : undefined,
        },
      }

      // Server returns tokens after successful 2FA verification + sets refresh cookie
      const result = await client.webauthnVerifyFinish(body)
      // Set the real access token from the server response
      if (result.access_token) {
        client.accessToken = result.access_token
      }
      return result
    } catch (e: unknown) {
      // On error, restore previous token
      if (challengeToken) {
        client.accessToken = prevToken
      }
      if (e instanceof DOMException && e.name === 'NotAllowedError') {
        error.value = { code: 'webauthn_cancelled', status: 0 } as VaultError
      } else {
        error.value = e as VaultError
      }
      throw e
    } finally {
      isLoading.value = false
    }
  }

  async function listCredentials(): Promise<WebAuthnCredential[]> {
    try {
      credentials.value = await client.webauthnListCredentials()
      return credentials.value
    } catch {
      // Non-critical — return current state
      return credentials.value
    }
  }

  async function deleteCredential(id: string): Promise<void> {
    isLoading.value = true
    error.value = null
    try {
      await client.webauthnDeleteCredential(id)
      credentials.value = credentials.value.filter((c: WebAuthnCredential) => c.id !== id)
    } catch (e: unknown) {
      error.value = e as VaultError
      throw e
    } finally {
      isLoading.value = false
    }
  }

  return {
    isSupported,
    isLoading,
    error,
    isRegistered,
    credentials,
    register,
    verify,
    listCredentials,
    deleteCredential,
  }
}
