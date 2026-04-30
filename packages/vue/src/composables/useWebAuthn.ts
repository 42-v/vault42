import { ref, computed, type Ref, type ComputedRef } from 'vue'
import { useVaultClient } from '../plugin'
import { base64urlToBuffer, bufferToBase64url } from '../base64url'
import type { VaultError, LoginResult, WebAuthnCredential } from '../types'

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
