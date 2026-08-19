<!--
  VaultAuthGuard: renders its default slot only to a signed-in user.

  Slots:
    default  the protected content
    loading  shown while the session is being restored (default: "Loading...")
    fallback shown to an anonymous user (default: a sign-in prompt)

  It renders the loading slot until `useAuth().init()` has settled, so a
  signed-in user reloading the page is never shown the fallback in the gap
  before the refresh resolves. Something must still call `init()`; the guard
  reads the state but does not start it.

  This is presentation, not access control. The protected markup is in the
  bundle either way and the data behind it is protected by the server, which
  validates the token on every request.
-->
<script setup lang="ts">
import { useAuth } from '../composables/useAuth'

const { isAuthenticated, isLoading, initialized } = useAuth()
</script>

<template>
  <template v-if="isAuthenticated">
    <slot />
  </template>
  <template v-else-if="isLoading || !initialized">
    <slot name="loading">
      <p>Loading...</p>
    </slot>
  </template>
  <template v-else>
    <slot name="fallback">
      <p>Please sign in to continue.</p>
    </slot>
  </template>
</template>
