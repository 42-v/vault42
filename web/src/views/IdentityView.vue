<script setup lang="ts">
import { onMounted, ref, reactive } from 'vue'
import { useIdentity, VaultAuthGuard, useT } from '@vault42/vue'
import type { IdentityData } from '@vault42/vue'
import { friendlyError } from '../errorMessages'
import { useModalFocus } from '../composables/useModalFocus'

const { identity, isLoading, isSaving, error, fetchIdentity, saveIdentity, deleteIdentity } = useIdentity()
const { t } = useT()
const showDeleteConfirm = ref(false)
const { dialogRef } = useModalFocus(showDeleteConfirm, () => { showDeleteConfirm.value = false })
const saveSuccess = ref(false)

const form = reactive<IdentityData>({
  given_name: '',
  family_name: '',
  country: '',
  date_of_birth: '',
  sex: '',
  billing: undefined,
})

const showBilling = ref(false)
const billing = reactive({
  address_line_1: '',
  address_line_2: '',
  city: '',
  postal_code: '',
  country: '',
  vat_id: '',
})

onMounted(async () => {
  await fetchIdentity()
  if (identity.value) {
    form.given_name = identity.value.given_name || ''
    form.family_name = identity.value.family_name || ''
    form.country = identity.value.country || ''
    form.date_of_birth = identity.value.date_of_birth || ''
    form.sex = identity.value.sex || ''
    if (identity.value.billing) {
      showBilling.value = true
      billing.address_line_1 = identity.value.billing.address_line_1 || ''
      billing.address_line_2 = identity.value.billing.address_line_2 || ''
      billing.city = identity.value.billing.city || ''
      billing.postal_code = identity.value.billing.postal_code || ''
      billing.country = identity.value.billing.country || ''
      billing.vat_id = identity.value.billing.vat_id || ''
    }
  }
})

async function handleSave() {
  saveSuccess.value = false
  const data: IdentityData = {
    given_name: form.given_name || undefined,
    family_name: form.family_name || undefined,
    country: form.country || undefined,
    date_of_birth: form.date_of_birth || undefined,
    sex: form.sex || undefined,
  }
  if (showBilling.value) {
    data.billing = {
      address_line_1: billing.address_line_1 || undefined,
      address_line_2: billing.address_line_2 || undefined,
      city: billing.city || undefined,
      postal_code: billing.postal_code || undefined,
      country: billing.country || undefined,
      vat_id: billing.vat_id || undefined,
    }
  }
  const ok = await saveIdentity(data)
  if (ok) saveSuccess.value = true
}

async function handleDelete() {
  showDeleteConfirm.value = false
  await deleteIdentity()
  form.given_name = ''
  form.family_name = ''
  form.country = ''
  form.date_of_birth = ''
  form.sex = ''
  Object.assign(billing, { address_line_1: '', address_line_2: '', city: '', postal_code: '', country: '', vat_id: '' })
  showBilling.value = false
}
</script>

<template>
  <VaultAuthGuard>
    <template #default>
      <div class="max-w-3xl mx-auto px-4 sm:px-6 py-8">
        <h1 class="text-2xl font-bold mb-6">{{ t('identity.title') }}</h1>

        <div v-if="isLoading" class="flex justify-center py-12">
          <div class="vault42-spinner vault42-spinner-lg"></div>
        </div>

        <template v-else>
          <div v-if="error" class="vault42-alert-error mb-4" role="alert">{{ friendlyError(error.code) }}</div>
          <div v-if="saveSuccess" class="vault42-alert-success mb-4" role="status">{{ t('identity.savedSuccess') }}</div>

          <form class="space-y-6" @submit.prevent="handleSave">
            <div class="vault42-card space-y-4">
              <h3 class="text-sm font-semibold text-vault42-muted uppercase tracking-wider">{{ t('identity.basicInfo') }}</h3>
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label for="identity-given-name" class="vault42-label">{{ t('identity.givenName') }}</label>
                  <input id="identity-given-name" v-model="form.given_name" type="text" class="vault42-input" placeholder="Jane" maxlength="100" />
                </div>
                <div>
                  <label for="identity-family-name" class="vault42-label">{{ t('identity.familyName') }}</label>
                  <input id="identity-family-name" v-model="form.family_name" type="text" class="vault42-input" placeholder="Doe" maxlength="100" />
                </div>
                <div>
                  <label for="identity-country" class="vault42-label">{{ t('identity.country') }}</label>
                  <input id="identity-country" v-model="form.country" type="text" class="vault42-input" placeholder="US" maxlength="2" pattern="[A-Z]{2}" />
                </div>
                <div>
                  <label for="identity-dob" class="vault42-label">{{ t('identity.dateOfBirth') }}</label>
                  <input id="identity-dob" v-model="form.date_of_birth" type="date" class="vault42-input" />
                </div>
                <div>
                  <label for="identity-sex" class="vault42-label">{{ t('identity.sex') }}</label>
                  <select id="identity-sex" v-model="form.sex" class="vault42-input">
                    <option value="">{{ t('identity.sexNotSpecified') }}</option>
                    <option value="male">{{ t('identity.sexMale') }}</option>
                    <option value="female">{{ t('identity.sexFemale') }}</option>
                    <option value="prefer-not-to-say">{{ t('identity.sexPreferNotToSay') }}</option>
                  </select>
                </div>
              </div>
            </div>

            <div class="vault42-card space-y-4">
              <div class="flex items-center justify-between">
                <h3 class="text-sm font-semibold text-vault42-muted uppercase tracking-wider">{{ t('identity.billingAddress') }}</h3>
                <button type="button" class="text-sm text-vault42-accent hover:text-vault42-accent transition-colors" @click="showBilling = !showBilling">
                  {{ showBilling ? t('identity.hideBilling') : t('identity.addBilling') }}
                </button>
              </div>
              <div v-if="showBilling" class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div class="sm:col-span-2">
                  <label for="billing-address-1" class="vault42-label">{{ t('identity.addressLine1') }}</label>
                  <input id="billing-address-1" v-model="billing.address_line_1" type="text" class="vault42-input" maxlength="200" />
                </div>
                <div class="sm:col-span-2">
                  <label for="billing-address-2" class="vault42-label">{{ t('identity.addressLine2') }}</label>
                  <input id="billing-address-2" v-model="billing.address_line_2" type="text" class="vault42-input" maxlength="200" />
                </div>
                <div>
                  <label for="billing-city" class="vault42-label">{{ t('identity.city') }}</label>
                  <input id="billing-city" v-model="billing.city" type="text" class="vault42-input" maxlength="100" />
                </div>
                <div>
                  <label for="billing-postal-code" class="vault42-label">{{ t('identity.postalCode') }}</label>
                  <input id="billing-postal-code" v-model="billing.postal_code" type="text" class="vault42-input" maxlength="20" />
                </div>
                <div>
                  <label for="billing-country" class="vault42-label">{{ t('identity.billingCountry') }}</label>
                  <input id="billing-country" v-model="billing.country" type="text" class="vault42-input" placeholder="SK" maxlength="2" pattern="[A-Z]{2}" />
                </div>
                <div>
                  <label for="billing-vat-id" class="vault42-label">{{ t('identity.vatId') }}</label>
                  <input id="billing-vat-id" v-model="billing.vat_id" type="text" class="vault42-input" maxlength="50" />
                </div>
              </div>
            </div>

            <div class="flex items-center gap-3">
              <button type="submit" :disabled="isSaving" class="vault42-btn-primary">
                <span v-if="isSaving" class="vault42-spinner vault42-spinner-sm mr-2"></span>
                {{ t('identity.saveIdentity') }}
              </button>
              <button v-if="identity" type="button" class="vault42-btn-danger" @click="showDeleteConfirm = true">
                {{ t('common.delete') }}
              </button>
            </div>
          </form>

          <!-- Delete confirmation -->
          <Teleport to="body">
            <div v-if="showDeleteConfirm" class="vault42-modal-overlay" @click.self="showDeleteConfirm = false">
              <div ref="dialogRef" class="vault42-modal" role="dialog" aria-modal="true" aria-labelledby="identity-delete-dialog-title">
                <h3 id="identity-delete-dialog-title" class="text-lg font-semibold mb-2">{{ t('identity.deleteTitle') }}</h3>
                <p class="text-sm text-vault42-muted mb-4">{{ t('identity.deleteConfirm') }}</p>
                <div class="flex gap-3">
                  <button class="vault42-btn-danger" @click="handleDelete">{{ t('common.delete') }}</button>
                  <button class="vault42-btn-secondary" @click="showDeleteConfirm = false">{{ t('common.cancel') }}</button>
                </div>
              </div>
            </div>
          </Teleport>
        </template>
      </div>
    </template>

    <template #loading>
      <div class="flex justify-center py-20">
        <div class="vault42-spinner vault42-spinner-lg"></div>
      </div>
    </template>
  </VaultAuthGuard>
</template>
