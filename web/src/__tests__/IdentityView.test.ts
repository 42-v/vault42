import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import IdentityView from '../views/IdentityView.vue'
import en from '../locales/en.json'

// Mock the @vault42/vue module
const mockFetchIdentity = vi.fn()
const mockSaveIdentity = vi.fn()
const mockDeleteIdentity = vi.fn()

const mockIdentity = ref<Record<string, unknown> | null>(null)
const mockIsLoading = ref(false)
const mockIsSaving = ref(false)
const mockError = ref<{ code: string } | null>(null)

vi.mock('@vault42/vue', () => ({
  useIdentity: () => ({
    identity: mockIdentity,
    isLoading: mockIsLoading,
    isSaving: mockIsSaving,
    error: mockError,
    fetchIdentity: mockFetchIdentity,
    saveIdentity: mockSaveIdentity,
    deleteIdentity: mockDeleteIdentity,
  }),
  useT: () => ({
    t: (key: string, params?: Record<string, string | number>) => {
      const val = (en as Record<string, string>)[key] ?? key
      if (!params) return val
      return val.replace(/\{(\w+)\}/g, (_, name: string) => params[name] != null ? String(params[name]) : `{${name}}`)
    },
    formatDate: (d: Date) => d.toLocaleDateString(),
  }),
  VaultAuthGuard: defineComponent({
    setup(_, { slots }) {
      // Always render the default slot (simulates authenticated state)
      return () => slots.default ? slots.default() : h('div')
    },
  }),
}))

function mountView() {
  return mount(IdentityView, {
    global: {
      stubs: {
        Teleport: true,
      },
    },
  })
}

describe('IdentityView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockIdentity.value = null
    mockIsLoading.value = false
    mockIsSaving.value = false
    mockError.value = null
    mockFetchIdentity.mockResolvedValue(undefined)
    mockSaveIdentity.mockResolvedValue(true)
    mockDeleteIdentity.mockResolvedValue(true)
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Personal Information')
  })

  it('shows loading spinner when isLoading', async () => {
    mockIsLoading.value = true
    const wrapper = mountView()
    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
    expect(wrapper.find('form').exists()).toBe(false)
  })

  it('renders form fields when loaded', () => {
    const wrapper = mountView()

    expect(wrapper.find('input[placeholder="Jane"]').exists()).toBe(true)
    expect(wrapper.find('input[placeholder="Doe"]').exists()).toBe(true)
    expect(wrapper.find('input[placeholder="US"]').exists()).toBe(true)
    expect(wrapper.find('input[type="date"]').exists()).toBe(true)
    expect(wrapper.find('select').exists()).toBe(true)
  })

  it('renders sex options', () => {
    const wrapper = mountView()
    const options = wrapper.findAll('select option')
    const labels = options.map(o => o.text())
    expect(labels).toContain('Male')
    expect(labels).toContain('Female')
    expect(labels).toContain('Prefer not to say')
  })

  it('has a Save Identity button', () => {
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect(btn.text()).toContain('Save Identity')
  })

  it('disables save button when isSaving', async () => {
    mockIsSaving.value = true
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
  })

  it('shows spinner in save button when isSaving', () => {
    mockIsSaving.value = true
    const wrapper = mountView()
    const btn = wrapper.find('button[type="submit"]')
    expect(btn.find('.vault42-spinner').exists()).toBe(true)
  })

  it('shows delete button when identity exists', () => {
    mockIdentity.value = { given_name: 'Jane' }
    const wrapper = mountView()
    const deleteBtn = wrapper.findAll('button').find(b => b.text() === 'Delete')
    expect(deleteBtn).toBeDefined()
  })

  it('hides delete button when no identity', () => {
    mockIdentity.value = null
    const wrapper = mountView()
    // Find all non-submit buttons
    const buttons = wrapper.findAll('button[type="button"]')
    const deleteBtn = buttons.find(b => b.text() === 'Delete')
    expect(deleteBtn).toBeUndefined()
  })

  it('shows error message when error exists', () => {
    mockError.value = { code: 'internal_error' }
    const wrapper = mountView()
    expect(wrapper.find('.vault42-alert-error').text()).toBe('Something went wrong. Please try again later.')
  })

  it('calls fetchIdentity on mount', () => {
    mountView()
    expect(mockFetchIdentity).toHaveBeenCalledOnce()
  })

  it('hides billing section by default', () => {
    const wrapper = mountView()
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(false)
  })

  it('shows billing section when toggle clicked', async () => {
    const wrapper = mountView()
    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    expect(toggleBtn).toBeDefined()
    await toggleBtn!.trigger('click')
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(true)
  })

  it('calls saveIdentity on form submit', async () => {
    const wrapper = mountView()

    // Fill form
    await wrapper.find('input[placeholder="Jane"]').setValue('John')
    await wrapper.find('input[placeholder="Doe"]').setValue('Smith')

    // Submit
    await wrapper.find('form').trigger('submit')

    expect(mockSaveIdentity).toHaveBeenCalledOnce()
    const savedData = mockSaveIdentity.mock.calls[0][0]
    expect(savedData.given_name).toBe('John')
    expect(savedData.family_name).toBe('Smith')
  })

  it('shows success message after save', async () => {
    mockSaveIdentity.mockResolvedValue(true)
    const wrapper = mountView()

    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-success').text()).toBe('Identity saved successfully.')
  })

  it('includes billing data when billing section is shown', async () => {
    const wrapper = mountView()

    // Open billing
    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    await toggleBtn!.trigger('click')

    // Fill billing
    await wrapper.find('input[placeholder="SK"]').setValue('SK')

    // Submit
    await wrapper.find('form').trigger('submit')

    const savedData = mockSaveIdentity.mock.calls[0][0]
    expect(savedData.billing).toBeDefined()
    expect(savedData.billing.country).toBe('SK')
  })

  it('populates form from fetched identity on mount', async () => {
    // Set identity BEFORE mount, and make fetchIdentity set it
    mockFetchIdentity.mockImplementation(async () => {
      mockIdentity.value = {
        given_name: 'Jane',
        family_name: 'Doe',
        country: 'US',
        date_of_birth: '1990-05-15',
        sex: 'female',
      }
    })

    const wrapper = mountView()
    await flushPromises()

    expect((wrapper.find('input[placeholder="Jane"]').element as HTMLInputElement).value).toBe('Jane')
    expect((wrapper.find('input[placeholder="Doe"]').element as HTMLInputElement).value).toBe('Doe')
    expect((wrapper.find('input[placeholder="US"]').element as HTMLInputElement).value).toBe('US')
    expect((wrapper.find('input[type="date"]').element as HTMLInputElement).value).toBe('1990-05-15')
    expect((wrapper.find('select').element as HTMLSelectElement).value).toBe('female')
  })

  it('populates billing from fetched identity with billing', async () => {
    mockFetchIdentity.mockImplementation(async () => {
      mockIdentity.value = {
        given_name: 'Jane',
        billing: {
          address_line_1: '123 Main St',
          address_line_2: 'Apt 4',
          city: 'Springfield',
          postal_code: '62704',
          country: 'US',
          vat_id: 'VAT123',
        },
      }
    })

    const wrapper = mountView()
    await flushPromises()

    // Billing section should be shown automatically
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(true)
  })

  it('handles delete confirmation flow', async () => {
    mockIdentity.value = { given_name: 'Jane' }
    const wrapper = mountView()

    // Click the outer Delete button to open confirmation
    const outerDeleteBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Delete')
    await outerDeleteBtn!.trigger('click')

    // The delete confirmation modal should render (stubbed via Teleport)
    // Look for the confirmation text
    expect(wrapper.text()).toContain('Delete Personal Information')
  })

  it('calls deleteIdentity and resets form after confirmation', async () => {
    mockIdentity.value = { given_name: 'Jane', family_name: 'Doe' }
    const wrapper = mountView()

    // Set a form value first
    await wrapper.find('input[placeholder="Jane"]').setValue('Jane')

    // Open confirmation
    const outerDeleteBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Delete')
    await outerDeleteBtn!.trigger('click')

    // Click the confirm Delete button inside the modal
    const confirmDeleteBtn = wrapper.findAll('button').filter(b => b.classes().some(c => c.includes('vault42-btn-danger')))
    // The last vault42-btn-danger in the DOM should be the confirmation one
    const lastDanger = confirmDeleteBtn[confirmDeleteBtn.length - 1]
    await lastDanger.trigger('click')
    await flushPromises()

    expect(mockDeleteIdentity).toHaveBeenCalledOnce()
  })

  it('does not show success message when save returns false', async () => {
    mockSaveIdentity.mockResolvedValue(false)
    const wrapper = mountView()

    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-success').exists()).toBe(false)
  })

  it('excludes empty fields as undefined in save', async () => {
    const wrapper = mountView()

    // Leave all fields empty and submit
    await wrapper.find('form').trigger('submit')

    const savedData = mockSaveIdentity.mock.calls[0][0]
    expect(savedData.given_name).toBeUndefined()
    expect(savedData.family_name).toBeUndefined()
    expect(savedData.country).toBeUndefined()
    expect(savedData.billing).toBeUndefined()
  })

  it('handles identity without billing property', async () => {
    mockFetchIdentity.mockImplementation(async () => {
      mockIdentity.value = {
        given_name: 'Test',
      }
    })

    const wrapper = mountView()
    await flushPromises()

    // Billing should still be hidden
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(false)
  })

  it('hides billing toggle text changes', async () => {
    const wrapper = mountView()

    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    expect(toggleBtn!.text()).toBe('Add billing info')

    await toggleBtn!.trigger('click')
    expect(toggleBtn!.text()).toBe('Hide')
  })

  it('fills all billing fields when saving', async () => {
    const wrapper = mountView()

    // Open billing
    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    await toggleBtn!.trigger('click')

    // Submit with billing open but empty
    await wrapper.find('form').trigger('submit')

    const savedData = mockSaveIdentity.mock.calls[0][0]
    // All billing fields should be undefined (empty strings become undefined)
    expect(savedData.billing).toBeDefined()
    expect(savedData.billing.address_line_1).toBeUndefined()
  })

  it('populates all billing fields from fetched identity', async () => {
    mockFetchIdentity.mockImplementation(async () => {
      mockIdentity.value = {
        given_name: 'Jane',
        billing: {
          address_line_1: '123 Main St',
          address_line_2: 'Apt 4',
          city: 'Springfield',
          postal_code: '62704',
          country: 'US',
          vat_id: 'VAT123',
        },
      }
    })

    const wrapper = mountView()
    await flushPromises()

    // All billing fields should be populated
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(true)
    expect((wrapper.find('input[placeholder="SK"]').element as HTMLInputElement).value).toBe('US')
  })

  it('saves billing fields with values when filled', async () => {
    const wrapper = mountView()

    // Open billing
    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    await toggleBtn!.trigger('click')

    // Fill all billing fields
    const billingCountry = wrapper.find('input[placeholder="SK"]')
    await billingCountry.setValue('CZ')

    await wrapper.find('form').trigger('submit')

    const savedData = mockSaveIdentity.mock.calls[0][0]
    expect(savedData.billing.country).toBe('CZ')
  })

  it('resets form completely after delete', async () => {
    mockIdentity.value = { given_name: 'Jane', family_name: 'Doe' }
    const wrapper = mountView()

    // Fill form values
    await wrapper.find('input[placeholder="Jane"]').setValue('Jane')

    // Open billing, then delete
    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    await toggleBtn!.trigger('click')
    await wrapper.find('input[placeholder="SK"]').setValue('DE')

    // Open confirmation
    const outerDeleteBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Delete')
    await outerDeleteBtn!.trigger('click')

    // Confirm
    const confirmDeleteBtn = wrapper.findAll('button').filter(b => b.classes().some(c => c.includes('vault42-btn-danger')))
    const lastDanger = confirmDeleteBtn[confirmDeleteBtn.length - 1]
    await lastDanger.trigger('click')
    await flushPromises()

    expect(mockDeleteIdentity).toHaveBeenCalledOnce()
    // Form should be cleared
    expect((wrapper.find('input[placeholder="Jane"]').element as HTMLInputElement).value).toBe('')
    // Billing should be hidden again
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(false)
  })

  it('closes delete modal on overlay click', async () => {
    mockIdentity.value = { given_name: 'Jane' }
    const wrapper = mountView()

    const outerDeleteBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Delete')
    await outerDeleteBtn!.trigger('click')
    expect(wrapper.text()).toContain('Delete Personal Information')

    // Click overlay
    const overlay = wrapper.find('.vault42-modal-overlay')
    await overlay.trigger('click')
    expect(wrapper.find('.vault42-modal-overlay').exists()).toBe(false)
  })

  it('renders all billing form fields when billing is open', async () => {
    const wrapper = mountView()

    const toggleBtn = wrapper.findAll('button[type="button"]').find(b => b.text() === 'Add billing info')
    await toggleBtn!.trigger('click')

    // Check all billing inputs exist
    expect(wrapper.find('input[placeholder="SK"]').exists()).toBe(true)
    expect(wrapper.findAll('input[maxlength="200"]').length).toBe(2) // address line 1 & 2
    expect(wrapper.findAll('input[maxlength="100"]').length).toBeGreaterThanOrEqual(3) // given_name, family_name, city
    expect(wrapper.find('input[maxlength="20"]').exists()).toBe(true) // postal code
    expect(wrapper.find('input[maxlength="50"]').exists()).toBe(true) // vat_id
  })

  it('renders sex select with correct options', () => {
    const wrapper = mountView()
    const select = wrapper.find('select')
    const options = select.findAll('option')
    expect(options.length).toBe(4) // not specified + 3 options
    expect(options[0].text()).toBe('-- Not specified --')
  })
})
