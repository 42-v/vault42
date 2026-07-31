import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import ProfileView from '../views/ProfileView.vue'
import en from '../locales/en.json'

const mockFetchProfile = vi.fn()

type Profile = {
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

const mockProfile = ref<Profile | null>(null)
const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
// Drives which slot the auth guard renders (default = authenticated).
const mockGuardLoading = ref(false)

vi.mock('@vault42/vue', () => ({
  useProfile: () => ({
    profile: mockProfile,
    isLoading: mockIsLoading,
    error: mockError,
    fetchProfile: mockFetchProfile,
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
      return () => {
        const slot = mockGuardLoading.value ? slots.loading : slots.default
        return slot ? slot() : h('div')
      }
    },
  }),
}))

const RouterLinkStub = defineComponent({
  props: { to: { type: String, default: '' } },
  setup(props, { slots }) {
    return () => h('a', { href: props.to }, slots.default ? slots.default() : [])
  },
})

function makeProfile(overrides: Partial<Profile> = {}): Profile {
  return {
    id: 'usr_01HQ',
    email: 'jane@example.com',
    email_verified: true,
    display_name: 'Jane Doe',
    avatar_url: '',
    locale: 'en',
    mfa_required: false,
    mfa_enabled: false,
    mfa_methods: [],
    created_at: '2026-02-24T10:00:00Z',
    updated_at: '2026-02-24T10:00:00Z',
    ...overrides,
  }
}

function mountView() {
  return mount(ProfileView, {
    global: {
      stubs: {
        Teleport: true,
        RouterLink: RouterLinkStub,
      },
    },
  })
}

describe('ProfileView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockProfile.value = null
    mockIsLoading.value = false
    mockError.value = null
    mockGuardLoading.value = false
    mockFetchProfile.mockResolvedValue(undefined)
  })

  it('shows a spinner instead of a blank page while the auth guard initialises', () => {
    mockGuardLoading.value = true
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner-lg').exists()).toBe(true)
    expect(wrapper.find('h1').exists()).toBe(false)
  })

  it('fetches the profile on mount', () => {
    mountView()
    expect(mockFetchProfile).toHaveBeenCalledOnce()
  })

  it('renders the page title', () => {
    const wrapper = mountView()
    expect(wrapper.find('h1').text()).toBe('Profile')
  })

  it('shows a spinner and no account details while loading', () => {
    mockIsLoading.value = true
    mockProfile.value = makeProfile()
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('Account Details')
  })

  it('renders profile fields once loaded', async () => {
    mockFetchProfile.mockImplementation(async () => {
      mockProfile.value = makeProfile({ id: 'usr_abc123', email: 'jane@example.com', locale: 'sk' })
    })
    const wrapper = mountView()
    await flushPromises()

    expect(wrapper.text()).toContain('Jane Doe')
    expect(wrapper.text()).toContain('jane@example.com')
    expect(wrapper.text()).toContain('usr_abc123')
    expect(wrapper.text()).toContain('sk')
    expect(wrapper.text()).toContain('Account Details')
  })

  it('shows the friendly error message when the fetch fails', () => {
    mockError.value = { code: 'unauthorized' }
    const wrapper = mountView()
    expect(wrapper.find('.vault42-alert-error').text()).toBe('Your session has expired. Please sign in again.')
  })

  it('does not render stale profile data alongside a fetch error', () => {
    // A failed refresh must not leave the previous account details on screen
    // looking authoritative next to the error.
    mockProfile.value = makeProfile({ email: 'stale@example.com' })
    mockError.value = { code: 'internal_error' }
    const wrapper = mountView()

    expect(wrapper.find('.vault42-alert-error').exists()).toBe(true)
    expect(wrapper.text()).not.toContain('stale@example.com')
    expect(wrapper.text()).not.toContain('Account Details')
  })

  it('renders nothing but the heading when the profile is absent without an error', () => {
    mockProfile.value = null
    mockIsLoading.value = false
    mockError.value = null
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner').exists()).toBe(false)
    expect(wrapper.find('.vault42-alert-error').exists()).toBe(false)
    expect(wrapper.find('.vault42-card').exists()).toBe(false)
  })

  it('falls back to a placeholder when there is no display name', () => {
    mockProfile.value = makeProfile({ display_name: '' })
    const wrapper = mountView()
    expect(wrapper.find('h2').text()).toBe('No display name')
  })

  it('derives the avatar initial from the email when there is no display name', () => {
    mockProfile.value = makeProfile({ display_name: '', email: 'zoe@example.com' })
    const wrapper = mountView()
    expect(wrapper.find('.rounded-full span').text()).toBe('Z')
  })

  it('derives the avatar initial from the display name when present', () => {
    mockProfile.value = makeProfile({ display_name: 'jane doe', email: 'zoe@example.com' })
    const wrapper = mountView()
    expect(wrapper.find('.rounded-full span').text()).toBe('J')
  })

  it('shows the verified badge when the email is verified', () => {
    mockProfile.value = makeProfile({ email_verified: true })
    const wrapper = mountView()

    expect(wrapper.find('.vault42-badge-success').text()).toBe('Email verified')
    expect(wrapper.find('.vault42-badge-error').exists()).toBe(false)
  })

  it('shows the unverified badge when the email is not verified', () => {
    mockProfile.value = makeProfile({ email_verified: false })
    const wrapper = mountView()

    expect(wrapper.find('.vault42-badge-error').text()).toBe('Email not verified')
    expect(wrapper.find('.vault42-badge-success').exists()).toBe(false)
  })

  it('reports MFA as enabled without offering the enable link', () => {
    mockProfile.value = makeProfile({ mfa_enabled: true })
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Enabled')
    expect(wrapper.findAll('a').find(a => a.text() === 'Enable')).toBeUndefined()
  })

  it('offers a link to /2fa when MFA is disabled', () => {
    mockProfile.value = makeProfile({ mfa_enabled: false })
    const wrapper = mountView()

    const enableLink = wrapper.findAll('a').find(a => a.text() === 'Enable')
    expect(enableLink).toBeDefined()
    expect(enableLink!.attributes('href')).toBe('/2fa')
  })

  it('falls back to "Not set" for a missing locale', () => {
    mockProfile.value = makeProfile({ locale: '' })
    const wrapper = mountView()
    expect(wrapper.text()).toContain('Not set')
  })

  it('renders the creation date through the locale formatter', () => {
    mockProfile.value = makeProfile({ created_at: '2026-02-24T10:00:00Z' })
    const wrapper = mountView()
    expect(wrapper.text()).toContain(new Date('2026-02-24T10:00:00Z').toLocaleDateString())
  })
})
