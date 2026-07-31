import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref, defineComponent, h } from 'vue'
import SessionsView from '../views/SessionsView.vue'
import en from '../locales/en.json'

const mockFetchSessions = vi.fn()
const mockFetchDevices = vi.fn()
const mockRevokeSession = vi.fn()
const mockRevokeAllSessions = vi.fn()
const mockRenameDevice = vi.fn()
const mockRemoveDevice = vi.fn()

type Session = {
  id: string
  friendly_name?: string
  ip: string
  user_agent: string
  trusted: boolean
  last_seen_at?: string
  first_seen_at: string
}

type Device = {
  id: string
  friendly_name: string
  trusted: boolean
  ip: string
  user_agent: string
  last_seen_at?: string
  first_seen_at: string
  created_at: string
}

const mockSessions = ref<Session[]>([])
const mockDevices = ref<Device[]>([])
const mockIsLoading = ref(false)
const mockError = ref<{ code: string } | null>(null)
// Drives which slot the auth guard renders (default = authenticated).
const mockGuardLoading = ref(false)

vi.mock('@vault42/vue', () => ({
  useSessions: () => ({
    sessions: mockSessions,
    devices: mockDevices,
    isLoading: mockIsLoading,
    error: mockError,
    fetchSessions: mockFetchSessions,
    fetchDevices: mockFetchDevices,
    revokeSession: mockRevokeSession,
    revokeAllSessions: mockRevokeAllSessions,
    renameDevice: mockRenameDevice,
    removeDevice: mockRemoveDevice,
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

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 'sess_1',
    friendly_name: 'Laptop',
    ip: '10.0.0.1',
    user_agent: 'Mozilla/5.0',
    trusted: false,
    last_seen_at: '2026-02-24T10:00:00Z',
    first_seen_at: '2026-02-01T10:00:00Z',
    ...overrides,
  }
}

function makeDevice(overrides: Partial<Device> = {}): Device {
  return {
    id: 'dev_1',
    friendly_name: 'Work laptop',
    trusted: false,
    ip: '10.0.0.1',
    user_agent: 'Mozilla/5.0',
    last_seen_at: '2026-02-24T10:00:00Z',
    first_seen_at: '2026-02-01T10:00:00Z',
    created_at: '2026-02-01T10:00:00Z',
    ...overrides,
  }
}

function mountView() {
  return mount(SessionsView, {
    global: {
      stubs: {
        Teleport: true,
      },
    },
  })
}

function sessionRows(wrapper: ReturnType<typeof mountView>) {
  return wrapper.findAll('button').filter(b => b.text() === 'Revoke')
}

describe('SessionsView', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockSessions.value = []
    mockDevices.value = []
    mockIsLoading.value = false
    mockError.value = null
    mockGuardLoading.value = false
    mockFetchSessions.mockResolvedValue(undefined)
    mockFetchDevices.mockResolvedValue(undefined)
    mockRevokeSession.mockResolvedValue(undefined)
    mockRevokeAllSessions.mockResolvedValue(undefined)
    mockRenameDevice.mockResolvedValue(undefined)
    mockRemoveDevice.mockResolvedValue(undefined)
  })

  // ---- Sessions list ----

  it('shows a spinner instead of a blank page while the auth guard initialises', () => {
    mockGuardLoading.value = true
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner-lg').exists()).toBe(true)
    expect(wrapper.find('h1').exists()).toBe(false)
  })

  it('fetches both sessions and devices on mount', () => {
    mountView()
    expect(mockFetchSessions).toHaveBeenCalledOnce()
    expect(mockFetchDevices).toHaveBeenCalledOnce()
  })

  it('renders one row per session with its name, ip and timestamps', () => {
    mockSessions.value = [
      makeSession({ id: 'sess_1', friendly_name: 'Laptop', ip: '10.0.0.1' }),
      makeSession({ id: 'sess_2', friendly_name: 'Phone', ip: '10.0.0.2' }),
    ]
    const wrapper = mountView()

    expect(sessionRows(wrapper)).toHaveLength(2)
    expect(wrapper.text()).toContain('Laptop')
    expect(wrapper.text()).toContain('Phone')
    expect(wrapper.text()).toContain('10.0.0.1')
    expect(wrapper.text()).toContain('10.0.0.2')
    expect(wrapper.text()).toContain(`Last seen ${new Date('2026-02-24T10:00:00Z').toLocaleDateString()}`)
    expect(wrapper.text()).toContain(`Since ${new Date('2026-02-01T10:00:00Z').toLocaleDateString()}`)
  })

  it('falls back to the user agent, then to a placeholder, for unnamed sessions', () => {
    mockSessions.value = [
      makeSession({ id: 'sess_ua', friendly_name: undefined, user_agent: 'Mozilla/5.0 (X11; Linux x86_64)' }),
      makeSession({ id: 'sess_none', friendly_name: undefined, user_agent: '' }),
    ]
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Mozilla/5.0 (X11; Linux x86_64)')
    expect(wrapper.text()).toContain('Unknown session')
  })

  it('omits the timestamp lines when the server reported none', () => {
    // Rendering them unconditionally would print "Last seen Invalid Date".
    mockSessions.value = [makeSession({ id: 'sess_new', last_seen_at: undefined, first_seen_at: '' })]
    mockDevices.value = [makeDevice({ id: 'dev_new', last_seen_at: undefined })]
    const wrapper = mountView()

    expect(wrapper.text()).not.toContain('Last seen')
    expect(wrapper.text()).not.toContain('Since')
    expect(wrapper.text()).not.toContain('Invalid Date')
  })

  it('shows the empty state instead of a list when there are no sessions', () => {
    const wrapper = mountView()
    expect(wrapper.text()).toContain('No active sessions.')
    expect(sessionRows(wrapper)).toHaveLength(0)
  })

  it('shows a spinner instead of the session list while loading', () => {
    mockIsLoading.value = true
    mockSessions.value = [makeSession()]
    const wrapper = mountView()

    expect(wrapper.find('.vault42-spinner').exists()).toBe(true)
    expect(sessionRows(wrapper)).toHaveLength(0)
  })

  it('renders the friendly error message when the composable reports an error', () => {
    mockError.value = { code: 'rate_limited' }
    const wrapper = mountView()
    expect(wrapper.find('.vault42-alert-error').text()).toBe('Too many requests. Please wait a moment.')
  })

  // ---- Revoke one ----

  it('revokes exactly the session whose row was clicked', async () => {
    mockSessions.value = [
      makeSession({ id: 'sess_1', friendly_name: 'Laptop' }),
      makeSession({ id: 'sess_2', friendly_name: 'Phone' }),
    ]
    const wrapper = mountView()

    await sessionRows(wrapper)[1].trigger('click')
    await flushPromises()

    expect(mockRevokeSession).toHaveBeenCalledOnce()
    expect(mockRevokeSession).toHaveBeenCalledWith('sess_2')
  })

  it('keeps the row on screen when the revoke fails', async () => {
    // The list is server-truth: a failed revoke must not optimistically drop the row,
    // or the user believes a still-live session is gone.
    mockSessions.value = [makeSession({ id: 'sess_1', friendly_name: 'Laptop' })]
    mockRevokeSession.mockImplementation(async () => {
      mockError.value = { code: 'internal_error' }
    })

    const wrapper = mountView()
    await sessionRows(wrapper)[0].trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Something went wrong. Please try again later.')
    expect(sessionRows(wrapper)).toHaveLength(1)
    expect(wrapper.text()).toContain('Laptop')
    expect(wrapper.text()).not.toContain('No active sessions.')
  })

  it('drops the row only once the composable removes it', async () => {
    mockSessions.value = [
      makeSession({ id: 'sess_1', friendly_name: 'Laptop' }),
      makeSession({ id: 'sess_2', friendly_name: 'Phone' }),
    ]
    mockRevokeSession.mockImplementation(async (id: string) => {
      mockSessions.value = mockSessions.value.filter(s => s.id !== id)
    })

    const wrapper = mountView()
    await sessionRows(wrapper)[0].trigger('click')
    await flushPromises()

    expect(sessionRows(wrapper)).toHaveLength(1)
    expect(wrapper.text()).not.toContain('Laptop')
    expect(wrapper.text()).toContain('Phone')
  })

  // ---- Revoke all ----

  it('hides the revoke-all button when there is nothing to revoke', () => {
    mockSessions.value = []
    const wrapper = mountView()
    expect(wrapper.findAll('button').find(b => b.text() === 'Revoke All')).toBeUndefined()
  })

  it('revokes every session once when revoke-all is clicked', async () => {
    mockSessions.value = [makeSession({ id: 'sess_1' }), makeSession({ id: 'sess_2' })]
    const wrapper = mountView()

    const revokeAll = wrapper.findAll('button').find(b => b.text() === 'Revoke All')
    expect(revokeAll).toBeDefined()
    await revokeAll!.trigger('click')
    await flushPromises()

    expect(mockRevokeAllSessions).toHaveBeenCalledOnce()
    expect(mockRevokeSession).not.toHaveBeenCalled()
  })

  it('leaves every row in place when revoke-all fails', async () => {
    mockSessions.value = [makeSession({ id: 'sess_1', friendly_name: 'Laptop' }), makeSession({ id: 'sess_2', friendly_name: 'Phone' })]
    mockRevokeAllSessions.mockImplementation(async () => {
      mockError.value = { code: 'unauthorized' }
    })

    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Revoke All')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Your session has expired. Please sign in again.')
    expect(sessionRows(wrapper)).toHaveLength(2)
  })

  // ---- Devices ----

  it('shows the devices empty state only when the fetch is finished', () => {
    mockDevices.value = []
    mockIsLoading.value = false
    const wrapper = mountView()
    expect(wrapper.text()).toContain('No devices registered yet.')
  })

  it('renders devices with their trusted badge', () => {
    mockDevices.value = [
      makeDevice({ id: 'dev_1', friendly_name: 'Work laptop', trusted: true }),
      makeDevice({ id: 'dev_2', friendly_name: 'Tablet', trusted: false }),
    ]
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Work laptop')
    expect(wrapper.text()).toContain('Tablet')
    expect(wrapper.findAll('.vault42-badge-success')).toHaveLength(1)
    expect(wrapper.find('.vault42-badge-success').text()).toBe('Trusted')
  })

  it('falls back to the user agent, then to a placeholder, for unnamed devices', () => {
    mockDevices.value = [
      makeDevice({ id: 'dev_ua', friendly_name: '', user_agent: 'Firefox/128.0' }),
      makeDevice({ id: 'dev_none', friendly_name: '', user_agent: '' }),
    ]
    const wrapper = mountView()

    expect(wrapper.text()).toContain('Firefox/128.0')
    expect(wrapper.text()).toContain('Unknown device')
  })

  it('removes exactly the device whose row was clicked', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1' }), makeDevice({ id: 'dev_2' })]
    const wrapper = mountView()

    const removeBtns = wrapper.findAll('button').filter(b => b.text() === 'Remove')
    await removeBtns[1].trigger('click')
    await flushPromises()

    expect(mockRemoveDevice).toHaveBeenCalledOnce()
    expect(mockRemoveDevice).toHaveBeenCalledWith('dev_2')
  })

  it('keeps the device row when removal fails', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    mockRemoveDevice.mockImplementation(async () => {
      mockError.value = { code: 'internal_error' }
    })

    const wrapper = mountView()
    await wrapper.findAll('button').find(b => b.text() === 'Remove')!.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Work laptop')
    expect(wrapper.text()).not.toContain('No devices registered yet.')
    expect(wrapper.find('.vault42-alert-error').exists()).toBe(true)
  })

  // ---- Rename device ----

  it('opens the rename editor prefilled with the current name', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')

    const input = wrapper.find('input')
    expect(input.exists()).toBe(true)
    expect((input.element as HTMLInputElement).value).toBe('Work laptop')
  })

  it('opens an empty editor for an unnamed device rather than seeding the user agent', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: '', user_agent: 'Firefox/128.0' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    expect((wrapper.find('input').element as HTMLInputElement).value).toBe('')
  })

  it('renames the device with the trimmed name and closes the editor', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    mockRenameDevice.mockImplementation(async (id: string, name: string) => {
      const d = mockDevices.value.find(x => x.id === id)
      if (d) d.friendly_name = name
    })

    const wrapper = mountView()
    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('  Home desktop  ')
    await wrapper.findAll('button').find(b => b.text() === 'Save')!.trigger('click')
    await flushPromises()

    expect(mockRenameDevice).toHaveBeenCalledWith('dev_1', 'Home desktop')
    expect(wrapper.find('input').exists()).toBe(false)
    expect(wrapper.text()).toContain('Home desktop')
  })

  it('saves the rename on Enter', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('Renamed')
    await wrapper.find('input').trigger('keyup.enter')
    await flushPromises()

    expect(mockRenameDevice).toHaveBeenCalledWith('dev_1', 'Renamed')
  })

  it('discards the edit on Escape without calling the API', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('Throwaway')
    await wrapper.find('input').trigger('keyup.escape')

    expect(mockRenameDevice).not.toHaveBeenCalled()
    expect(wrapper.find('input').exists()).toBe(false)
    expect(wrapper.text()).toContain('Work laptop')
    expect(wrapper.text()).not.toContain('Throwaway')
  })

  it('discards the edit on Cancel without calling the API', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('Throwaway')
    await wrapper.findAll('button').find(b => b.text() === 'Cancel')!.trigger('click')

    expect(mockRenameDevice).not.toHaveBeenCalled()
    expect(wrapper.find('input').exists()).toBe(false)
    expect(wrapper.text()).toContain('Work laptop')
  })

  it('refuses to submit a blank rename and keeps the editor open', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('   ')
    await wrapper.findAll('button').find(b => b.text() === 'Save')!.trigger('click')
    await flushPromises()

    expect(mockRenameDevice).not.toHaveBeenCalled()
    expect(wrapper.find('input').exists()).toBe(true)
  })

  it('does not show the new name when the rename fails', async () => {
    // The composable swallows the failure; the list must still show the server-side name.
    mockDevices.value = [makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' })]
    mockRenameDevice.mockImplementation(async () => {
      mockError.value = { code: 'name_too_long' }
    })

    const wrapper = mountView()
    await wrapper.find('button[title="Rename device"]').trigger('click')
    await wrapper.find('input').setValue('Home desktop')
    await wrapper.findAll('button').find(b => b.text() === 'Save')!.trigger('click')
    await flushPromises()

    expect(wrapper.find('.vault42-alert-error').text()).toBe('Blob name is too long (max 255 characters).')
    expect(wrapper.text()).not.toContain('Home desktop')
    expect(wrapper.text()).toContain('Work laptop')
  })

  it('only edits the device whose pencil was clicked', async () => {
    mockDevices.value = [
      makeDevice({ id: 'dev_1', friendly_name: 'Work laptop' }),
      makeDevice({ id: 'dev_2', friendly_name: 'Tablet' }),
    ]
    const wrapper = mountView()

    await wrapper.findAll('button[title="Rename device"]')[1].trigger('click')
    expect(wrapper.findAll('input')).toHaveLength(1)

    await wrapper.find('input').setValue('Slate')
    await wrapper.findAll('button').find(b => b.text() === 'Save')!.trigger('click')
    await flushPromises()

    expect(mockRenameDevice).toHaveBeenCalledWith('dev_2', 'Slate')
  })

  it('caps the rename input length at the server limit', async () => {
    mockDevices.value = [makeDevice({ id: 'dev_1' })]
    const wrapper = mountView()

    await wrapper.find('button[title="Rename device"]').trigger('click')
    expect(wrapper.find('input').attributes('maxlength')).toBe('100')
  })
})
