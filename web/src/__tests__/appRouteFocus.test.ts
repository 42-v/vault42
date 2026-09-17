import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import { createRouter, createWebHistory, type Router } from 'vue-router'
import App from '../App.vue'

// A routed navigation must land focus in the content.
//
// The shell does not remount when the route changes -- App.test.ts pins that --
// so the browser has no reason to move focus at all. Whatever the visitor
// activated keeps it, and when that control was inside the view being replaced,
// focus falls to <body>. Either way the new page is never announced and the
// next Tab resumes from the header.
//
// These tests assert document.activeElement, which is the only thing a screen
// reader and a Tab key both read. That is why the wrapper is attached to the
// document: an unattached tree has no active element to be.

const mockIsAuthenticated = ref(true)
const mockInitialized = ref(true)
const mockIsLoading = ref(false)
const mockUser = ref<{ email: string } | null>({ email: 'v@example.com' })
const mockRegistrationEnabled = ref(true)

vi.mock('@vault42/vue', () => ({
  useAuth: () => ({
    isAuthenticated: mockIsAuthenticated,
    initialized: mockInitialized,
    isLoading: mockIsLoading,
    user: mockUser,
    registrationEnabled: mockRegistrationEnabled,
    init: vi.fn(),
    logout: vi.fn(),
  }),
  useT: () => ({
    t: (key: string) => key,
    locale: ref('en'),
    setLocale: vi.fn(),
    availableLocales: ['en'],
    formatDate: (d: Date) => d.toISOString(),
    formatNumber: (n: number) => String(n),
  }),
}))

const stub = { template: '<div />' }

function createTestRouter(): Router {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: { template: '<p>dashboard</p>' } },
      { path: '/profile', component: { template: '<p>profile</p>' } },
      { path: '/sessions', component: stub },
      { path: '/2fa', component: stub },
      { path: '/password', component: stub },
      { path: '/identity', component: stub },
      { path: '/storage', component: stub },
      { path: '/login', component: stub },
      { path: '/register', component: stub },
    ],
  })
}

async function mountApp(path = '/') {
  const router = createTestRouter()
  await router.push(path)
  await router.isReady()
  const wrapper = mount(App, {
    global: { plugins: [router] },
    attachTo: document.body,
  })
  await flushPromises()
  return { wrapper, router }
}

describe('focus after a routed navigation', () => {
  beforeEach(() => {
    document.body.innerHTML = ''
    mockIsAuthenticated.value = true
    mockInitialized.value = true
    mockRegistrationEnabled.value = true
  })

  // This assertion is load-bearing, not a restatement of the template.
  //
  // happy-dom will focus any element handed to .focus(); a browser refuses a
  // <main> that has no tabindex, and the call silently does nothing. Removing
  // the attribute therefore leaves every behavioural test in this file green
  // while the feature is dead in production, and this is the only check that
  // fails.
  it('gives main a programmatic focus target that is not in the tab order', async () => {
    const { wrapper } = await mountApp()
    const main = wrapper.find('main')

    expect(main.attributes('tabindex')).toBe('-1')
    expect(main.attributes('id')).toBe('main-content')
    wrapper.unmount()
  })

  it('moves focus to main when the route changes', async () => {
    const { wrapper, router } = await mountApp()

    // Where the browser leaves it after a nav link is activated.
    const link = wrapper.findAll('a').find(a => a.attributes('href') === '/profile')!
    ;(link.element as HTMLElement).focus()
    expect(document.activeElement).toBe(link.element)

    await router.push('/profile')
    await flushPromises()

    expect(document.activeElement).toBe(wrapper.find('main').element)
    wrapper.unmount()
  })

  it('focuses main even when the control that was activated is gone', async () => {
    const { wrapper, router } = await mountApp()

    // The routed view owns the control, so it is unmounted by the navigation
    // and focus falls to <body>. This is the case a "restore the previous
    // element" strategy cannot serve, and the reason focus goes to a landmark
    // that outlives the view rather than back where it came from.
    ;(document.body as HTMLElement).focus()

    await router.push('/sessions')
    await flushPromises()

    expect(document.activeElement).toBe(wrapper.find('main').element)
    wrapper.unmount()
  })

  it('leaves focus alone on the first paint', async () => {
    // The initial navigation is the page load. The browser's own focus is
    // correct there, and moving it would skip the header before it was read.
    const { wrapper } = await mountApp('/profile')

    expect(document.activeElement).not.toBe(wrapper.find('main').element)
    wrapper.unmount()
  })

  it('leaves focus alone when only the query changes', async () => {
    const { wrapper, router } = await mountApp('/2fa')

    const link = wrapper.findAll('a').find(a => a.attributes('href') === '/profile')!
    ;(link.element as HTMLElement).focus()

    // Same path, different query: the view stays mounted, so there is nothing
    // new to read and pulling focus would interrupt whatever is being operated.
    await router.push('/2fa?tab=webauthn')
    await flushPromises()

    expect(document.activeElement).toBe(link.element)
    wrapper.unmount()
  })
})
