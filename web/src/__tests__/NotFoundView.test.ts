import { describe, it, expect, vi, beforeEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import { createRouter, createWebHistory, type Router } from 'vue-router'
import NotFoundView from '../views/NotFoundView.vue'
import en from '../locales/en.json'
import sk from '../locales/sk.json'

const localeMessages: Record<string, Record<string, string>> = {
  en: en as Record<string, string>,
  sk: sk as Record<string, string>,
}

const mockLocale = ref('en')

vi.mock('@vault42/vue', () => ({
  useT: () => ({
    t: (key: string) => {
      const msgs = localeMessages[mockLocale.value] ?? localeMessages.en
      return msgs[key] ?? localeMessages.en[key] ?? key
    },
    locale: mockLocale,
    setLocale: vi.fn(),
    availableLocales: ['en', 'sk'],
    formatDate: (d: Date) => d.toLocaleDateString(),
    formatNumber: (n: number) => n.toString(),
  }),
}))

const stub = { template: '<div>home page</div>' }

function createTestRouter(): Router {
  return createRouter({
    history: createWebHistory(),
    routes: [
      { path: '/', component: stub },
      { path: '/:pathMatch(.*)*', component: NotFoundView },
    ],
  })
}

async function mountView() {
  const router = createTestRouter()
  await router.push('/no-such-page')
  await router.isReady()
  const wrapper = mount(NotFoundView, { global: { plugins: [router] } })
  return { wrapper, router }
}

describe('NotFoundView', () => {
  beforeEach(() => {
    mockLocale.value = 'en'
  })

  it('renders the 404 code and the not-found copy', async () => {
    const { wrapper } = await mountView()

    expect(wrapper.text()).toContain('404')
    expect(wrapper.find('h1').text()).toBe('Page not found')
    expect(wrapper.text()).toContain("The page you're looking for doesn't exist or has been moved.")
  })

  it('offers a Go Home link pointing at the root route', async () => {
    const { wrapper } = await mountView()

    const link = wrapper.findAll('a').find(a => a.text() === 'Go Home')
    expect(link).toBeDefined()
    expect(link!.attributes('href')).toBe('/')
  })

  it('actually navigates back to the root route when the escape link is clicked', async () => {
    const { wrapper, router } = await mountView()
    expect(router.currentRoute.value.path).toBe('/no-such-page')

    const link = wrapper.findAll('a').find(a => a.text() === 'Go Home')
    await link!.trigger('click')
    await flushPromises()

    expect(router.currentRoute.value.path).toBe('/')
  })

  it('translates the escape hatch instead of hard-coding English', async () => {
    mockLocale.value = 'sk'
    const { wrapper } = await mountView()

    expect(wrapper.find('h1').text()).toBe('Stránka nenájdená')
    const link = wrapper.findAll('a').find(a => a.attributes('href') === '/')
    expect(link!.text()).toBe('Domov')
  })
})
