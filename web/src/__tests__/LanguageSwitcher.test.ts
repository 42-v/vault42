import { describe, it, expect, vi, beforeAll, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import { ref } from 'vue'
import LanguageSwitcher from '../components/LanguageSwitcher.vue'
import { loadLocale } from '../i18n'
import en from '../locales/en.json'

const AVAILABLE = ['en', 'sk', 'ja', 'zh-Hans', 'xx']

const mockLocale = ref('en')
const mockSetLocale = vi.fn((loc: string) => {
  mockLocale.value = loc
})

/** Flipped by one test to simulate a locale chunk that will not download. */
const mockLocaleChunkFails = { value: false }

vi.mock('../i18n', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../i18n')>()
  return {
    ...actual,
    loadLocale: async (locale: string) => {
      if (mockLocaleChunkFails.value) throw new Error('failed to fetch dynamically imported module')
      return actual.loadLocale(locale)
    },
  }
})

vi.mock('@vault42/vue', () => ({
  useT: () => ({
    t: (key: string) => (en as Record<string, string>)[key] ?? key,
    locale: mockLocale,
    setLocale: mockSetLocale,
    availableLocales: AVAILABLE,
    formatDate: (d: Date) => d.toLocaleDateString(),
    formatNumber: (n: number) => n.toString(),
  }),
}))

function mountSwitcher(attach = false) {
  return mount(LanguageSwitcher, attach ? { attachTo: document.body } : {})
}

function trigger(wrapper: ReturnType<typeof mountSwitcher>) {
  return wrapper.findAll('button')[0]
}

function optionButtons(wrapper: ReturnType<typeof mountSwitcher>) {
  return wrapper.findAll('button').slice(1)
}

/**
 * Clicks an option and waits for the switch to settle.
 *
 * `select` fetches the locale's catalogue before flipping the locale, so a bare
 * `trigger('click')` returns while the chunk is still in flight.
 */
async function pick(wrapper: ReturnType<typeof mountSwitcher>, label: string) {
  const option = optionButtons(wrapper).find(b => b.text().includes(label))
  expect(option, `no option matching ${label}`).toBeDefined()
  await option!.trigger('click')
  await flushPromises()
}

describe('LanguageSwitcher', () => {
  // `select` awaits loadLocale before switching. Warming the catalogues here
  // puts it on its already-loaded fast path, so a single flushPromises settles
  // the click; a cold dynamic import needs more than one drain of the microtask
  // queue and the assertions would race it. The loader's own cold path,
  // including the miss that returns false, is covered in i18nIndex.test.ts.
  beforeAll(async () => {
    await Promise.all(['en', 'sk', 'ja', 'zh-Hans'].map(loadLocale))
  })

  beforeEach(() => {
    vi.clearAllMocks()
    mockLocale.value = 'en'
    localStorage.clear()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('labels the trigger with the human name of the active locale', () => {
    mockLocale.value = 'sk'
    const wrapper = mountSwitcher()

    expect(trigger(wrapper).text()).toContain('Slovencina')
  })

  it('falls back to the raw code when a locale has no human name', () => {
    mockLocale.value = 'xx'
    const wrapper = mountSwitcher()

    expect(trigger(wrapper).text()).toContain('xx')
  })

  it('keeps the list closed until the trigger is clicked', () => {
    const wrapper = mountSwitcher()

    expect(optionButtons(wrapper)).toHaveLength(0)
    expect(wrapper.find('input[type="text"]').exists()).toBe(false)
  })

  it('lists every available locale with its name and uppercase code once opened', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    const options = optionButtons(wrapper)
    expect(options).toHaveLength(AVAILABLE.length)

    const text = wrapper.text()
    expect(text).toContain('English')
    expect(text).toContain('Slovencina')
    expect(text).toContain('Nihongo')
    expect(text).toContain('Zhongwen (Jian)')
    expect(text).toContain('ZH-HANS')
    expect(text).toContain('EN')
  })

  it('does not offer locales the app was never built with', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    expect(wrapper.text()).not.toContain('Magyar')
    expect(wrapper.text()).not.toContain('Deutsch')
  })

  it('marks the active locale in the list', async () => {
    mockLocale.value = 'ja'
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    const active = optionButtons(wrapper).filter(b => b.classes().includes('text-vault42-accent'))
    expect(active).toHaveLength(1)
    expect(active[0].text()).toContain('Nihongo')
  })

  it('applies and persists the chosen locale', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    await pick(wrapper, 'Slovencina')

    expect(mockSetLocale).toHaveBeenCalledExactlyOnceWith('sk')
    expect(localStorage.getItem('vault42-locale')).toBe('sk')
  })

  it('persists the exact tagged code, not a truncated one', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    await pick(wrapper, 'Zhongwen (Jian)')

    expect(mockSetLocale).toHaveBeenCalledExactlyOnceWith('zh-Hans')
    expect(localStorage.getItem('vault42-locale')).toBe('zh-Hans')
  })

  it('publishes the chosen locale on the document element', async () => {
    // Without this the page stays lang="en" forever, so a screen reader
    // pronounces every translation with English rules.
    document.documentElement.lang = 'en'
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await pick(wrapper, 'Nihongo')

    expect(document.documentElement.lang).toBe('ja')
    expect(document.documentElement.dir).toBe('ltr')
  })

  it('keeps the current language when a locale has no catalogue to load', async () => {
    // 'xx' is offered by the mocked availableLocales but has no locale file, so
    // its chunk cannot load. Switching anyway would render nothing but keys.
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await pick(wrapper, 'xx')

    expect(mockSetLocale).not.toHaveBeenCalled()
    expect(localStorage.getItem('vault42-locale')).toBeNull()
    expect(optionButtons(wrapper)).toHaveLength(0)
  })

  it('survives a locale chunk that fails to download', async () => {
    // Offline, or a stale index pointing at an evicted chunk. Neither may leave
    // the switcher stuck open or the app rendering bare translation keys.
    mockLocaleChunkFails.value = true
    try {
      const wrapper = mountSwitcher()
      await trigger(wrapper).trigger('click')
      await pick(wrapper, 'Slovencina')

      expect(mockSetLocale).not.toHaveBeenCalled()
      expect(localStorage.getItem('vault42-locale')).toBeNull()
      expect(optionButtons(wrapper)).toHaveLength(0)
      expect(trigger(wrapper).text()).toContain('English')
    } finally {
      mockLocaleChunkFails.value = false
    }
  })

  it('closes the list and relabels the trigger after a selection', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await pick(wrapper, 'Slovencina')

    expect(optionButtons(wrapper)).toHaveLength(0)
    expect(trigger(wrapper).text()).toContain('Slovencina')
  })

  it('filters the list by locale name, case-insensitively', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('sloven')

    const options = optionButtons(wrapper)
    expect(options).toHaveLength(1)
    expect(options[0].text()).toContain('Slovencina')
  })

  it('filters the list by locale code', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('ja')

    const options = optionButtons(wrapper)
    expect(options).toHaveLength(1)
    expect(options[0].text()).toContain('Nihongo')
  })

  it('says "No results" instead of silently showing an empty list', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('klingon')

    expect(optionButtons(wrapper)).toHaveLength(0)
    expect(wrapper.text()).toContain('No results')
  })

  it('discards a stale search term when the list is reopened', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('sloven')
    expect(optionButtons(wrapper)).toHaveLength(1)

    await trigger(wrapper).trigger('click')
    await trigger(wrapper).trigger('click')

    expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('')
    expect(optionButtons(wrapper)).toHaveLength(AVAILABLE.length)
  })

  it('discards a stale search term after a selection', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('sloven')
    await optionButtons(wrapper)[0].trigger('click')
    await flushPromises()
    await trigger(wrapper).trigger('click')

    expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('')
    expect(optionButtons(wrapper)).toHaveLength(AVAILABLE.length)
  })

  it('closes on an outside click without changing the locale', async () => {
    const wrapper = mountSwitcher(true)
    await trigger(wrapper).trigger('click')
    expect(optionButtons(wrapper).length).toBeGreaterThan(0)

    document.body.dispatchEvent(new Event('click', { bubbles: true }))
    await wrapper.vm.$nextTick()

    expect(optionButtons(wrapper)).toHaveLength(0)
    expect(mockSetLocale).not.toHaveBeenCalled()
    wrapper.unmount()
  })

  it('stays open when the search box itself is clicked', async () => {
    const wrapper = mountSwitcher(true)
    await trigger(wrapper).trigger('click')

    await wrapper.find('input[type="text"]').trigger('click')

    expect(optionButtons(wrapper)).toHaveLength(AVAILABLE.length)
    wrapper.unmount()
  })

  it('stays open when a non-interactive part of the dropdown is clicked', async () => {
    const wrapper = mountSwitcher(true)
    await trigger(wrapper).trigger('click')
    await wrapper.find('input[type="text"]').setValue('sloven')

    // The padding around the search box does not stop propagation, so the document-level
    // outside-click handler runs with a target that is still inside the dropdown.
    await wrapper.find('.p-2').trigger('click')

    expect(optionButtons(wrapper)).toHaveLength(1)
    expect((wrapper.find('input[type="text"]').element as HTMLInputElement).value).toBe('sloven')
    wrapper.unmount()
  })

  it('stops listening for outside clicks once unmounted', async () => {
    const removeSpy = vi.spyOn(document, 'removeEventListener')
    const wrapper = mountSwitcher(true)
    wrapper.unmount()

    expect(removeSpy).toHaveBeenCalledWith('click', expect.any(Function))
    removeSpy.mockRestore()
  })
})
