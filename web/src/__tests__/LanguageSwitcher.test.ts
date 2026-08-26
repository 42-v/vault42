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

  /**
   * The disclosure contract, and the keyboard.
   *
   * The trigger opened a panel and said nothing about it: no `aria-expanded`,
   * so a screen reader announced the same thing whether the list was open or
   * shut, and no `aria-controls`, so nothing tied the button to the region it
   * governs. Escape did nothing at all -- the only way to dismiss it was a
   * mouse click somewhere else -- and because `v-if` removes the panel, closing
   * it dropped focus to `<body>`, which puts a keyboard user back at the top of
   * the document with no announcement.
   *
   * Naming the filter box is still out of scope and still blocked: it needs a
   * new string in thirty-eight locales (#297). None of what is asserted here
   * needs one.
   */
  it('tells assistive technology whether the list is open', async () => {
    const wrapper = mountSwitcher()
    expect(trigger(wrapper).attributes('aria-expanded')).toBe('false')

    await trigger(wrapper).trigger('click')
    expect(trigger(wrapper).attributes('aria-expanded')).toBe('true')

    await trigger(wrapper).trigger('click')
    expect(trigger(wrapper).attributes('aria-expanded')).toBe('false')
  })

  it('points the trigger at the region it controls', async () => {
    const wrapper = mountSwitcher()
    await trigger(wrapper).trigger('click')

    const controls = trigger(wrapper).attributes('aria-controls')
    expect(controls).toBeTruthy()
    // The relationship, not merely the presence of two attributes: an
    // aria-controls naming an element that is not there is worse than none.
    expect(wrapper.find(`#${controls}`).exists()).toBe(true)
  })

  it('does not claim to be a menu or a listbox', () => {
    // A listbox may not contain a textbox, and this panel holds the filter
    // field. Promising either shape changes what keys a screen-reader user is
    // told to expect, so the disclosure pattern is the honest one.
    const wrapper = mountSwitcher()
    expect(trigger(wrapper).attributes('aria-haspopup')).toBeUndefined()
  })

  it('closes on Escape and puts focus back on the trigger', async () => {
    const wrapper = mountSwitcher(true)
    await trigger(wrapper).trigger('click')
    expect(optionButtons(wrapper).length).toBeGreaterThan(0)

    await wrapper.find('input').trigger('keydown', { key: 'Escape' })

    expect(optionButtons(wrapper).length).toBe(0)
    expect(document.activeElement).toBe(trigger(wrapper).element)
    wrapper.unmount()
  })

  it('puts focus back on the trigger after a selection', async () => {
    // The chosen button is removed with the panel, so without this the browser
    // drops focus to <body> at the exact moment the user has committed to an
    // action -- the worst time to lose your place.
    const wrapper = mountSwitcher(true)
    await trigger(wrapper).trigger('click')
    await pick(wrapper, 'Slovencina')

    expect(document.activeElement).toBe(trigger(wrapper).element)
    wrapper.unmount()
  })

  it('ignores Escape when the list is already closed', async () => {
    // Without the guard in `close`, Escape anywhere in this component would
    // yank focus to the trigger even with nothing open -- a control stealing
    // focus from wherever the user actually was, on a key that means "get out
    // of my way".
    const wrapper = mountSwitcher(true)
    const elsewhere = document.createElement('button')
    document.body.appendChild(elsewhere)
    elsewhere.focus()

    await trigger(wrapper).trigger('keydown', { key: 'Escape' })

    expect(document.activeElement).toBe(elsewhere)
    elsewhere.remove()
    wrapper.unmount()
  })

  it('leaves focus alone when the list is dismissed by clicking elsewhere', async () => {
    // Clicking outside is the user moving focus deliberately. Dragging it back
    // to the trigger would fight them, so the restore is scoped to the two
    // paths that destroy the focused element.
    const wrapper = mountSwitcher(true)
    const outside = document.createElement('button')
    document.body.appendChild(outside)

    await trigger(wrapper).trigger('click')
    outside.focus()
    document.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await wrapper.vm.$nextTick()

    expect(optionButtons(wrapper).length).toBe(0)
    expect(document.activeElement).toBe(outside)
    outside.remove()
    wrapper.unmount()
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
