import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import { createApp, defineComponent, h, nextTick } from 'vue'
import { createI18nPlugin, I18N_KEY } from '../i18n/plugin'
import { useT } from '../i18n/composable'
import type { I18nInstance, LocaleMessages } from '../i18n/types'

const en: LocaleMessages = { 'common.signIn': 'Sign In', 'auth.welcome': 'Hello {name}' }
const de: LocaleMessages = { 'common.signIn': 'Anmelden' }

function plugin() {
  return createI18nPlugin({ locale: 'en', messages: { en, de } })
}

/** Mount a component that resolves useT() inside a plugin context. */
function mountWithPlugin(p = plugin()) {
  let i18n!: I18nInstance

  const wrapper = mount(
    defineComponent({
      setup() {
        i18n = useT()
        return () => h('span', i18n.t('common.signIn'))
      },
    }),
    { global: { plugins: [p] } },
  )

  return { wrapper, i18n, p }
}

afterEach(() => {
  vi.restoreAllMocks()
})

describe('createI18nPlugin install', () => {
  it('provides the same instance it exposes as .instance', () => {
    const p = plugin()
    const { i18n } = mountWithPlugin(p)

    expect(i18n).toBe(p.instance)
  })

  it('provides the instance under I18N_KEY', () => {
    const p = plugin()
    let injected: I18nInstance | undefined

    mount(
      defineComponent({
        inject: { i18n: { from: I18N_KEY as unknown as string, default: undefined } },
        setup() {
          return () => h('div')
        },
        created() {
          injected = (this as unknown as { i18n?: I18nInstance }).i18n
        },
      }),
      { global: { plugins: [p] } },
    )

    expect(injected).toBe(p.instance)
  })

  it('registers $t as a global property usable from a template', () => {
    const p = plugin()
    const wrapper = mount(
      { template: '<span>{{ $t("auth.welcome", { name: "Jane" }) }}</span>' },
      { global: { plugins: [p] } },
    )

    expect(wrapper.text()).toBe('Hello Jane')
  })

  it('keeps $t reactive to setLocale', async () => {
    const p = plugin()
    const wrapper = mount(
      { template: '<span>{{ $t("common.signIn") }}</span>' },
      { global: { plugins: [p] } },
    )

    expect(wrapper.text()).toBe('Sign In')
    p.instance.setLocale('de')
    await nextTick()
    expect(wrapper.text()).toBe('Anmelden')
  })

  it('keeps $t working when detached from its component', () => {
    // globalProperties.$t is a closure, not a method bound to `this`.
    const p = plugin()
    const app = createApp({ render: () => h('div') })
    app.use(p)

    const detached = app.config.globalProperties.$t
    expect(detached('common.signIn')).toBe('Sign In')
  })
})

describe('createI18nPlugin repeated installation', () => {
  it('is safe to install twice on the same app and keeps one instance', () => {
    const p = plugin()
    const app = createApp({ render: () => h('div') })

    expect(() => {
      app.use(p)
      app.use(p)
    }).not.toThrow()

    p.instance.setLocale('de')
    expect(app.config.globalProperties.$t('common.signIn')).toBe('Anmelden')
  })

  it('creates independent instances for separate createI18nPlugin calls', () => {
    const a = plugin()
    const b = plugin()

    a.instance.setLocale('de')

    expect(a.instance).not.toBe(b.instance)
    expect(a.instance.t('common.signIn')).toBe('Anmelden')
    expect(b.instance.t('common.signIn')).toBe('Sign In')
  })

  it('DEFECT: one plugin object installed on two apps shares mutable locale state', () => {
    // The instance is created in createI18nPlugin, not in install(), so two
    // apps sharing the plugin object share the locale ref: switching language
    // in one app silently switches it in the other.
    const p = plugin()
    const appA = createApp({ render: () => h('div') })
    const appB = createApp({ render: () => h('div') })
    appA.use(p)
    appB.use(p)

    // Resolve A's $t before switching locale, so the assertion below is about
    // B seeing the change and not about either app having never read it.
    expect(appA.config.globalProperties.$t).toBeTypeOf('function')
    p.instance.setLocale('de')

    expect(appB.config.globalProperties.$t('common.signIn')).toBe('Anmelden')
  })

  it('lets a second, different plugin override $t on the same app', () => {
    const p = plugin()
    const other = createI18nPlugin({ locale: 'de', messages: { en, de } })
    const app = createApp({ render: () => h('div') })

    app.use(p)
    app.use(other)

    expect(app.config.globalProperties.$t('common.signIn')).toBe('Anmelden')
  })
})

describe('useT', () => {
  it('resolves the injected instance inside a component', () => {
    const { wrapper } = mountWithPlugin()
    expect(wrapper.text()).toBe('Sign In')
  })

  it('throws a diagnostic error when the plugin was not installed', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    expect(() =>
      mount(
        defineComponent({
          setup() {
            useT()
            return () => h('div')
          },
        }),
      ),
    ).toThrow('[@vault42/vue] I18n not provided. Did you call app.use(createI18nPlugin({ ... }))?')
  })

  it('throws rather than returning undefined outside any component setup', () => {
    vi.spyOn(console, 'warn').mockImplementation(() => {})

    expect(() => useT()).toThrow('[@vault42/vue] I18n not provided')
  })
})
