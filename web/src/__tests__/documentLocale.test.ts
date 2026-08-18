import { describe, it, expect, beforeEach } from 'vitest'
import { applyDocumentLocale, isRTL } from '../i18n'
import { messages } from '../i18n'

describe('isRTL', () => {
  it('recognises the right-to-left languages that ship a catalogue', () => {
    expect(isRTL('ar')).toBe(true)
    expect(isRTL('he')).toBe(true)
  })

  it('matches on the primary subtag, not the whole tag', () => {
    expect(isRTL('ar-EG')).toBe(true)
    expect(isRTL('AR')).toBe(true)
    expect(isRTL('he-IL')).toBe(true)
  })

  it('leaves left-to-right locales alone, including the multi-part ones', () => {
    for (const locale of ['en', 'sk', 'zh-Hans', 'zh-Hant', 'hi', 'th']) {
      expect(isRTL(locale), locale).toBe(false)
    }
  })

  it('classifies every shipped locale without throwing', () => {
    const rtl = Object.keys(messages).filter(isRTL).sort()
    expect(rtl).toEqual(['ar', 'he'])
  })
})

describe('applyDocumentLocale', () => {
  beforeEach(() => {
    document.documentElement.lang = 'en'
    document.documentElement.dir = 'ltr'
  })

  it('publishes the active locale on the root element', () => {
    applyDocumentLocale('sk')
    expect(document.documentElement.lang).toBe('sk')
    expect(document.documentElement.dir).toBe('ltr')
  })

  it('flips direction for a right-to-left locale', () => {
    applyDocumentLocale('ar')
    expect(document.documentElement.lang).toBe('ar')
    expect(document.documentElement.dir).toBe('rtl')
  })

  it('flips back when leaving a right-to-left locale', () => {
    applyDocumentLocale('he')
    expect(document.documentElement.dir).toBe('rtl')

    applyDocumentLocale('de')
    expect(document.documentElement.lang).toBe('de')
    expect(document.documentElement.dir).toBe('ltr')
  })

  it('keeps the script subtag, which a screen reader needs to pick a voice', () => {
    applyDocumentLocale('zh-Hant')
    expect(document.documentElement.lang).toBe('zh-Hant')
  })

  it('accepts an explicit root, so it is testable off the live document', () => {
    const el = document.createElement('html')
    applyDocumentLocale('ar', el)

    expect(el.lang).toBe('ar')
    expect(el.dir).toBe('rtl')
    expect(document.documentElement.lang).toBe('en')
  })
})
