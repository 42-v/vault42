<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useT } from '@vault42/vue'
import { applyDocumentLocale, loadLocale } from '../i18n'

const { locale, setLocale, availableLocales } = useT()

const localeNames: Record<string, string> = {
  en: 'English',
  sk: 'Slovencina',
  hu: 'Magyar',
  de: 'Deutsch',
  fr: 'Francais',
  es: 'Espanol',
  pt: 'Portugues',
  it: 'Italiano',
  nl: 'Nederlands',
  pl: 'Polski',
  cs: 'Cestina',
  ro: 'Romana',
  bg: 'Bulgarski',
  hr: 'Hrvatski',
  sr: 'Srpski',
  sl: 'Slovenscina',
  uk: 'Ukrainska',
  ru: 'Russkij',
  tr: 'Turkce',
  el: 'Ellinika',
  ar: 'Arabiyya',
  he: 'Ivrit',
  ja: 'Nihongo',
  ko: 'Hangugeo',
  'zh-Hans': 'Zhongwen (Jian)',
  'zh-Hant': 'Zhongwen (Fan)',
  hi: 'Hindi',
  th: 'Phaasaathai',
  vi: 'Tieng Viet',
  id: 'Bahasa Indonesia',
  ms: 'Bahasa Melayu',
  fi: 'Suomi',
  sv: 'Svenska',
  da: 'Dansk',
  no: 'Norsk',
  et: 'Eesti',
  lv: 'Latviesu',
  lt: 'Lietuviu',
}

const open = ref(false)
const search = ref('')
const dropdownRef = ref<HTMLElement | null>(null)
const triggerRef = ref<HTMLButtonElement | null>(null)

// The id the trigger points `aria-controls` at. A constant rather than a
// generated one: there is a single language switcher on the page, and a stable
// id is what lets the test assert the relationship rather than assert that two
// generated strings happen to match.
const MENU_ID = 'language-switcher-menu'

// This is a disclosure, and deliberately not a menu or a listbox.
//
// `aria-haspopup` was the obvious thing to add and it would have been wrong.
// Its values promise a specific shape -- menu, listbox, tree, grid, dialog --
// and what opens here is a container holding a text filter and forty buttons.
// It is none of those, and a listbox may not contain a textbox at all. Claiming
// one changes how a screen reader announces the control and what keys the user
// is then entitled to expect from it.
//
// `aria-expanded` plus `aria-controls` is the whole disclosure pattern, and it
// is what this actually is: a button that shows and hides a region.

const currentName = computed(() => localeNames[locale.value] || locale.value)

const filtered = computed(() => {
  const q = search.value.toLowerCase()
  if (!q) return availableLocales
  return availableLocales.filter((loc: string) => {
    const name = (localeNames[loc] || loc).toLowerCase()
    return name.includes(q) || loc.toLowerCase().includes(q)
  })
})

async function select(loc: string) {
  close()

  // Catalogues are fetched one chunk at a time, so the copy has to be in hand
  // before the locale ref flips; switching first would render bare keys until a
  // later re-render happened to pick the catalogue up. A chunk that fails to
  // load leaves the current language in place rather than switching to one that
  // would render nothing but keys.
  if (!(await loadLocale(loc).catch(() => false))) return

  setLocale(loc)
  applyDocumentLocale(loc)
  localStorage.setItem('vault42-locale', loc)
}

function toggle() {
  open.value = !open.value
  if (!open.value) search.value = ''
}

/**
 * Closes the list and puts focus back on the trigger.
 *
 * The focus half is the part that was missing rather than merely absent. The
 * popup is removed from the DOM by `v-if`, so whatever was focused inside it --
 * the filter box, or one of the forty locale buttons -- goes with it, and the
 * browser drops focus to `<body>`. A keyboard user is then at the top of the
 * document with no announcement, which is the same defect useModalFocus was
 * written for on the three dialogs.
 *
 * It is deliberately not called from the click-outside handler: clicking
 * somewhere else is the user moving focus on purpose, and dragging it back to
 * the trigger would fight them.
 */
function close() {
  if (!open.value) return
  open.value = false
  search.value = ''
  triggerRef.value?.focus()
}

function onClickOutside(e: MouseEvent) {
  if (dropdownRef.value && !dropdownRef.value.contains(e.target as Node)) {
    open.value = false
    search.value = ''
  }
}

onMounted(() => document.addEventListener('click', onClickOutside))
onUnmounted(() => document.removeEventListener('click', onClickOutside))
</script>

<template>
  <div ref="dropdownRef" class="relative" @keydown.escape="close">
    <button
      ref="triggerRef"
      class="text-xs text-vault42-muted hover:text-vault42-text transition-colors flex items-center gap-1"
      type="button"
      :aria-expanded="open"
      :aria-controls="MENU_ID"
      @click.stop="toggle"
    >
      {{ currentName }}
      <svg class="w-3 h-3" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
      </svg>
    </button>

    <div
      v-if="open"
      :id="MENU_ID"
      class="absolute bottom-full mb-2 right-0 w-52 bg-vault42-surface border border-vault42-border rounded-lg shadow-lg overflow-hidden z-50"
    >
      <div class="p-2">
        <input
          v-model="search"
          type="text"
          class="w-full bg-vault42-bg border border-vault42-control rounded-sm px-2 py-1.5 text-xs text-vault42-text placeholder-vault42-muted outline-hidden focus:border-vault42-accent transition-colors"
          placeholder="Search..."
          autofocus
          @click.stop
        />
      </div>
      <div class="max-h-48 overflow-y-auto">
        <button
          v-for="loc in filtered"
          :key="loc"
          :class="[
            'w-full text-left px-3 py-1.5 text-xs transition-colors',
            loc === locale
              ? 'bg-vault42-primary/15 text-vault42-accent font-medium'
              : 'text-vault42-text hover:bg-vault42-border/50'
          ]"
          @click.stop="select(loc)"
        >
          {{ localeNames[loc] || loc }}
          <span class="text-vault42-muted ml-1">{{ loc.toUpperCase() }}</span>
        </button>
        <div v-if="filtered.length === 0" class="px-3 py-2 text-xs text-vault42-muted">
          No results
        </div>
      </div>
    </div>
  </div>
</template>
