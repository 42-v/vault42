<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useT } from '@vault42/vue'
import { applyDocumentLocale } from '../i18n'

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

const currentName = computed(() => localeNames[locale.value] || locale.value)

const filtered = computed(() => {
  const q = search.value.toLowerCase()
  if (!q) return availableLocales
  return availableLocales.filter((loc: string) => {
    const name = (localeNames[loc] || loc).toLowerCase()
    return name.includes(q) || loc.toLowerCase().includes(q)
  })
})

function select(loc: string) {
  setLocale(loc)
  applyDocumentLocale(loc)
  localStorage.setItem('vault42-locale', loc)
  open.value = false
  search.value = ''
}

function toggle() {
  open.value = !open.value
  if (!open.value) search.value = ''
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
  <div ref="dropdownRef" class="relative">
    <button
      class="text-xs text-vault42-muted hover:text-vault42-text transition-colors flex items-center gap-1"
      type="button"
      @click.stop="toggle"
    >
      {{ currentName }}
      <svg class="w-3 h-3" :class="{ 'rotate-180': open }" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
      </svg>
    </button>

    <div
      v-if="open"
      class="absolute bottom-full mb-2 right-0 w-52 bg-vault42-surface border border-vault42-border rounded-lg shadow-lg overflow-hidden z-50"
    >
      <div class="p-2">
        <input
          v-model="search"
          type="text"
          class="w-full bg-vault42-bg border border-vault42-border rounded px-2 py-1.5 text-xs text-vault42-text placeholder-vault42-muted outline-none focus:border-vault42-primary transition-colors"
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
              ? 'bg-vault42-primary/15 text-vault42-primary font-medium'
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
