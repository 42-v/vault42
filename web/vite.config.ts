/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    sourcemap: false,
  },
  server: {
    port: 5173,
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'json-summary', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.{ts,vue}'],
      // Entry point and ambient declarations carry no testable logic; locale JSON
      // is data. Everything else that ships to a browser is measured.
      exclude: ['src/main.ts', 'src/env.d.ts', 'src/locales/**'],
      // Set just under what the suite actually achieves (99.52 / 98.93 / 100 /
      // 99.86), so an uncovered new branch fails CI rather than quietly eroding
      // the number.
      thresholds: {
        statements: 99,
        branches: 98,
        functions: 100,
        lines: 99,
      },
    },
  },
})
