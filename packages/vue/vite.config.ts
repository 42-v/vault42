/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import dts from 'vite-plugin-dts'
import { resolve } from 'path'

export default defineConfig({
  plugins: [
    vue(),
    dts({ insertTypesEntry: true }),
  ],
  build: {
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'Vault42Vue',
      fileName: 'vault42-vue',
    },
    rollupOptions: {
      external: ['vue'],
      output: {
        globals: {
          vue: 'Vue',
        },
      },
    },
  },
  test: {
    environment: 'happy-dom',
    globals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text-summary', 'json-summary', 'html'],
      reportsDirectory: './coverage',
      include: ['src/**/*.ts'],
      // index.ts is the barrel re-export and types.ts is type-only; neither
      // carries behaviour that a test could pin.
      exclude: ['src/index.ts', 'src/types.ts', 'src/i18n/types.ts', 'src/i18n/index.ts'],
      // The SDK ships to downstream applications, so it holds the stricter bar:
      // every statement, function and line is covered. Set at what the suite
      // actually achieves so an uncovered addition fails CI rather than eroding
      // the number quietly.
      thresholds: {
        statements: 100,
        branches: 99,
        functions: 100,
        lines: 100,
      },
    },
  },
})
