/// <reference types="vitest/config" />
import { defineConfig, type Plugin } from 'vite'
import vue from '@vitejs/plugin-vue'

// Origins that only ever mean "somebody's development machine". A production
// bundle carrying one of these is a mis-built release, not a configuration
// choice: the dashboard is served by the Go binary from the same origin as the
// API, so the shipped bundle needs no absolute origin at all.
const DEV_ONLY_ORIGINS = ['vault.localhost', 'localhost:5173', '127.0.0.1:5173']

/**
 * Fails a production build whose output contains a development origin.
 *
 * Vite loads a plain `.env` in every mode, so `web/.env` used to bake
 * `https://vault.localhost` into `web/dist`. `scripts/build-all.sh` copies that
 * directory into `internal/frontend/dist`, `go:embed` compiles it into the
 * binary, and all three images inherit it — a local build shipping a dashboard
 * that pointed every API call at a developer's hostname. CI never caught it
 * because CI builds from a fresh checkout where `.env` does not exist.
 *
 * `web/src/config.ts` stops `main.ts` honouring the override in a production
 * bundle. This is the second line: it reads the emitted chunks back and refuses
 * to write a release that contains the string by any route.
 */
function forbidDevOrigins(): Plugin {
  let isProduction = false

  return {
    name: 'vault42-forbid-dev-origins',
    apply: 'build',
    enforce: 'post',

    configResolved(config) {
      isProduction = config.isProduction
    },

    generateBundle(_options, bundle) {
      if (!isProduction) return

      for (const [fileName, output] of Object.entries(bundle)) {
        const text =
          output.type === 'chunk'
            ? output.code
            : typeof output.source === 'string'
              ? output.source
              : ''

        for (const origin of DEV_ONLY_ORIGINS) {
          if (text.includes(origin)) {
            this.error(
              `${fileName} contains the development origin "${origin}". A release bundle ` +
                'must resolve the API from window.location.origin. Look for a stale ' +
                'web/.env (the dev value belongs in web/.env.development) or a ' +
                'VITE_VAULT_URL in the build environment.',
            )
          }
        }
      }
    },
  }
}

export default defineConfig({
  plugins: [vue(), forbidDevOrigins()],
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
