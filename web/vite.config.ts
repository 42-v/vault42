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
  },
})
