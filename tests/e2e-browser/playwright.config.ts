import { defineConfig } from '@playwright/test';

// Skip TLS verification for local dev certs (Mailpit API calls from Node)
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

export default defineConfig({
  testDir: './tests',
  globalSetup: './global-setup.ts',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: 0,
  workers: 1,
  reporter: 'list',
  timeout: 30_000,

  use: {
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },

  projects: [
    {
      name: 'vault',
      use: {
        browserName: 'chromium',
        baseURL: process.env.VAULT_URL || 'https://vault.localhost',
      },
      testIgnore: '**/admin-*.spec.ts',
    },
    {
      name: 'admin',
      use: {
        browserName: 'chromium',
        baseURL: process.env.ADMIN_URL || 'https://admin.localhost',
      },
      testMatch: '**/admin-*.spec.ts',
    },
  ],
});
