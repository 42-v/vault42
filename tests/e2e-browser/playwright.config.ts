import { defineConfig } from '@playwright/test';

const VAULT_URL = process.env.VAULT_URL || 'https://vault.localhost';
const ADMIN_URL = process.env.ADMIN_URL || 'https://admin.localhost';
const MAILPIT_URL = process.env.MAILPIT_URL || 'http://mail.localhost';

// A local dev deployment serves a self-signed certificate, so neither Node's
// fetch (global-setup's /healthz probe, the Mailpit API client) nor Chromium
// will talk to it with verification on.
//
// NODE_TLS_REJECT_UNAUTHORIZED has no host scope: it is one switch for the
// whole process. Setting it unconditionally meant that pointing VAULT_URL at a
// real deployment -- a staging environment, or production during a smoke test
// -- ran the entire suite with certificate validation off and printed nothing
// to say so. So it is set only when every configured target is a local host,
// and left alone otherwise: against anything else the suite verifies
// certificates like any other client and fails on a bad one.
const isLocalTarget = (raw: string): boolean => {
  let host: string;
  try {
    host = new URL(raw).hostname;
  } catch {
    return false;
  }
  return (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host === '127.0.0.1' ||
    host === '::1' ||
    host === '[::1]'
  );
};

const allTargetsAreLocal = [VAULT_URL, ADMIN_URL, MAILPIT_URL].every(isLocalTarget);

if (allTargetsAreLocal) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
} else {
  console.warn('[e2e-browser] a configured target is not a local host; TLS verification stays on.');
}

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
    // Browser-side counterpart of the switch above, scoped the same way.
    ignoreHTTPSErrors: allTargetsAreLocal,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },

  projects: [
    {
      name: 'vault',
      use: {
        browserName: 'chromium',
        baseURL: VAULT_URL,
      },
      testIgnore: '**/admin-*.spec.ts',
    },
    {
      name: 'admin',
      use: {
        browserName: 'chromium',
        baseURL: ADMIN_URL,
      },
      testMatch: '**/admin-*.spec.ts',
    },
  ],
});
