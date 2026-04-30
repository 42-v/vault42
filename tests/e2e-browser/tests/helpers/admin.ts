/**
 * Admin gateway authentication helpers for Playwright E2E tests.
 *
 * Required env vars:
 *   ADMIN_FIRST_PASSWORD — first-boot super_admin password (from pod logs)
 *
 * Optional env vars:
 *   ADMIN_URL            — gateway URL (default: https://admin.localhost)
 *   ADMIN_USERNAME       — admin username (default: admin)
 */

import type { Page, APIRequestContext } from '@playwright/test';
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { generateTOTP } from './totp';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const ADMIN_URL = process.env.ADMIN_URL || 'https://admin.localhost';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

const SECRET_FILE = join(__dirname, '../../test-results/.admin-totp-secret');

interface LoginResponse {
  token?: string;
  error?: string;
  requires_2fa?: boolean;
  admin?: {
    id: string;
    username: string;
    role: string;
    totp_configured: boolean;
  };
}

interface TOTPSetupResponse {
  secret: string;
  otpauth_uri: string;
}

/**
 * Read cached TOTP secret from file (persists between test runs).
 */
export function getCachedTOTPSecret(): string | null {
  try {
    if (existsSync(SECRET_FILE)) {
      return readFileSync(SECRET_FILE, 'utf-8').trim();
    }
  } catch { /* ignore */ }
  return null;
}

/**
 * Save TOTP secret to cache file.
 */
function cacheTOTPSecret(secret: string): void {
  try {
    const dir = dirname(SECRET_FILE);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(SECRET_FILE, secret, 'utf-8');
  } catch { /* ignore */ }
}

/**
 * Login to the admin gateway via API. Handles TOTP if configured.
 * Returns the session token.
 */
export async function getAdminToken(request: APIRequestContext): Promise<string> {
  if (!ADMIN_PASSWORD) {
    throw new Error('ADMIN_FIRST_PASSWORD env var is required for admin tests');
  }

  const totpSecret = getCachedTOTPSecret();
  const totpCode = totpSecret ? generateTOTP(totpSecret) : '';

  const resp = await request.post(`${ADMIN_URL}/admin/auth/login`, {
    data: {
      username: ADMIN_USERNAME,
      password: ADMIN_PASSWORD,
      totp_code: totpCode,
    },
    headers: { 'Content-Type': 'application/json' },
  });

  const data: LoginResponse = await resp.json();

  if (data.error) {
    throw new Error(`Admin login failed: ${data.error}`);
  }

  if (!data.token) {
    throw new Error('Admin login response missing token');
  }

  // If 2FA setup required (first boot), complete TOTP enrollment
  if (data.requires_2fa) {
    const secret = await setupTOTP(request, data.token);
    cacheTOTPSecret(secret);
  }

  return data.token;
}

/**
 * Set up TOTP for the admin account (first boot flow).
 * Returns the TOTP secret.
 */
async function setupTOTP(request: APIRequestContext, token: string): Promise<string> {
  // Step 1: Generate secret
  const setupResp = await request.post(`${ADMIN_URL}/admin/admins/me/totp/setup`, {
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  const setup: TOTPSetupResponse = await setupResp.json();
  if (!setup.secret) throw new Error('TOTP setup returned no secret');

  // Step 2: Generate code and verify
  const code = generateTOTP(setup.secret);
  const verifyResp = await request.post(`${ADMIN_URL}/admin/admins/me/totp/verify`, {
    data: { code },
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  const verifyData = await verifyResp.json();
  if (verifyData.error) throw new Error(`TOTP verify failed: ${verifyData.error}`);

  return setup.secret;
}

/**
 * Authenticate the Playwright page for admin gateway access.
 * Sets both the Authorization header (for server-rendered pages behind SessionAuth)
 * and sessionStorage token (for client-side JS API calls).
 */
export async function authenticateAdminPage(page: Page, token: string): Promise<void> {
  // Set Authorization header so the server accepts page navigation requests
  await page.setExtraHTTPHeaders({ 'Authorization': `Bearer ${token}` });
  // Navigate to login page (public) to establish origin for sessionStorage
  await page.goto('/admin/login');
  // Set sessionStorage so admin.js can make API calls
  await page.evaluate((t) => sessionStorage.setItem('admin_token', t), token);
}

/**
 * Navigate to an admin page (assumes authenticateAdminPage was already called).
 */
export async function gotoAdminPage(page: Page, path: string): Promise<void> {
  await page.goto(path);
  await page.waitForLoadState('networkidle');
}
