import type { Page } from '@playwright/test';
import { expect } from '@playwright/test';
import { waitForCode, deleteAllMessages, getVerifyLink } from './mailpit';

let counter = 0;

/**
 * Generate a unique test email address. Mailpit catches all mail so any
 * domain works.
 */
export function uniqueEmail(): string {
  counter++;
  return `e2e-${Date.now()}-${counter}@test.vault`;
}

/**
 * Generate a password that meets the 15-char minimum.
 */
export function testPassword(): string {
  return 'E2eTestPassword!42';
}

/**
 * Register a new user via the UI. Does NOT verify email.
 */
export async function register(page: Page, email: string, password: string, name = 'E2E User'): Promise<void> {
  await page.goto('/register');
  await page.locator('#vault-reg-name').fill(name);
  await page.locator('#vault-reg-email').fill(email);
  await page.locator('#vault-reg-password').fill(password);
  await page.locator('#vault-reg-confirm').fill(password);
  await page.locator('button[type="submit"]:has-text("Create Account")').click();

  // Wait for success message
  await expect(page.getByText('Account Created')).toBeVisible({ timeout: 10_000 });
}

/**
 * Register a new user and verify their email via Mailpit link.
 */
export async function registerAndVerify(page: Page, email: string, password: string, name = 'E2E User'): Promise<void> {
  await deleteAllMessages();
  await register(page, email, password, name);

  // Extract verification link from email and visit it
  const verifyLink = await getVerifyLink(email);
  await page.goto(verifyLink);
  await expect(page.getByRole('heading', { name: 'Email Verified' })).toBeVisible({ timeout: 10_000 });
}

/**
 * After login/OTP, the user may land on MFA onboarding ("Secure Your Account").
 * Skip it if it appears.
 */
async function skipMfaOnboarding(page: Page): Promise<void> {
  const skipLink = page.getByText('Skip for now');
  const isOnboarding = await skipLink.isVisible({ timeout: 3_000 }).catch(() => false);
  if (isOnboarding) {
    await skipLink.click();
    // Should redirect to dashboard/home
    await page.waitForURL(/\/$/, { timeout: 10_000 });
  }
}

/**
 * Wait for the user to be fully logged in — either on a known authenticated page
 * or on the MFA onboarding page (which we skip).
 */
async function waitForLoggedIn(page: Page): Promise<void> {
  // After login, we may land on: home (/), profile (/profile), MFA onboarding (/mfa-onboarding)
  // All share the nav bar with "Sign Out"
  await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  await skipMfaOnboarding(page);
}

/**
 * Login via the UI. Handles email OTP if triggered (no TOTP setup).
 * Skips MFA onboarding if presented. Returns when fully logged in.
 */
export async function login(page: Page, email: string, password: string): Promise<void> {
  await page.goto('/login');
  await page.locator('#vault-login-email').fill(email);
  await page.locator('#vault-login-password').fill(password);
  await page.locator('button[type="submit"]:has-text("Sign In")').click();

  // After credentials, we might get 2FA challenge or direct login.
  const emailOtp = page.locator('#vault-email-otp-code');
  const totpCode = page.locator('#vault-totp-code');
  const signOut = page.getByText('Sign Out');

  const first = await Promise.race([
    emailOtp.waitFor({ timeout: 10_000 }).then(() => 'email_otp' as const),
    totpCode.waitFor({ timeout: 10_000 }).then(() => 'totp' as const),
    signOut.waitFor({ timeout: 10_000 }).then(() => 'logged_in' as const),
  ]);

  if (first === 'email_otp') {
    // Get code from Mailpit and enter it
    const code = await waitForCode(email);
    await emailOtp.fill(code);
    await page.locator('button:has-text("Verify Code")').click();
    await waitForLoggedIn(page);
  } else if (first === 'totp') {
    // TOTP needs to be handled by the caller
    throw new Error('TOTP challenge appeared — use loginWithTOTP helper instead');
  } else {
    // Direct login (no 2FA required in dev profile)
    await skipMfaOnboarding(page);
  }
}

/**
 * Logout via the "Sign Out" button in the nav bar.
 */
export async function logout(page: Page): Promise<void> {
  await page.getByText('Sign Out').click();
  // Should redirect to login
  await expect(page.locator('#vault-login-email')).toBeVisible({ timeout: 10_000 });
}
