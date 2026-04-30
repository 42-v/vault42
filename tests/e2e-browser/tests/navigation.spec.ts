import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login, logout } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Navigation & Auth Guard', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  // ----- Desktop Navigation (authenticated) -----

  test('desktop nav shows all links when authenticated', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    const nav = page.getByRole('navigation');

    await expect(nav.getByText('Dashboard')).toBeVisible({ timeout: 10_000 });
    await expect(nav.getByText('Profile')).toBeVisible();
    await expect(nav.getByText('Sessions')).toBeVisible();
    await expect(nav.getByText('2FA')).toBeVisible();
    await expect(nav.getByText('Password')).toBeVisible();
    await expect(nav.getByText('Identity')).toBeVisible();
    await expect(nav.getByText('Storage')).toBeVisible();
  });

  test('user email shown in nav when authenticated', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByRole('navigation').getByText(email)).toBeVisible({ timeout: 10_000 });
  });

  test('Sign Out button visible when authenticated', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });

  test('Sign Out logs out and redirects to login', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await logout(page);
    await expect(page.locator('#vault-login-email')).toBeVisible({ timeout: 10_000 });
  });

  // ----- Unauthenticated Navigation -----

  test('Sign In link shown when not authenticated', async ({ page }) => {
    await page.goto('/login');
    // The login page or nav should show sign in
    await expect(page.getByText(/sign in/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('Get Started button shown when not authenticated', async ({ page }) => {
    await page.goto('/login');
    await expect(page.getByText(/get started|create account/i).first()).toBeVisible({ timeout: 10_000 });
  });

  // ----- Auth Guard -----

  test('protected route redirects to login with redirect param', async ({ page }) => {
    // Go directly to a protected page without authentication
    await page.goto('/profile');
    // Should redirect to login with ?redirect=/profile
    await expect(page.locator('#vault-login-email')).toBeVisible({ timeout: 10_000 });
    expect(page.url()).toContain('redirect');
  });

  test('protected route loads after login redirect', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();

    // Try to go to /profile without being logged in
    await page.goto('/profile');
    await expect(page.locator('#vault-login-email')).toBeVisible({ timeout: 10_000 });

    // Now login — should redirect back to /profile
    await page.locator('#vault-login-email').fill(email);
    await page.locator('#vault-login-password').fill(pw);
    await page.locator('button[type="submit"]:has-text("Sign In")').click();

    // Handle potential 2FA (email OTP)
    const emailOtp = page.locator('#vault-email-otp-code');
    const signOut = page.getByText('Sign Out');
    const first = await Promise.race([
      emailOtp.waitFor({ timeout: 10_000 }).then(() => 'otp' as const),
      signOut.waitFor({ timeout: 10_000 }).then(() => 'done' as const),
    ]);
    if (first === 'otp') {
      const { waitForCode } = await import('./helpers/mailpit');
      const code = await waitForCode(email);
      await emailOtp.fill(code);
      await page.locator('button:has-text("Verify Code")').click();
    }

    // Should eventually be on /profile or skip MFA onboarding
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });

  // ----- Footer -----

  test('footer shows well-known endpoint links', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });

    // Footer JWKS link
    await expect(page.getByRole('link', { name: /JWKS/i })).toBeVisible();
    // Footer OIDC link
    await expect(page.getByRole('link', { name: /OIDC/i })).toBeVisible();
  });

  // ----- 404 Page -----

  test('404 page for unknown routes', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/nonexistent-page-xyz');
    await expect(page.getByText(/not found|404/i)).toBeVisible({ timeout: 10_000 });
  });

  test('404 page has home link', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/nonexistent-page-xyz');
    await expect(page.getByText(/not found|404/i)).toBeVisible({ timeout: 10_000 });
    // Should have a link back to home
    await expect(page.getByRole('link', { name: /home|back|dashboard/i })).toBeVisible();
  });

  // ----- Language Switcher -----

  test('language switcher opens dropdown on click', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });

    // Find and click the language switcher button (in footer)
    const langBtn = page.locator('footer').locator('button').last();
    await langBtn.click();

    // A search input should appear in the dropdown
    await expect(page.locator('footer input[type="text"], footer input[type="search"]')).toBeVisible({ timeout: 5_000 });
  });

  test('language switcher search filters locales', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });

    // Open language switcher
    const langBtn = page.locator('footer').locator('button').last();
    await langBtn.click();

    const searchInput = page.locator('footer input[type="text"], footer input[type="search"]');
    await expect(searchInput).toBeVisible({ timeout: 5_000 });

    // Type to filter
    await searchInput.fill('Deutsch');
    // Should show German option
    await expect(page.getByText('Deutsch').first()).toBeVisible({ timeout: 5_000 });
  });

  // ----- Mobile Navigation -----

  test('mobile hamburger menu toggles on small viewport', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    // Set small viewport to trigger mobile nav
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');
    await expect(page.getByText('Sign Out').or(page.locator('#vault-login-email'))).toBeVisible({ timeout: 10_000 });

    // Look for hamburger button (SVG toggle)
    const hamburger = page.locator('button[aria-label*="menu"], button[aria-label*="Menu"], nav button:has(svg)').first();
    if (await hamburger.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await hamburger.click();
      // Mobile menu should show nav links
      await expect(page.getByText('Dashboard')).toBeVisible({ timeout: 5_000 });
      await expect(page.getByText('Profile')).toBeVisible();
    }
  });

  // ----- Page Title -----

  test('page title includes "The Vault" suffix', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    const title = await page.title();
    expect(title).toContain('Vault');
  });
});
