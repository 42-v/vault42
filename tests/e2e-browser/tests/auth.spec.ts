import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, register, registerAndVerify, login, logout } from './helpers/auth';
import { deleteAllMessages, waitForCode } from './helpers/mailpit';

test.describe('Authentication', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('register new user', async ({ page }) => {
    const email = uniqueEmail();
    await register(page, email, testPassword());

    // Should see success message
    await expect(page.getByText('Account Created')).toBeVisible();
    await expect(page.getByText('Check your email')).toBeVisible();
  });

  test('login with valid credentials', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();

    await login(page, email, pw);

    // Should be logged in — nav bar shows Sign Out and email
    await expect(page.getByText('Sign Out')).toBeVisible();
    await expect(page.getByRole('navigation').getByText(email)).toBeVisible();
  });

  test('login with wrong password shows error', async ({ page }) => {
    const email = uniqueEmail();
    await registerAndVerify(page, email, testPassword());

    await page.goto('/login');
    await page.locator('#vault-login-email').fill(email);
    await page.locator('#vault-login-password').fill('wrongpassword12345');
    await page.locator('button[type="submit"]:has-text("Sign In")').click();

    await expect(page.getByText('Invalid email or password')).toBeVisible({ timeout: 10_000 });
  });

  test('login with email OTP', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();

    await page.goto('/login');
    await page.locator('#vault-login-email').fill(email);
    await page.locator('#vault-login-password').fill(pw);
    await page.locator('button[type="submit"]:has-text("Sign In")').click();

    // Should see email OTP form (not TOTP)
    await expect(page.locator('#vault-email-otp-code')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Email Verification Code')).toBeVisible();

    // The TOTP form label should NOT be visible
    await expect(page.getByText('Authentication Code')).not.toBeVisible();

    // Get OTP from Mailpit
    const code = await waitForCode(email);
    await page.locator('#vault-email-otp-code').fill(code);
    await page.locator('button:has-text("Verify Code")').click();

    // Should be logged in (may land on MFA onboarding or home)
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });

  test('logout redirects to login', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await logout(page);

    // Should be on login page
    await expect(page.locator('#vault-login-email')).toBeVisible();
  });
});
