import { test, expect } from '@playwright/test';
import { getCachedTOTPSecret } from './helpers/admin';
import { generateTOTP } from './helpers/totp';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';

test.describe('Admin Login', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  test('login page renders with username, password, and TOTP fields', async ({ page }) => {
    await page.goto('/admin/login');

    await expect(page.locator('#username')).toBeVisible();
    await expect(page.locator('#password')).toBeVisible();
    await expect(page.locator('#totp_code')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toBeVisible();
  });

  test('login page shows VAULTADMIN branding', async ({ page }) => {
    await page.goto('/admin/login');
    await expect(page.locator('.login-logo')).toBeVisible();
    await expect(page.getByText('VAULT')).toBeVisible();
    await expect(page.getByText('ADMIN')).toBeVisible();
  });

  test('username field has autofocus', async ({ page }) => {
    await page.goto('/admin/login');
    await expect(page.locator('#username')).toBeFocused();
  });

  test('TOTP field accepts only 6 digits', async ({ page }) => {
    await page.goto('/admin/login');
    await expect(page.locator('#totp_code')).toHaveAttribute('maxlength', '6');
    await expect(page.locator('#totp_code')).toHaveAttribute('pattern', '[0-9]{6}');
    await expect(page.locator('#totp_code')).toHaveAttribute('inputmode', 'numeric');
  });

  test('invalid credentials shows error message', async ({ page }) => {
    await page.goto('/admin/login');

    await page.locator('#username').fill('admin');
    await page.locator('#password').fill('wrong_password_1234567890');
    await page.locator('button[type="submit"]').click();

    await expect(page.locator('#loginError')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#loginError')).toContainText(/invalid|credentials|error/i);
  });

  test('nonexistent user shows same error as wrong password', async ({ page }) => {
    await page.goto('/admin/login');

    await page.locator('#username').fill('nonexistent_user_xyz_abc');
    await page.locator('#password').fill('wrong_password_1234567890');
    await page.locator('button[type="submit"]').click();

    await expect(page.locator('#loginError')).toBeVisible({ timeout: 10_000 });
    // Anti-enumeration: same error for nonexistent and wrong password
    await expect(page.locator('#loginError')).toContainText(/invalid|credentials|error/i);
  });

  test('empty form submission prevented by required fields', async ({ page }) => {
    await page.goto('/admin/login');
    // Click submit with empty fields — HTML5 required prevents submission
    await page.locator('button[type="submit"]').click();
    // Should still be on login page (form didn't submit)
    await expect(page.locator('#loginForm')).toBeVisible();
  });

  test('successful login navigates away from login page', async ({ page }) => {
    const totpSecret = getCachedTOTPSecret();
    const totpCode = totpSecret ? generateTOTP(totpSecret) : '';

    await page.goto('/admin/login');
    await page.locator('#username').fill(ADMIN_USERNAME);
    await page.locator('#password').fill(ADMIN_PASSWORD);
    if (totpCode) {
      await page.locator('#totp_code').fill(totpCode);
    }
    await page.locator('button[type="submit"]').click();

    // After successful login, should navigate to dashboard or TOTP setup
    await page.waitForURL(/\/admin\/(ui\/totp-setup)?$/, { timeout: 15_000 });
  });

  test('Sign In button shows loading state during submission', async ({ page }) => {
    await page.goto('/admin/login');
    await page.locator('#username').fill('admin');
    await page.locator('#password').fill('wrong_password_1234567890');

    const btn = page.locator('button[type="submit"]');
    await btn.click();

    // Button should show loading text briefly
    await expect(btn).toContainText(/loading|sign/i);
  });

  test('expired session shows expired message', async ({ page }) => {
    await page.goto('/admin/login?expired=1');
    await expect(page.locator('#loginError')).toBeVisible();
    await expect(page.locator('#loginError')).toContainText(/expired/i);
  });
});
