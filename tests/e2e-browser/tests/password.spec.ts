import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login, logout } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Password Management', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('change password', async ({ page }) => {
    const email = uniqueEmail();
    const oldPw = testPassword();
    const newPw = 'NewSecurePassword!99';
    await registerAndVerify(page, email, oldPw);
    await deleteAllMessages();
    await login(page, email, oldPw);

    // Navigate to change password
    await page.goto('/password');
    await expect(page.getByRole('heading', { name: 'Change Password' })).toBeVisible({ timeout: 10_000 });

    // Fill change password form
    await page.locator('input[autocomplete="current-password"]').fill(oldPw);
    await page.locator('input[autocomplete="new-password"]').first().fill(newPw);
    await page.locator('input[autocomplete="new-password"]').last().fill(newPw);
    await page.locator('button:has-text("Update Password")').click();

    // Should see success message
    await expect(page.getByText('Password changed successfully')).toBeVisible({ timeout: 10_000 });

    // Logout and login with new password
    await logout(page);
    await deleteAllMessages();
    await login(page, email, newPw);

    // Should be logged in
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });

  test('forgot password flow', async ({ page }) => {
    const email = uniqueEmail();
    const oldPw = testPassword();
    const newPw = 'ResetTestPassword!77';
    await registerAndVerify(page, email, oldPw);
    await deleteAllMessages();

    // Request password reset
    await page.goto('/forgot-password');
    await expect(page.getByRole('heading', { name: 'Reset Password' })).toBeVisible({ timeout: 10_000 });

    await page.locator('#reset-email').fill(email);
    await page.locator('button:has-text("Send Reset Link")').click();

    // Should see confirmation
    await expect(page.getByText('Check Your Email')).toBeVisible({ timeout: 10_000 });

    // Get reset link from Mailpit
    const { getResetLink } = await import('./helpers/mailpit');
    const resetLink = await getResetLink(email);
    expect(resetLink).toBeTruthy();

    // Visit reset link
    await page.goto(resetLink);
    await expect(page.getByRole('heading', { name: 'Set New Password' })).toBeVisible({ timeout: 10_000 });

    // Fill new password
    await page.locator('input[autocomplete="new-password"]').first().fill(newPw);
    await page.locator('input[autocomplete="new-password"]').last().fill(newPw);
    await page.locator('button:has-text("Reset Password")').click();

    // Should see success
    await expect(page.getByText('Password Reset')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Your password has been updated')).toBeVisible();

    // Login with new password
    await page.locator('button:has-text("Sign In")').click();
    await deleteAllMessages();
    await login(page, email, newPw);

    // Should be logged in
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });
});
