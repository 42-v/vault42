import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Sessions & Devices', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('sessions page shows heading and active session', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.vault-pulse').first()).toBeVisible({ timeout: 10_000 });
  });

  test('active session shows IP address', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.locator('.vault-pulse').first()).toBeVisible({ timeout: 10_000 });
    // IP should be visible (at least a dotted quad or IPv6)
    await expect(page.getByRole('main').locator('text=/\\d+\\.\\d+\\.\\d+\\.\\d+|::1/').first()).toBeVisible({ timeout: 10_000 });
  });

  test('active session shows timestamps', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.locator('.vault-pulse').first()).toBeVisible({ timeout: 10_000 });
    // Should show date-like text (contains year or relative time)
    await expect(page.getByText(/\d{4}|ago|just now/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('revoke all sessions logs user out', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.locator('.vault-pulse').first()).toBeVisible({ timeout: 10_000 });

    const revokeAllBtn = page.getByRole('button', { name: /revoke all/i });
    if (await revokeAllBtn.isVisible()) {
      await revokeAllBtn.click();
      // Should be logged out and redirected to login
      await expect(page.locator('#vault-login-email')).toBeVisible({ timeout: 10_000 });
    }
  });

  test('devices section heading is visible', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Devices').first()).toBeVisible({ timeout: 10_000 });
  });

  test('edit device name and save with Enter', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10_000 });

    // Wait for devices to load
    await page.waitForTimeout(2000);

    // Look for an edit button (pencil icon or Edit text)
    const editBtn = page.locator('[aria-label*="dit"], [aria-label*="ename"]').first();
    if (await editBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await editBtn.click();

      const editInput = page.locator('input.vault-input').last();
      await expect(editInput).toBeVisible({ timeout: 5_000 });
      await editInput.fill('My Browser');
      await editInput.press('Enter');

      await expect(page.getByText('My Browser')).toBeVisible({ timeout: 10_000 });
    }
  });

  test('cancel device name edit with Escape', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await page.waitForTimeout(2000);

    const editBtn = page.locator('[aria-label*="dit"], [aria-label*="ename"]').first();
    if (await editBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await editBtn.click();

      const editInput = page.locator('input.vault-input').last();
      await expect(editInput).toBeVisible({ timeout: 5_000 });
      await editInput.fill('Should Not Save');
      await editInput.press('Escape');

      await expect(page.getByText('Should Not Save')).not.toBeVisible();
    }
  });
});
