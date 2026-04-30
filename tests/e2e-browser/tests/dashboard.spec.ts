import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Dashboard', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('authenticated user sees welcome message with display name', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    const name = 'Dashboard User';
    await registerAndVerify(page, email, pw, name);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText(`Welcome back, ${name}`)).toBeVisible({ timeout: 10_000 });
  });

  test('security overview shows email verified badge', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Email verified')).toBeVisible({ timeout: 10_000 });
  });

  test('security overview shows 2FA not configured for new user', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByRole('link', { name: /enable/i })).toBeVisible({ timeout: 10_000 });
  });

  test('member since card shows creation date', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await expect(page.getByText('Member Since')).toBeVisible({ timeout: 10_000 });
  });

  test('quick action cards link to all protected pages', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    const expectedLinks = ['/profile', '/sessions', '/2fa', '/password', '/identity', '/storage'];
    for (const href of expectedLinks) {
      await expect(page.locator(`a[href="${href}"]`).first()).toBeVisible({ timeout: 10_000 });
    }
  });

  test('clicking profile card navigates to profile page', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await page.locator('a[href="/profile"]').first().click();
    await expect(page).toHaveURL(/\/profile/);
    await expect(page.getByRole('heading', { name: 'Profile', exact: true })).toBeVisible({ timeout: 10_000 });
  });

  test('clicking sessions card navigates to sessions page', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await page.locator('a[href="/sessions"]').first().click();
    await expect(page).toHaveURL(/\/sessions/);
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10_000 });
  });

  test('clicking 2FA card navigates to two-factor page', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await page.locator('a[href="/2fa"]').first().click();
    await expect(page).toHaveURL(/\/2fa/);
    await expect(page.getByRole('heading', { name: 'Two-Factor Authentication' })).toBeVisible({ timeout: 10_000 });
  });

  test('clicking storage card navigates to storage page', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/');
    await page.locator('a[href="/storage"]').first().click();
    await expect(page).toHaveURL(/\/storage/);
    await expect(page.getByRole('heading', { name: /storage/i })).toBeVisible({ timeout: 10_000 });
  });
});
