import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Profile', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('view profile shows user details', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    const name = 'Profile Test User';
    await registerAndVerify(page, email, pw, name);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/profile');
    await expect(page.getByRole('heading', { name: 'Profile', exact: true })).toBeVisible({ timeout: 10_000 });

    // Email visible (use first() — email appears in multiple spots on page)
    await expect(page.getByRole('main').getByText(email).first()).toBeVisible();

    // Display name visible
    await expect(page.getByText(name)).toBeVisible();

    // Email verified badge
    await expect(page.getByText('Email verified')).toBeVisible();

    // Account Details section
    await expect(page.getByText('Account Details')).toBeVisible();
    await expect(page.getByText('Account ID')).toBeVisible();
  });

  test('MFA status shows disabled for new user', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/profile');
    await expect(page.getByRole('heading', { name: 'Profile', exact: true })).toBeVisible({ timeout: 10_000 });

    // MFA should be disabled
    await expect(page.getByText('Multi-Factor Auth')).toBeVisible();
    await expect(page.getByText('Disabled')).toBeVisible();
    // "Enable" link to /2fa
    await expect(page.getByRole('link', { name: 'Enable' })).toBeVisible();
  });

  test('sessions page shows active session', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/sessions');
    await expect(page.getByRole('heading', { name: 'Sessions' })).toBeVisible({ timeout: 10_000 });

    // Should have at least one active session (current)
    // The green pulse indicator means a session exists
    await expect(page.locator('.vault-pulse').first()).toBeVisible({ timeout: 10_000 });
  });
});
