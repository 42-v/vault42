import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages, waitForCode, waitForNewCode, getMessages } from './helpers/mailpit';

test.describe('Multi-Factor Authentication', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('email OTP form shows for user without TOTP', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();

    await page.goto('/login');
    await page.locator('#vault-login-email').fill(email);
    await page.locator('#vault-login-password').fill(pw);
    await page.locator('button[type="submit"]:has-text("Sign In")').click();

    // Must see email OTP, NOT TOTP
    await expect(page.locator('#vault-email-otp-code')).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText('Check your email for a verification code')).toBeVisible();
    await expect(page.locator('#vault-totp-code')).not.toBeVisible();
  });

  test('email OTP resend delivers new code', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();

    await page.goto('/login');
    await page.locator('#vault-login-email').fill(email);
    await page.locator('#vault-login-password').fill(pw);
    await page.locator('button[type="submit"]:has-text("Sign In")').click();

    await expect(page.locator('#vault-email-otp-code')).toBeVisible({ timeout: 10_000 });

    // Get the first code and note how many emails exist
    const code1 = await waitForCode(email);
    expect(code1).toMatch(/^\d{6}$/);
    const messagesBefore = await getMessages(email);

    // Click resend — text changes to "Sending..." then back to "Resend code"
    await page.getByText('Resend code').click();
    await expect(page.getByText('Resend code')).toBeVisible({ timeout: 10_000 });

    // Wait for a NEW email (count must increase)
    const code2 = await waitForNewCode(email, messagesBefore.length, 20_000);
    expect(code2).toMatch(/^\d{6}$/);

    // Enter the new code
    await page.locator('#vault-email-otp-code').fill(code2);
    await page.locator('button:has-text("Verify Code")').click();

    // Should be logged in (may land on MFA onboarding or home)
    await expect(page.getByText('Sign Out')).toBeVisible({ timeout: 10_000 });
  });

  test('TOTP setup and verify', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    // Navigate to 2FA settings
    await page.goto('/2fa');
    await expect(page.getByRole('heading', { name: 'Two-Factor Authentication' })).toBeVisible({ timeout: 10_000 });

    // Begin TOTP setup — this triggers a password confirmation dialog
    await page.getByRole('button', { name: 'Begin Setup' }).click();

    // Handle password confirmation dialog
    const confirmInput = page.locator('input[placeholder="Enter your password"]');
    await expect(confirmInput).toBeVisible({ timeout: 5_000 });
    await confirmInput.fill(pw);
    await page.getByRole('button', { name: 'Confirm' }).click();

    // Wait for the confirm dialog to close and setup to appear
    await expect(confirmInput).not.toBeVisible({ timeout: 10_000 });

    // Wait for QR code / setup to appear
    await expect(page.locator('canvas').or(page.getByText('secret'))).toBeVisible({ timeout: 10_000 });

    // The setup flow should show a code input for verification
    await expect(page.locator('input[inputmode="numeric"]').or(page.locator('input[pattern="[0-9]{6}"]'))).toBeVisible({ timeout: 5_000 });
  });

  test('backup codes can be generated', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/2fa');
    await expect(page.getByRole('heading', { name: 'Two-Factor Authentication' })).toBeVisible({ timeout: 10_000 });

    // Generate backup codes
    await page.getByRole('button', { name: 'Generate New Codes' }).click();

    // Password confirmation dialog
    const confirmInput = page.locator('input[placeholder="Enter your password"]');
    await expect(confirmInput).toBeVisible({ timeout: 5_000 });
    await confirmInput.fill(pw);
    await page.getByRole('button', { name: 'Confirm' }).click();

    // Wait for the confirm dialog to close
    await expect(confirmInput).not.toBeVisible({ timeout: 10_000 });

    // Should see backup codes displayed (look for the mono-spaced code elements)
    // The codes are shown in a grid of <code> elements
    await expect(page.locator('code').first()).toBeVisible({ timeout: 10_000 });
    const codeCount = await page.locator('code').count();
    expect(codeCount).toBeGreaterThanOrEqual(8);
  });
});
