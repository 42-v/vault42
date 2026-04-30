import { test, expect } from '@playwright/test';
import { uniqueEmail, testPassword, registerAndVerify, login } from './helpers/auth';
import { deleteAllMessages } from './helpers/mailpit';

test.describe('Identity', () => {
  test.beforeEach(async () => {
    await deleteAllMessages();
  });

  test('identity form renders with all fields', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#identity-family-name')).toBeVisible();
    await expect(page.locator('#identity-country')).toBeVisible();
    await expect(page.locator('#identity-dob')).toBeVisible();
    await expect(page.locator('#identity-sex')).toBeVisible();
  });

  test('save identity with basic info shows success', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.locator('#identity-given-name').fill('John');
    await page.locator('#identity-family-name').fill('Doe');
    await page.locator('#identity-country').fill('US');
    await page.locator('#identity-dob').fill('1990-01-15');
    await page.locator('#identity-sex').selectOption('male');

    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved|updated|success/i)).toBeVisible({ timeout: 10_000 });
  });

  test('billing address section toggles visibility', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    // Billing fields hidden initially
    await expect(page.locator('#billing-address-1')).not.toBeVisible();

    // Toggle open
    await page.getByRole('button', { name: /billing/i }).click();
    await expect(page.locator('#billing-address-1')).toBeVisible();

    // Toggle closed
    await page.getByRole('button', { name: /hide|billing/i }).click();
    await expect(page.locator('#billing-address-1')).not.toBeVisible();
  });

  test('save identity with billing address', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.locator('#identity-given-name').fill('Jane');
    await page.locator('#identity-family-name').fill('Smith');
    await page.locator('#identity-country').fill('GB');

    await page.getByRole('button', { name: /billing/i }).click();
    await expect(page.locator('#billing-address-1')).toBeVisible();

    await page.locator('#billing-address-1').fill('123 Main St');
    await page.locator('#billing-address-2').fill('Apt 4');
    await page.locator('#billing-city').fill('London');
    await page.locator('#billing-postal-code').fill('SW1A 1AA');
    await page.locator('#billing-country').fill('GB');
    await page.locator('#billing-vat-id').fill('GB123456789');

    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved|updated|success/i)).toBeVisible({ timeout: 10_000 });
  });

  test('saved identity data persists on reload', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.locator('#identity-given-name').fill('Persistent');
    await page.locator('#identity-family-name').fill('User');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved|updated|success/i)).toBeVisible({ timeout: 10_000 });

    await page.reload();
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#identity-given-name')).toHaveValue('Persistent');
    await expect(page.locator('#identity-family-name')).toHaveValue('User');
  });

  test('delete identity with confirmation modal', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.locator('#identity-given-name').fill('ToDelete');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved|updated|success/i)).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /delete/i }).click();
    await expect(page.locator('[role="dialog"]')).toBeVisible({ timeout: 5_000 });
    await page.locator('[role="dialog"]').getByRole('button', { name: /delete|confirm/i }).click();

    // Form should be cleared
    await expect(page.locator('#identity-given-name')).toHaveValue('');
  });

  test('cancel delete keeps identity data', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.locator('#identity-given-name').fill('KeepMe');
    await page.getByRole('button', { name: /save/i }).click();
    await expect(page.getByText(/saved|updated|success/i)).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /delete/i }).click();
    await expect(page.locator('[role="dialog"]')).toBeVisible({ timeout: 5_000 });
    await page.locator('[role="dialog"]').getByRole('button', { name: /cancel/i }).click();

    await expect(page.locator('#identity-given-name')).toHaveValue('KeepMe');
  });

  test('country field enforces 2-char maxlength and pattern', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-country')).toBeVisible({ timeout: 10_000 });

    await expect(page.locator('#identity-country')).toHaveAttribute('maxlength', '2');
    await expect(page.locator('#identity-country')).toHaveAttribute('pattern', '[A-Z]{2}');
  });

  test('sex select has expected options', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-sex')).toBeVisible({ timeout: 10_000 });

    const options = page.locator('#identity-sex option');
    const count = await options.count();
    // Should have at least the default empty + male + female options
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('billing field maxlength attributes', async ({ page }) => {
    const email = uniqueEmail();
    const pw = testPassword();
    await registerAndVerify(page, email, pw);
    await deleteAllMessages();
    await login(page, email, pw);

    await page.goto('/identity');
    await expect(page.locator('#identity-given-name')).toBeVisible({ timeout: 10_000 });

    await page.getByRole('button', { name: /billing/i }).click();
    await expect(page.locator('#billing-address-1')).toBeVisible();

    await expect(page.locator('#billing-address-1')).toHaveAttribute('maxlength', '200');
    await expect(page.locator('#billing-address-2')).toHaveAttribute('maxlength', '200');
    await expect(page.locator('#billing-city')).toHaveAttribute('maxlength', '100');
    await expect(page.locator('#billing-postal-code')).toHaveAttribute('maxlength', '20');
    await expect(page.locator('#billing-country')).toHaveAttribute('maxlength', '2');
    await expect(page.locator('#billing-vat-id')).toHaveAttribute('maxlength', '50');
  });
});
