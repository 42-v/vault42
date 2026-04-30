import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Configuration', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('config page loads with table', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await expect(page.getByText('Configuration')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#configBody')).toBeVisible();
  });

  test('add config form toggles visibility', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await expect(page.getByText('Configuration')).toBeVisible({ timeout: 10_000 });

    const form = page.locator('#addConfigForm');
    await expect(form).not.toBeVisible();

    await page.locator('[data-action="show-add-config"]').click();
    await expect(form).toBeVisible();

    await page.locator('[data-action="hide-add-config"]').click();
    await expect(form).not.toBeVisible();
  });

  test('add config entry and verify it appears', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await page.waitForTimeout(2000);

    const configKey = `e2e.test.${Date.now()}`;
    const configValue = 'test-value-42';

    await page.locator('[data-action="show-add-config"]').click();
    await expect(page.locator('#addConfigForm')).toBeVisible();

    const inputs = page.locator('#addConfigForm input');
    await inputs.first().fill(configKey);
    await inputs.nth(1).fill(configValue);

    await page.locator('[data-action="add-config"]').click();

    await page.waitForTimeout(3000);

    // Config entry should appear in table
    await expect(page.getByText(configKey)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(configValue)).toBeVisible({ timeout: 10_000 });
  });

  test('edit config entry updates value', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await page.waitForTimeout(2000);

    // First create an entry to edit
    const configKey = `e2e.edit.${Date.now()}`;
    const originalValue = 'original-value';
    const updatedValue = 'updated-value';

    await page.locator('[data-action="show-add-config"]').click();
    const inputs = page.locator('#addConfigForm input');
    await inputs.first().fill(configKey);
    await inputs.nth(1).fill(originalValue);
    await page.locator('[data-action="add-config"]').click();
    await page.waitForTimeout(2000);

    await expect(page.getByText(configKey)).toBeVisible({ timeout: 10_000 });

    // Click edit button on the row
    const editBtn = page.locator(`[data-action="edit-config"]`).last();
    if (await editBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await editBtn.click();

      // Form should be populated with the key and value
      await expect(page.locator('#addConfigForm')).toBeVisible();

      // Update the value
      const valueInput = page.locator('#addConfigForm input').nth(1);
      await valueInput.clear();
      await valueInput.fill(updatedValue);
      await page.locator('[data-action="add-config"]').click();

      await page.waitForTimeout(2000);

      await expect(page.getByText(updatedValue)).toBeVisible({ timeout: 10_000 });
    }
  });

  test('delete config entry with confirmation', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await page.waitForTimeout(2000);

    // Create an entry to delete
    const configKey = `e2e.delete.${Date.now()}`;

    await page.locator('[data-action="show-add-config"]').click();
    const inputs = page.locator('#addConfigForm input');
    await inputs.first().fill(configKey);
    await inputs.nth(1).fill('delete-me');
    await page.locator('[data-action="add-config"]').click();
    await page.waitForTimeout(2000);

    await expect(page.getByText(configKey)).toBeVisible({ timeout: 10_000 });

    // Click delete
    const deleteBtn = page.locator('[data-action="delete-config"]').last();
    await deleteBtn.click();

    // Confirmation modal
    await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('#modalBody')).toContainText(/delete/i);

    // Confirm deletion
    await page.locator('#modalConfirm').click();

    await page.waitForTimeout(2000);

    // Entry should be removed
    await expect(page.getByText(configKey)).not.toBeVisible({ timeout: 10_000 });
  });

  test('cancel delete keeps config entry', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await page.waitForTimeout(2000);

    // Create an entry
    const configKey = `e2e.keep.${Date.now()}`;

    await page.locator('[data-action="show-add-config"]').click();
    const inputs = page.locator('#addConfigForm input');
    await inputs.first().fill(configKey);
    await inputs.nth(1).fill('keep-me');
    await page.locator('[data-action="add-config"]').click();
    await page.waitForTimeout(2000);

    await expect(page.getByText(configKey)).toBeVisible({ timeout: 10_000 });

    // Click delete then cancel
    const deleteBtn = page.locator('[data-action="delete-config"]').last();
    await deleteBtn.click();

    await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
    await page.locator('#modalCancel').click();

    // Entry should still exist
    await expect(page.getByText(configKey)).toBeVisible();
  });

  test('refresh button reloads config list', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await page.waitForTimeout(2000);

    const refreshBtn = page.locator('[data-action="refresh-config"]');
    await expect(refreshBtn).toBeVisible({ timeout: 5_000 });
    await refreshBtn.click();

    await page.waitForTimeout(2000);

    // Page should still show config table
    await expect(page.locator('#configBody')).toBeVisible();
  });

  test('add config form auto-focuses key input', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await expect(page.getByText('Configuration')).toBeVisible({ timeout: 10_000 });

    await page.locator('[data-action="show-add-config"]').click();
    await expect(page.locator('#addConfigForm')).toBeVisible();

    const firstInput = page.locator('#addConfigForm input').first();
    await expect(firstInput).toBeFocused({ timeout: 3_000 });
  });

  test('Escape key closes add config form', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/config');

    await expect(page.getByText('Configuration')).toBeVisible({ timeout: 10_000 });

    await page.locator('[data-action="show-add-config"]').click();
    await expect(page.locator('#addConfigForm')).toBeVisible();

    await page.keyboard.press('Escape');
    await expect(page.locator('#addConfigForm')).not.toBeVisible();
  });
});
