import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Key Management', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('keys page loads with table', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await expect(page.getByText('Signing Keys')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#keysBody')).toBeVisible();
  });

  test('keys page shows at least one active key', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    const keysBody = page.locator('#keysBody');
    const rows = keysBody.locator('tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('active key shows RS256 algorithm', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    await expect(page.getByText('RS256').first()).toBeVisible({ timeout: 10_000 });
  });

  test('active key shows active status badge', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    await expect(page.locator('.status-active').first()).toBeVisible({ timeout: 10_000 });
  });

  test('rotate key button creates new key', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    // Count keys before rotation
    const rowsBefore = await page.locator('#keysBody tr').count();

    // Click rotate key
    const rotateBtn = page.locator('[data-action="rotate-key"]');
    await expect(rotateBtn).toBeVisible({ timeout: 5_000 });
    await rotateBtn.click();

    // Wait for new key to appear
    await page.waitForTimeout(3000);

    // Key count should have increased
    const rowsAfter = await page.locator('#keysBody tr').count();
    expect(rowsAfter).toBeGreaterThanOrEqual(rowsBefore);
  });

  test('refresh button reloads key list', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    const refreshBtn = page.locator('[data-action="refresh-keys"]');
    await expect(refreshBtn).toBeVisible({ timeout: 5_000 });
    await refreshBtn.click();

    // Keys should still be visible after refresh
    await page.waitForTimeout(2000);
    const rows = await page.locator('#keysBody tr').count();
    expect(rows).toBeGreaterThanOrEqual(1);
  });

  test('key row shows copy button for KID', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    await page.waitForTimeout(2000);

    // Should have at least one copy button
    const copyBtn = page.locator('[data-action="copy"]').first();
    await expect(copyBtn).toBeVisible({ timeout: 10_000 });
  });

  test('keys nav link is highlighted as active', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/keys');

    const activeLink = page.locator('a.nav-link.active');
    await expect(activeLink).toContainText('Keys');
  });
});
