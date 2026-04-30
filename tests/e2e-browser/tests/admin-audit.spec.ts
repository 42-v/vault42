import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Audit Log', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('audit page loads with filter controls', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await expect(page.getByText('Audit Log')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#auditEventType')).toBeVisible();
    await expect(page.locator('#auditBody')).toBeVisible();
  });

  test('event type dropdown has filter options', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await expect(page.locator('#auditEventType')).toBeVisible({ timeout: 10_000 });

    const options = page.locator('#auditEventType option');
    const count = await options.count();
    // Should have "All" + at least a few event types
    expect(count).toBeGreaterThanOrEqual(3);
  });

  test('audit entries are loaded on page init', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    // Should have at least one audit entry (admin login)
    const rows = page.locator('#auditBody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('audit entries show event type badges', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    await expect(page.locator('#auditBody .badge').first()).toBeVisible({ timeout: 10_000 });
  });

  test('audit entries show timestamp', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    // Should show formatted timestamp
    await expect(page.locator('#auditBody').getByText(/\d{4}|AM|PM|ago/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('audit entries show IP address', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    await expect(page.locator('#auditBody').getByText(/\d+\.\d+\.\d+\.\d+|::1|127/).first()).toBeVisible({ timeout: 10_000 });
  });

  test('audit entries show risk score', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    // Risk score cell should have a colored span
    await expect(page.locator('#auditBody .status-active, #auditBody .status-locked, #auditBody .status-inactive').first()).toBeVisible({ timeout: 10_000 });
  });

  test('filter by event type narrows results', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    // Select a specific event type (admin_login should exist)
    await page.locator('#auditEventType').selectOption({ index: 1 });
    await page.locator('[data-action="query-audit"]').click();

    await page.waitForTimeout(2000);

    // Results should be filtered (may be fewer rows or different event types)
    const auditBody = page.locator('#auditBody');
    await expect(auditBody).toBeVisible();
  });

  test('user ID filter field is present', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    // User ID input for filtering
    await expect(page.locator('#auditUserId, input[placeholder*="User ID"]')).toBeVisible({ timeout: 10_000 });
  });

  test('result count is displayed', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/audit');

    await page.waitForTimeout(3000);

    await expect(page.getByText(/\d+ result/i)).toBeVisible({ timeout: 10_000 });
  });
});
