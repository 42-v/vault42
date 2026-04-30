import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Sessions', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('sessions page loads with table', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await expect(page.getByText('Admin Sessions')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#sessionsBody')).toBeVisible();
  });

  test('sessions table shows at least one active session', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await page.waitForTimeout(2000);

    const rows = page.locator('#sessionsBody tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('session row shows IP address', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await page.waitForTimeout(2000);

    // Should show at least one IP-like value
    await expect(page.locator('#sessionsBody').getByText(/\d+\.\d+\.\d+\.\d+|::1|127/).first()).toBeVisible({ timeout: 10_000 });
  });

  test('session row shows creation time', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await page.waitForTimeout(2000);

    // Should show relative or absolute time
    await expect(page.locator('#sessionsBody').getByText(/ago|just now|\d{4}/i).first()).toBeVisible({ timeout: 10_000 });
  });

  test('refresh button reloads sessions', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await page.waitForTimeout(2000);

    const refreshBtn = page.locator('[data-action="refresh-sessions"]');
    await expect(refreshBtn).toBeVisible({ timeout: 5_000 });
    await refreshBtn.click();

    // Sessions should still be visible
    await page.waitForTimeout(2000);
    const rows = await page.locator('#sessionsBody tr').count();
    expect(rows).toBeGreaterThanOrEqual(1);
  });

  test('revoke all shows confirmation with warning', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    await page.waitForTimeout(2000);

    const revokeAllBtn = page.locator('[data-action="revoke-all-sessions"]');
    await expect(revokeAllBtn).toBeVisible({ timeout: 5_000 });
    await revokeAllBtn.click();

    // Confirmation modal
    await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
    await expect(page.locator('#modalBody')).toContainText(/revoke|session|logged out/i);

    // Cancel — do NOT actually revoke (would break other tests)
    await page.locator('#modalCancel').click();
    await expect(page.locator('#modalOverlay')).not.toBeVisible();
  });

  test('sessions nav link is highlighted', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/sessions');

    const activeLink = page.locator('a.nav-link.active');
    await expect(activeLink).toContainText('Sessions');
  });
});
