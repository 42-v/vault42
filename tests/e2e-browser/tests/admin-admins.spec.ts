import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Account Management', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('admins page loads with table', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await expect(page.getByText('Admin Accounts')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('#adminsBody')).toBeVisible();
  });

  test('admins table shows at least the boot admin', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    // Should show the default admin account
    await expect(page.getByText('admin').first()).toBeVisible({ timeout: 10_000 });
  });

  test('admin shows role badge', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    // Boot admin should have super_admin role badge
    await expect(page.locator('.role-badge, .badge').filter({ hasText: /super_admin/ }).first()).toBeVisible({ timeout: 10_000 });
  });

  test('admin shows TOTP configured status', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    // TOTP column should show Yes (configured after first login)
    await expect(page.locator('#adminsBody').getByText('Yes').first()).toBeVisible({ timeout: 10_000 });
  });

  test('create admin form toggles visibility', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await expect(page.getByText('Admin Accounts')).toBeVisible({ timeout: 10_000 });

    const form = page.locator('#createAdminForm');
    await expect(form).not.toBeVisible();

    await page.locator('[data-action="show-create-admin"]').click();
    await expect(form).toBeVisible();

    await page.locator('[data-action="hide-create-admin"]').click();
    await expect(form).not.toBeVisible();
  });

  test('create admin with valid credentials', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    const username = `e2e-admin-${Date.now()}`;
    const password = 'E2eAdminTestPassword!42';

    await page.locator('[data-action="show-create-admin"]').click();
    await expect(page.locator('#createAdminForm')).toBeVisible();

    // Fill username
    const inputs = page.locator('#createAdminForm input');
    await inputs.first().fill(username);
    // Fill password (20+ chars required)
    await inputs.nth(1).fill(password);

    // Select role
    const roleSelect = page.locator('#createAdminForm select');
    if (await roleSelect.isVisible()) {
      await roleSelect.selectOption('viewer');
    }

    await page.locator('[data-action="create-admin"]').click();

    await page.waitForTimeout(3000);

    // New admin should appear in table
    await expect(page.getByText(username)).toBeVisible({ timeout: 10_000 });
  });

  test('revoke admin shows confirmation dialog', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    const revokeBtn = page.locator('[data-action="revoke-admin"]').first();
    if (await revokeBtn.isVisible({ timeout: 5_000 }).catch(() => false)) {
      await revokeBtn.click();

      await expect(page.locator('#modalOverlay')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('#modalBody')).toContainText(/revoke|irreversible/i);

      // Cancel to avoid mutation
      await page.locator('#modalCancel').click();
    }
  });

  test('refresh button reloads admin list', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    const refreshBtn = page.locator('[data-action="refresh-admins"]');
    await expect(refreshBtn).toBeVisible({ timeout: 5_000 });
    await refreshBtn.click();

    await page.waitForTimeout(2000);

    const rows = await page.locator('#adminsBody tr').count();
    expect(rows).toBeGreaterThanOrEqual(1);
  });

  test('admin last login column shows time', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/ui/admins');

    await page.waitForTimeout(2000);

    // Boot admin should have a last_login_at value
    await expect(page.locator('#adminsBody').getByText(/ago|just now|\d{4}/i).first()).toBeVisible({ timeout: 10_000 });
  });
});
