import { test, expect } from '@playwright/test';
import { getAdminToken, authenticateAdminPage, gotoAdminPage } from './helpers/admin';

const ADMIN_PASSWORD = process.env.ADMIN_FIRST_PASSWORD || '';

test.describe('Admin Dashboard', () => {
  test.skip(!ADMIN_PASSWORD, 'ADMIN_FIRST_PASSWORD env var required');

  let adminToken: string;

  test.beforeAll(async ({ request }) => {
    adminToken = await getAdminToken(request);
  });

  test('dashboard page loads with stat cards', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.getByText('Dashboard')).toBeVisible({ timeout: 10_000 });
    // Stat card placeholders should be present
    await expect(page.locator('#keyCount')).toBeVisible();
    await expect(page.locator('#sessionCount')).toBeVisible();
    await expect(page.locator('#adminCount')).toBeVisible();
    await expect(page.locator('#clientCount')).toBeVisible();
  });

  test('stat cards populate with numbers', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    // Wait for API calls to populate the stat cards
    await page.waitForTimeout(3000);

    // At least keys, sessions, and admins should have non-zero counts
    const keyCount = await page.locator('#keyCount').textContent();
    expect(keyCount).toBeTruthy();
    expect(keyCount).not.toBe('—');

    const sessionCount = await page.locator('#sessionCount').textContent();
    expect(sessionCount).toBeTruthy();

    const adminCount = await page.locator('#adminCount').textContent();
    expect(adminCount).toBeTruthy();
    expect(parseInt(adminCount || '0')).toBeGreaterThanOrEqual(1);
  });

  test('stat cards link to respective pages', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.getByText('Dashboard')).toBeVisible({ timeout: 10_000 });

    // Verify links in stat cards
    await expect(page.locator('a[href="/admin/ui/keys"]')).toBeVisible();
    await expect(page.locator('a[href="/admin/ui/sessions"]')).toBeVisible();
    await expect(page.locator('a[href="/admin/ui/admins"]')).toBeVisible();
    await expect(page.locator('a[href="/admin/ui/clients"]')).toBeVisible();
  });

  test('recent audit events table is populated', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    // Wait for audit data to load
    await page.waitForTimeout(3000);

    const auditBody = page.locator('#auditBody');
    await expect(auditBody).toBeVisible({ timeout: 10_000 });

    // Should have at least one audit event (the login itself)
    const rows = auditBody.locator('tr');
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test('audit events show event type badges', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await page.waitForTimeout(3000);

    // At least one badge should be visible in audit table
    await expect(page.locator('#auditBody .badge').first()).toBeVisible({ timeout: 10_000 });
  });

  test('sidebar navigation is visible', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    await expect(page.locator('#sidebar')).toBeVisible({ timeout: 10_000 });
    await expect(page.locator('.nav-link').first()).toBeVisible();
  });

  test('dashboard nav link is active', async ({ page }) => {
    await authenticateAdminPage(page, adminToken);
    await gotoAdminPage(page, '/admin/');

    const dashboardLink = page.locator('a.nav-link.active');
    await expect(dashboardLink).toBeVisible({ timeout: 10_000 });
    await expect(dashboardLink).toContainText('Dashboard');
  });
});
